// SPDX-License-Identifier: BSD-3-Clause
use std::{fs::File, io::{Cursor, Read}, net::IpAddr, os::fd::AsRawFd, os::fd::AsFd, time::Duration};
use byteorder::{NativeEndian, ReadBytesExt};
use libbpf_rs::{Link, RingBuffer, skel::SkelBuilder as _};
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use thiserror::Error;
use log::{debug, info, warn};

// Import the eBPF program that the build script prepared.
mod tracecon {
	include!(concat!(env!("OUT_DIR"), "/tlshstrace.skel.rs"));
}
use tracecon::*;

#[derive(Error, Debug)]
pub enum Error {
	#[error("Error while loding eBPF program into kernel: {0}")]
	Ebpf(#[from]libbpf_rs::Error),
	#[error("Could not increase rlimit")]
	MemlockRlimit,
	#[error("Broken eBPF program. Section 'bss_data' missing.")]
	NoBssData
}

/// Data from eBPF output structure
#[derive(Debug)]
pub struct EbpfOutput {
    pub remote_address: IpAddr,
	pub remote_port:u16,
    pub local_address: IpAddr,
	pub local_port:u16,
	pub ringbuffer_full_counter:u64,
	pub invalid_packet_counter:u64,
	pub cipher_suite:u16,
	pub named_group:u16,
}

const AF_INET: u32= 2;
const AF_INET6: u32 = 10;

/**
 * Read an ipv4/ipv6 address from the data package.
 * The af (address family) value must be set to the address family from the
 * output data packet.
 */
fn read_address(src: &mut impl Read, af: u32) -> Result<IpAddr, std::io::Error> {
    let mut address = [0u8; 16];
    src.read_exact(&mut address)?;

    match af {
        AF_INET => {
            let v4addr_bytes: [u8; 4] = address[0..4].try_into().unwrap(); // Unwrap is ok here, because we know the length of the slice.
            Ok(IpAddr::from(v4addr_bytes)) 
        },
        AF_INET6 => {
            Ok(IpAddr::from(address))
        },
        _ => {
            Err(std::io::Error::last_os_error())    //FIXME
        }
    }
}

/**
 * Unserialize the result struct of the eBPF program. From a u8 array.
 */
impl TryFrom<&[u8]> for EbpfOutput {
    type Error = std::io::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut data = Cursor::new(data);

        let af = data.read_u32::<NativeEndian>()?;
        
        Ok(EbpfOutput {
            local_address: read_address(&mut data, af)?,
            remote_address: read_address(&mut data, af)?,
            remote_port: data.read_u16::<NativeEndian>()?,
            local_port: data.read_u16::<NativeEndian>()?,
            ringbuffer_full_counter: data.read_u64::<NativeEndian>()?,
            invalid_packet_counter: data.read_u64::<NativeEndian>()?,
            cipher_suite: data.read_u16::<NativeEndian>()?,
            named_group: data.read_u16::<NativeEndian>()?
        })
    }
}

pub type MonitoredCGroup = Link;

/**
 * Represents an opened eBPF program that was not loaded.
 */
pub struct Ebpf<'obj> {
    open_skel: OpenTlshstraceSkel<'obj>
}

impl<'obj> Ebpf<'obj> {
    // Result codes for the callback passed to init.
    pub const CALLBACK_OK: i32 = 0;
    #[allow(unused)]
    pub const CALLBACK_FAILED: i32 = -1;

    /**
     * Initializes the tlshstrace eBPF program.
     * The debug_bpf parameter enables debug logging from the eBPF program.
     * If this is enabled in_const_debug will be set to 1 by manipulating the
     * const value before the program is optimized by the kernel.
     */
    pub fn new(object: &'obj mut std::mem::MaybeUninit<libbpf_rs::OpenObject>, debug_ebpf: bool) -> Result<Self, Error> {
        let tls_hs_trace_skel = TlshstraceSkelBuilder::default();

        let mut open_skel = tls_hs_trace_skel.open(object)?;

        // Initialize the in_const_debug variable to enable or disable ebpf debugging.
        if let Some(ref mut bss_data) = open_skel.maps.bss_data {
            bss_data.in_const_debug = if debug_ebpf {
                info!("Enabling debug output for eBPF program.");
                1
            } else {
                0
            };
        } else {
            return Err(Error::NoBssData);
        };

        Ok(Self{
            open_skel
        })
    }

    /**
     * Initializes the eBPF program and sets up the output ringbuffer.
     * This will also call the eBPF verifier.
     */
    pub fn init<F>(mut self, ports: &[u16], callback: F) -> Result<ConfiguredEbpf<'obj>, Error>
        where F: FnMut(&[u8]) -> i32 + 'obj {

        // Allocate the in_ports map to fit the necessary ports into it.
        debug!("Reserve {} slots for ports in 'in_ports' map.", ports.len());
        self.open_skel.maps.in_ports.set_max_entries(ports.len() as u32)?;

        // Show the size of the output ring buffer.
        debug!("Output ring buffer size is {} kBytes.", self.open_skel.maps.output.max_entries() / 1024);

        // Load the eBPF program after we modified the configuration.
        debug!("Loading eBPF program...");
        let skel = self.open_skel.load()?;

        // Initialize the ports list.
        debug!("Updating ports list...");
        let dummy = [1u8];
        for port in ports {
            debug!("Add port {port} to the 'in_ports' map.");
            skel.maps.in_ports.update(&port.to_ne_bytes(), &dummy, MapFlags::ANY)?;
        }

	    // Attach the ringbuffer for data transfer between the eBPF program and userspace
    	debug!("Attaching ringbuffer...");

        let mut output_buffer_builder = libbpf_rs::RingBufferBuilder::new();
        output_buffer_builder.add(&skel.maps.output, callback)?;
        let output_buffer = output_buffer_builder.build()?;

        Ok(ConfiguredEbpf{
            skel,
            output_buffer
        })
    }
}

/**
 * Represents an eBPF program that is loaded into the kernel.
 */
pub struct ConfiguredEbpf<'obj> {
    skel: TlshstraceSkel<'obj>,
    output_buffer: RingBuffer<'obj>
}

impl<'obj> ConfiguredEbpf<'obj> {
    /**
     * Called to process the ringbuffer. If the ringbuffer is empty this call
     * will wait 250ms before returning.
     * It will also return if an Interrupted-Error occurs. This error is not
     * passed back to the caller.
     */
    pub fn process_output_buffer(&self) -> Result<(), Error> {
        match self.output_buffer.poll(Duration::from_millis(250)) {
            Ok(_) => Ok(()),
            // Ignore the Interrupted error. Just return ok. The caller will call us again if neccessary.
            Err(err) if err.kind() == libbpf_rs::ErrorKind::Interrupted  => Ok(()),
            // Return all other values unaltered
            Err(err) => Err(Error::from(err))
        }
    }

    /**
     * Attaches the `bpf_socket_operation` (BPF_PROG_TYPE_SOCK_OPS) eBPF function
     * to a cGroup given cgroup. This makes sure the function is called at specific
     * lifecycle events of a socket.
     * It also attaches the `bpf_stream_parser` to the `tls_sockets` sockmap.
     * This sockmap is that is filled by `bpf_socket_operation`. This makes sure
     * that traffic for each socket that is put into the `tls_sockets` map by
     * `bpf_socket_operation` is processed by the stream parser.
     * If this function is not called, nothing will be processed by the eBPF
     * program.
     */
    pub fn attach_to_cgroup(&mut self, cgroup: File) -> Result<MonitoredCGroup, Error> {
        // Attach the eBPF program to the selected cgroup.
        debug!("Attaching eBPF program to cgroup FD...");
        let cgroup_fd = cgroup.as_fd();
        let cgroup_link = self.skel.progs.bpf_socket_operation.attach_cgroup(cgroup_fd.as_raw_fd())?;

        // Attach the other eBPF program to the socket_map. The first program adds every socket that fits
        // the port filter to this socket map and makes the bpf_stream_parser run.
        debug!("Attaching eBPF program to socket map 'tls_sockets'...");
        let tls_socketmap_fd = self.skel.maps.tls_sockets.as_fd();
        self.skel.progs.bpf_stream_parser.attach_sockmap(tls_socketmap_fd.as_raw_fd())?;

        Ok(cgroup_link as MonitoredCGroup)
    }
}

/**
 * This function is passed to libbpf_rs::set_print to funnel
 * all eBPF output through this library.
 */
fn libbpf_print(level: libbpf_rs::PrintLevel, msg: String) {
    match level {
        libbpf_rs::PrintLevel::Debug => debug!("{msg}"),
        libbpf_rs::PrintLevel::Info => info!("{msg}"),
        libbpf_rs::PrintLevel::Warn => warn!("{msg}")
    }
}

/**
 * Initializes log forwarding for libebpf based on the loglevel based on
 * `log::LevelFilter`.
 */
pub fn init_logging(level: log::LevelFilter) {
    let libbpf_print_level = match level {
        log::LevelFilter::Off | log::LevelFilter::Error | log::LevelFilter::Warn => libbpf_rs::PrintLevel::Warn,
        log::LevelFilter::Info => libbpf_rs::PrintLevel::Info,
        log::LevelFilter::Debug | log::LevelFilter::Trace => libbpf_rs::PrintLevel::Debug
    };

    libbpf_rs::set_print(Some((libbpf_print_level, libbpf_print)));
}

/**
 * Increase the memlock limit to allow the creation of all necessary BPF maps.
 */
pub fn bump_memlock_rlimit() -> Result<(), Error> {
	let rlimit = libc::rlimit {
		rlim_cur: 128 << 20,
		rlim_max: 128 << 20,
	};

	if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } == 0 {
		Ok(())
	} else {
		Err(Error::MemlockRlimit)
	}
}
