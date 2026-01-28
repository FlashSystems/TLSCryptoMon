// SPDX-License-Identifier: BSD-3-Clause
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::skel::OpenSkel as _;
use log::{debug, error, warn, info};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::FormatItem;

mod ebpf;
use ebpf::EbpfOutput;
mod tls;
mod cmdline;

/// Timestamp format
const TIMESTAMP_FORMAT: &[FormatItem] = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

// Import the eBPF program that the build script prepared.
mod tracecon {
	include!(concat!(env!("OUT_DIR"), "/tlshstrace.skel.rs"));
}
use tracecon::*;

#[derive(Error, Debug)]
pub enum RuntimeError {
	#[error("Error while loding eBPF program into kernel: {0}")]
	EbpfError(#[from]libbpf_rs::Error),
	#[error("Could not increase rlimit")]
	MemlockRlimit,
	#[error("Could not open cgroup: {0}")]
	CgroupOpen(std::io::Error),
	#[error("Broken eBPF program. Section 'bss_data' missing.")]
	NoBssData
}

fn bump_memlock_rlimit() -> Result<(), RuntimeError> {
	let rlimit = libc::rlimit {
		rlim_cur: 128 << 20,
		rlim_max: 128 << 20,
	};

	if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } == 0 {
		Ok(())
	} else {
		Err(RuntimeError::MemlockRlimit)
	}
}

fn process_tls_session(data: &[u8], ringbuffer_full_counter: &mut u64, invalid_packet_counter: &mut u64) {
	match EbpfOutput::try_from(data) {
		Ok(output) => {
			// Becaouse we're analysing the return package the remote_port and local_port are swaped.
			// It would be confusing to output it this way, because the user would think of the
			// connection originating from the client. Therefore we swap the remote_port and the
			// local_port.
			println!("{timestamp} {local_ip} {remote_port} {remote_ip} {local_port} {kex} {cipher}",
				local_ip = output.local_address,
				local_port = output.local_port,
				remote_ip = output.remote_address,
				remote_port = output.remote_port,
				cipher = tls::get_cipher_suite_name(output.cipher_suite),
				kex = tls::get_kex_name(output.named_group),
				timestamp = OffsetDateTime::now_utc()
				            .format(&TIMESTAMP_FORMAT)
                            .unwrap() //FIXME
			);

			if *ringbuffer_full_counter != output.ringbuffer_full_counter {
				warn!("Warning: Ringbuffer got full. Missed {} events.", output.ringbuffer_full_counter - *ringbuffer_full_counter);
				*ringbuffer_full_counter = output.ringbuffer_full_counter;
			}

			if *invalid_packet_counter != output.invalid_packet_counter {
				warn!("Warning: {} invalid packets.", output.invalid_packet_counter - *invalid_packet_counter);
				*invalid_packet_counter = output.invalid_packet_counter;
			}
		},
		Err(err) => {
			error!("Error parsing data from kernel eBPF program: {err}");
		}
	}
}

/// This function is passed to libbpf_rs::set_print to funnel
/// all eBPF output through this library.
fn libbpf_print(level: libbpf_rs::PrintLevel, msg: String) {
    match level {
        libbpf_rs::PrintLevel::Debug => debug!("{msg}"),
        libbpf_rs::PrintLevel::Info => info!("{msg}"),
        libbpf_rs::PrintLevel::Warn => warn!("{msg}")
    }
}

/// Removes errors of kind Interrupted from the passed Result. Returns Ok(default) instead.
/// This is used to handle Ctrl+C wihtout erroring out.
fn filter_int_error<R>(result: Result<R, libbpf_rs::Error>, default: R) -> Result<R, libbpf_rs::Error>{
	match result {
		Ok(_) => result,
		Err(err) => {
			if err.kind() == libbpf_rs::ErrorKind::Interrupted {
				Ok(default)
			} else {
				Err(err)
			}
		}
	}
}

fn run(config: cmdline::Config) -> Result<(), RuntimeError> {
	debug!("Increasing memlock limit...");
	bump_memlock_rlimit()?;

	debug!("Initializing shutdown handler...");
	let shutdown = Arc::new(AtomicBool::new(false));    // Gibt's da nichts besseres?

	let handler_shutdown = shutdown.clone();
	ctrlc::set_handler(move || {
		handler_shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
	}).expect("Error setting Ctrl-C handler");

	let tls_hs_trace_skel = TlshstraceSkelBuilder::default();

	debug!("Reading and configuring eBPF program...");

	let mut open_object = MaybeUninit::uninit();
	let mut open_skel = tls_hs_trace_skel.open(&mut open_object)?;

	// Allocate the in_ports map to fit the necessary ports into it.
	debug!("Reserve {} slots for ports in 'in_ports' map.", config.ports.len());
	open_skel.maps.in_ports.set_max_entries(config.ports.len() as u32)?;

	// Show the size of the output ring buffer.
	debug!("Output ring buffer size is {} kBytes.", open_skel.maps.output.max_entries() / 1024);

	// Initialize the in_const_debug variable to enable or disable ebpf debugging.
	if let Some(ref mut bss_data) = open_skel.maps.bss_data {
		bss_data.in_const_debug = if config.debug_ebpf {
			info!("Enabling debug output for eBPF program.");
			1
		} else {
			0
		};
	} else {
		return Err(RuntimeError::NoBssData);
	};

	// Load the eBPF program after we modified the configuration.
	debug!("Loading eBPF program...");
	let skel = open_skel.load()?;

	// Initialize the ports list.
	debug!("Updating ports list...");
	let dummy = [1u8];
	for port in config.ports {
		debug!("Add port {port} to the 'in_ports' map.");
		skel.maps.in_ports.update(&port.to_ne_bytes(), &dummy, MapFlags::ANY)?;
	}

	// These variables are passed to the ring buffer reader and store the last value of these variables.
	// If the value changes, the new values are output as warnings.
	let mut ringbuffer_full_counter = 0;
	let mut invalid_packet_counter = 0;

	// Attach the ringbuffer for data transfer between the eBPF program and userspace
	debug!("Attaching ringbuffer...");
    let mut output_buffer_builder = libbpf_rs::RingBufferBuilder::new();

	output_buffer_builder.add(&skel.maps.output, move |data| { process_tls_session(data, &mut ringbuffer_full_counter, &mut invalid_packet_counter); 0 })?;
	let output_buffer = output_buffer_builder.build()?;

	// FIXME: What cgroup should we use?
	let cgroup = std::fs::File::open(config.cgroup).map_err(RuntimeError::CgroupOpen)?;

	// Attach the eBPF program to the selected cgroup.
	debug!("Attaching eBPF program to cgroup...");
	let cgroup_fd = cgroup.as_fd();
	let keep = skel.progs.bpf_socket_operation.attach_cgroup(cgroup_fd.as_raw_fd())?;

	// Attach the other eBPF program to the socket_map. The first program adds every socket that fits
	// the port filter to this socket map and makes the bpf_stream_parser run.
	debug!("Attaching eBPF program to socket map 'tls_sockets'...");
	let tls_socketmap_fd = skel.maps.tls_sockets.as_fd();
	skel.progs.bpf_stream_parser.attach_sockmap(tls_socketmap_fd.as_raw_fd())?;

	debug!("Waiting for messages...");
	while !shutdown.load(std::sync::atomic::Ordering::SeqCst) {
		filter_int_error(output_buffer.poll(Duration::from_millis(250)), ())?;
	}

	debug!("Shutting down...");
	drop(keep);

	Ok(())
}

fn main() {
	match cmdline::get_config() {
		Ok(config) => {
			// Initialize logging
			let log_level = if config.debug {
				libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Debug, libbpf_print)));
				log::LevelFilter::Trace
			} else if config.verbose {
				libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Info, libbpf_print)));
				log::LevelFilter::Info
			} else {
				libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Warn, libbpf_print)));
				log::LevelFilter::Warn
			};

			// Initialize the logger with the configured log level.
			// Use the systemd journal if it is avaiable
			simple_logger::SimpleLogger::new()
				.with_utc_timestamps()
				.init().unwrap();
			log::set_max_level(log_level);

			debug!("Initializing...");
			if let Err(error) = run(config) {
				error!("{error}");
			}
		},
		Err(error) => {
			log::error!("Configuration error: {error}. Check command line.");
		}
	}
}
