// SPDX-License-Identifier: BSD-3-Clause
use std::{io::{Cursor, Read}, net::{IpAddr}};
use byteorder::{NativeEndian, ReadBytesExt};

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

/// Read an ipv4/ipv6 address from the data package.
/// The af (address family) value must be set to the address family from the
/// output data packet.
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