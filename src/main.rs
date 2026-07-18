// SPDX-License-Identifier: BSD-3-Clause
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use log::{debug, error, warn};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::FormatItem;

mod ebpf;
use ebpf::{EbpfOutput, Ebpf};

mod tls;
mod cmdline;

/// Timestamp format
const TIMESTAMP_FORMAT: &[FormatItem] = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

#[derive(Error, Debug)]
pub enum RuntimeError {
	#[error("eBPF error: {0}")]
	EbpfError(#[from]ebpf::Error),
	#[error("Could not open cgroup: {0}")]
	CgroupOpen(std::io::Error),
	#[error("Broken eBPF program. Section 'bss_data' missing.")]
	NoBssData
}

fn process_tls_session(non_pq_only: bool, data: &[u8], ringbuffer_full_counter: &mut u64, invalid_packet_counter: &mut u64) {
	match EbpfOutput::try_from(data) {
		Ok(output) => {
			let kex_info = tls::get_kex_info(output.named_group);

			if ! (non_pq_only && kex_info.pq) {
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
					kex = kex_info.name,
					timestamp = OffsetDateTime::now_utc()
								.format(&TIMESTAMP_FORMAT)
								.unwrap() //FIXME
				);
			}

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

fn run(config: cmdline::Config) -> Result<(), RuntimeError> {
	debug!("Increasing memlock limit...");
	ebpf::bump_memlock_rlimit()?;

	debug!("Initializing shutdown handler...");
	let shutdown = Arc::new(AtomicBool::new(false));    // Gibt's da nichts besseres?

	let handler_shutdown = shutdown.clone();
	ctrlc::set_handler(move || {
		handler_shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
	}).expect("Error setting Ctrl-C handler");

	debug!("Opening eBPF program...");
	let mut open_object = MaybeUninit::uninit();
	let open_ebpf = Ebpf::new(&mut open_object, config.debug_ebpf)?;

	debug!("Loading eBPF program...");

	// These variables are passed to the ring buffer reader and store the last value of these variables.
	// If the value changes, the new values are output as warnings.
	let mut ringbuffer_full_counter = 0;
	let mut invalid_packet_counter = 0;
	let non_pq_only = config.non_pq_only;

	let mut ebpf = open_ebpf.init(
		&config.ports,
		move |data| { process_tls_session(non_pq_only, data, &mut ringbuffer_full_counter, &mut invalid_packet_counter); Ebpf::CALLBACK_OK }
	)?;

	debug!("Attaching to cgroup '{}'...", config.cgroup.to_string_lossy());
	let cgroup = std::fs::File::open(config.cgroup).map_err(RuntimeError::CgroupOpen)?;
	let monitored_cgroup = ebpf.attach_to_cgroup(cgroup)?;

	debug!("Waiting for messages...");
	while !shutdown.load(std::sync::atomic::Ordering::SeqCst) {
		ebpf.process_output_buffer()?;
	}

	debug!("Shutting down...");
	drop(monitored_cgroup);

	Ok(())
}

fn main() {
	match cmdline::get_config() {
		Ok(config) => {
			// Initialize logging
			let log_level = if config.debug {
				log::LevelFilter::Trace
			} else if config.verbose {
				log::LevelFilter::Info
			} else {
				log::LevelFilter::Warn
			};

			ebpf::init_logging(log_level);

			// Initialize the logger with the configured log level.
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
			error!("Configuration error: {error}. Check command line.");
		}
	}
}
