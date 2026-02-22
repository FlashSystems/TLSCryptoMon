// SPDX-License-Identifier: BSD-3-Clause
use std::{collections::HashSet, path::PathBuf};
use clap::Parser;
use thiserror::Error;

const MAX_PORTS: u8 = 16;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Too many ports. Used {0} of {1} allowed ports.")]
    TooManyPorts(usize, u8),
}

/// This program analyses TLS server hello packages to determin the used
/// key exchange algorithm and cipher suite.
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Config {
    /// Enables debug output of the program. To eneable debug output for the eBPF program hat is loaded into the kernel use -D.
    #[arg(short, long)]
    pub debug: bool,

    /// Enable verbose output. This prints more information, but not as much information as the debug option.
    #[arg(short, long)]
    pub verbose: bool,

    /// Enables debug output on the eBPF program that is loaded into the kernel.
    /// Debug output can be retrieved via tracefs's `trace_pipe`.
    #[arg(short = 'D')]
    pub debug_ebpf: bool,

    /// Port to monitor.
    #[arg(short = 'p', required = true)]
    pub ports: Vec<u16>,

    /// Monitor only processes belonging to this cgroup.
    #[arg(short, long, default_value = "/sys/fs/cgroup/")]
    pub cgroup: PathBuf,

    /// Output only connections using non post quantum key exchanges
    #[arg(short = 'n', long)]
    pub non_pq_only: bool
}

pub fn get_config() -> Result<Config, ConfigError>  {
    let mut config = Config::parse();

    // Make sure the ports are unique
    let unique_ports: HashSet<u16> = HashSet::from_iter(config.ports);
    config.ports = unique_ports.into_iter().collect();
    if config.ports.len() > MAX_PORTS as usize {
        return Err(ConfigError::TooManyPorts(config.ports.len(), MAX_PORTS));
    }

    Ok(config)
}