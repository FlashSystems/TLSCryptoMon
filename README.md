With the advent of quantum computers, the migration to post-quantum cryptography is becoming increasingly relevant. One of the first — and easiest — steps is to secure TLS communication against 'harvest now, decrypt later' attacks. These attacks leverage the fact that storage is cheap and that quantum computers capable of breaking RSA and ECC are only a few years away. Data harvested and stored now will be decrypted at a later date using quantum computers.

To prevent this type of attack, the first phase of the TLS handshake must be strengthened. One of the first things the two communicating computers do is generate a shared, random key to encrypt the rest of the TLS session. If this key exchange uses a post-quantum algorithm, 'harvest now, decrypt later' is impossible.

NIST has standardised the post-quantum algorithms [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) and [ML-DSA](https://csrc.nist.gov/pubs/fips/204/final). With OpenSSL 3.5, ML-KEM can be used for TLS key agreement. However, to avoid placing sole reliance on these new algorithms, a hybrid key exchange should be used. Combining an elliptic curve with ML-KEM provides the best of both worlds: a well-tested key exchange mechanism (the elliptic curve) and quantum safety (due to ML-KEM). The two relevant web browsers, Chrome and Firefox, already implement this hybrid key exchange. It's just a matter of enabling it on the server side.

However, one crucial thing is missing: observability.

Neither OpenSSL, Apache nor OpenLDAP logs the key-exchange mechanism used. They can log the encryption algorithm (e.g. AES) used for the transferred data. However, it is impossible to obtain information on how the key was generated.

TLSCryptoMon solves this very specific problem. It enables you to analyse TLS 1.3 traffic and identify the key exchange and encryption algorithms used.

# How does it work?

TLSCryptoMon uses a dynamically loaded eBPF program within the Linux kernel. This program analyses the first few packets sent by the server on the specified port(s). The packet we are interested in is the TLS Server Hello packet. This is the second packet in the [TLS handshake](https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3) and contains extensions that specify the selected cipher suites. This information is then passed to a user-space program, which prints the source and destination IP address and port, as well as the selected cipher suite and key exchange mechanism, to the console.

# Usage

The only mandatory parameter is `-p` that specifies the port to monitor on the host system. This parameter can be specified multiple times to monitor multiple ports. There are some more parameters that can be specified:

| Paramter | Description |
| ---: | :----- |
| `-d` | Enables debug output for the core program. |
| `-v` | Enables verbose output. This prints more information, but not as much information as the debug option. |
| `-D` | Enables debug output on the eBPF program that is loaded into the kernel. Debug output can be retrieved via tracefs's `trace_pipe`. Normally the `trace_pipe` pipe is accessible via `/sys/kernel/tracing/trace_pipe`. |
| `-c` | Monitor only processes belonging to this cgroup. Default: `/sys/fs/cgroup/` |
| `-n` | Show only connections that are not using a quantum safe key exchange mechanism. |

To monitor all HTTPs taffic on port 443 use:

```bash
sudo ./tlscryptomon -p 443
```

The following information is logged on StdOut as one space-separated line for every new TLS connection that uses TLS 1.3:

- Timestamp
- Remote IP (v4 or v6 format)
- Remote port
- Local IP (v4 or v6 format)
- Local port
- Used key exchange algorihm
- Used data encryption algorithm

## Example

```text
::ffff:192.168.0.10 33166 ::ffff:192.168.0.1 443 X25519MLKEM768 TLS_AES_128_GCM_SHA256
```

This exmaple shows a TLS 1.3 connection originating from 192.168.0.10 and destined for the local server at 192.168.0.1 using the destination port 443. The server selected `X25519MLKEM768` as the key exchange algorithm and `TLS_AES_128_GCM_SHA256` for data encryption.

# Compiling

To compile the program yourself the following tools must be installed:

- Rust version 1.80 or later
- Cargo
- Clang compiler for compiling the eBPF code

Then clone the repository and update the submodules:

```bash
git clone https://github.com/FlashSystems/TLSCryptoMon.git
cd TLSCryptoMon
git submodule update --init --recursive
```

Once this has been done, the program can be compiled by entering the following command:

```bash
cargo build --release
```

The final executable `tlscryptomon` will be placed in `target/release/`

# Caveats

TLSCryptoMon is an initial attempt at an idea. While it works remarkably well, there may be many edge cases where it does not behave as expected. Always treat the output with caution.

Although the program is optimised to have as little performance impact as possible, it has not been tested on any high-throughput system.

# License

Because this program loads code into the Linux Kernel it uses two licenses:
* GPL v2 or later for the eBPF program
* BSD-2-Clause for the user space program
