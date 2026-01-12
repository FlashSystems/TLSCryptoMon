use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/tlshstrace.bpf.c";

fn main() {
    let mut out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("tlshstrace.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH must be set in build script");
    let release_build = env::var("PROFILE").expect("PROFILE must be set in build script") == "release";

    // Initialize the parameters to be passed to clang to compile the eBPF program.
    // We put these into a vector to be able to add more dynamicly.
    let mut args: Vec<OsString> = Vec::from([
        OsString::from("-O3"),
        OsString::from("-I"),
        Path::new("vmlinux.h/include")
            .join(arch)
            .as_os_str().to_owned(),
    ]);

    // Enable to treat warnings as error if we're building a relase build.
    if release_build {
        args.push(OsString::from("-Werror"));
    }

    // Run the compiler
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(args)
        .build_and_generate(&out)
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", SRC);
}
