use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/exec.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("exec.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-I", "src/bpf", "-Wall", "-Wno-unused-function", arch_define().as_str()])
        .build_and_generate(&out)
        .expect("failed to build BPF program");
    println!("cargo:rerun-if-changed=src/bpf");
}

fn arch_define() -> String {
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("riscv64") => "riscv",
        _ => "x86",
    };
    format!("-D__TARGET_ARCH_{arch}")
}
