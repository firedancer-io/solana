extern crate rustc_version;
use {
    rustc_version::{version_meta, Channel},
    std::process::Command,
};

fn main() {
    // Copied and adapted from
    // https://github.com/Kimundi/rustc-version-rs/blob/1d692a965f4e48a8cb72e82cda953107c0d22f47/README.md#example
    // Licensed under Apache-2.0 + MIT
    match version_meta().unwrap().channel {
        Channel::Stable => {
            println!("cargo:rustc-cfg=RUSTC_WITHOUT_SPECIALIZATION");
        }
        Channel::Beta => {
            println!("cargo:rustc-cfg=RUSTC_WITHOUT_SPECIALIZATION");
        }
        Channel::Nightly => {
            println!("cargo:rustc-cfg=RUSTC_WITH_SPECIALIZATION");
        }
        Channel::Dev => {
            println!("cargo:rustc-cfg=RUSTC_WITH_SPECIALIZATION");
        }
    }

    let proto_base_path = std::path::PathBuf::from("proto");

    let protos = &[proto_base_path.join("invoke.proto")];

    protos
        .iter()
        .for_each(|proto| println!("cargo:rerun-if-changed={}", proto.display()));

    prost_build::compile_protos(protos, &[proto_base_path]).unwrap();

    println!("cargo:rerun-if-changed=tests/self_test.c");
    Command::new("clang")
        .args(["-o", "target/self_test"])
        .arg("tests/self_test.c")
        .arg("-Werror=all")
        .arg("-ldl")
        .arg("-fsanitize=address,fuzzer-no-link")
        .arg("-fsanitize-coverage=inline-8bit-counters")
        .status()
        .expect("Failed to run C compiler");
}
