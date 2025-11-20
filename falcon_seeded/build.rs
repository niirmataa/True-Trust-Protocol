#![forbid(unsafe_code)]

//! Build script for falcon_seeded

use std::env;
use std::path::PathBuf;

fn main() {
    // Get the target directory
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Compile PQClean Falcon-512 C files
    cc::Build::new()
        .file("pqclean/crypto_sign/falcon-512/clean/codec.c")
        .file("pqclean/crypto_sign/falcon-512/clean/common.c")
        .file("pqclean/crypto_sign/falcon-512/clean/fft.c")
        .file("pqclean/crypto_sign/falcon-512/clean/fpr.c")
        .file("pqclean/crypto_sign/falcon-512/clean/keygen.c")
        .file("pqclean/crypto_sign/falcon-512/clean/pqclean.c")
        .file("pqclean/crypto_sign/falcon-512/clean/rng.c")
        .file("pqclean/crypto_sign/falcon-512/clean/sign.c")
        .file("pqclean/crypto_sign/falcon-512/clean/vrfy.c")
        .file("pqclean/common/fips202.c")
        .file("src/ffi.c")
        .include("pqclean/crypto_sign/falcon-512/clean")
        .include("pqclean/common")
        .compile("falcon512");

    // Link the library
    println!("cargo:rustc-link-lib=static=falcon512");
    println!("cargo:rustc-link-search=native={}", out_dir.display());

    // Re-run build if C files change
    println!("cargo:rerun-if-changed=pqclean/");
}
