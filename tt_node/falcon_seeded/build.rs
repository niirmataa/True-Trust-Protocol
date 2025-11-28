//! Build script for falcon_seeded (local copy for tt_node/falcon_seeded)

use std::env;
use std::path::PathBuf;

fn main() {
    // Get the target directory
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    
    // Compile PQClean Falcon-512 C files (paths relative to this crate)
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
        .file("pqclean/common/randombytes.c")
        .file("pqclean/common/fips202.c")
        .file("pqclean/common/sp800-185.c")
        // do not compile platform-specific NEON optimizations on x86
        .include("pqclean/crypto_sign/falcon-512/clean")
        .include("pqclean/common")
        .file("pqclean/tt_falcon_wrappers.c")
        .include("pqclean/common")
        .compile("falcon512");
    
    // Link the library
    println!("cargo:rustc-link-lib=static=falcon512");
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    
    // Re-run build if C files change
    println!("cargo:rerun-if-changed=pqclean/");
}
