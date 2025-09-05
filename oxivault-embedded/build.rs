//! Build script for oxivault-embedded

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Get OUT_DIR
    let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());

    // Copy memory.x to OUT_DIR for the linker
    println!("cargo:rustc-link-search={}", out.display());
    fs::copy("memory.x", out.join("memory.x")).ok();

    // Re-run if memory.x changes
    println!("cargo:rerun-if-changed=memory.x");
}
