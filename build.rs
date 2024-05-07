use std::env;
use std::path::PathBuf;

use glob::glob;

fn main() {
    // Tell cargo to tell rustc to link the rsa_crt and crypto libraries
    println!("cargo:rustc-link-lib=rsa_crt");
    println!("cargo:rustc-link-lib=crypto");

    // Tell cargo to invalidate the built crate whenever the RSA lib or OpenSSL changes
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=lib/rsa/rsa_crt.c");
    println!("cargo:rerun-if-changed=rsa_crt.h");
    println!("cargo:rerun-if-env-changed=OPENSSL_LIB_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_INCLUDE_DIR");

    // build rsa-crt
    cc::Build::new()
        .file("lib/rsa/rsa_crt.c")
        .include("/usr/include")
        .flag("-Wno-deprecated-declarations")
        .compile("librsa_crt.a");

    // build spoiler
    let spoiler_srcs = glob("lib/spoiler/src/*.c")
        .expect("Failed to glob lib/spoiler/src")
        .filter_map(Result::ok);
    let spoiler_incs = glob("lib/spoiler/include/*.h")
        .expect("Failed to glob lib/spoiler/include")
        .filter_map(Result::ok);
    cc::Build::new()
        .files(spoiler_srcs)
        .files(spoiler_incs)
        .flag("-g")
        .flag("-O0")
        .compile("libspoiler.a");

    // Link with OpenSSL library

    if let Ok(lib_dir) = std::env::var("OPENSSL_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", lib_dir);
    }

    if let Ok(include_dir) = std::env::var("OPENSSL_INCLUDE_DIR") {
        println!("cargo:include={}", include_dir);
    }

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("lib/rsa/rsa_crt.h")
        .header("lib/spoiler/include/spoiler.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
