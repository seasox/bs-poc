use std::env;
use std::path::PathBuf;

use glob::glob;

fn bind_spoiler(bindings: bindgen::Builder) -> bindgen::Builder {
    println!("cargo:rustc-link-lib=spoiler");
    println!("cargo:rerun-if-changed=lib/spoiler/include/spoiler.h");
    bindings.header("lib/spoiler/include/spoiler.h")
}

fn build_spoiler() {
    // build spoiler
    let spoiler_srcs = vec![
        "lib/spoiler/src/spoiler.c",
        "lib/spoiler/src/drama.c",
        "lib/spoiler/src/misc.c",
    ];
    cc::Build::new()
        .files(spoiler_srcs.clone())
        .flag("-g")
        .flag("-O0")
        .compile("libspoiler.a");
    for src in spoiler_srcs {
        println!("cargo:rerun-if-changed={}", src);
    }
}

fn bind_rsa(bindings: bindgen::Builder) -> bindgen::Builder {
    println!("cargo:rerun-if-changed=lib/rsa/rsa_crt.h");
    // Link with OpenSSL library
    println!("cargo:rerun-if-env-changed=OPENSSL_LIB_DIR");
    if let Ok(lib_dir) = std::env::var("OPENSSL_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", lib_dir);
    }
    println!("cargo:rerun-if-env-changed=OPENSSL_INCLUDE_DIR");
    if let Ok(include_dir) = std::env::var("OPENSSL_INCLUDE_DIR") {
        println!("cargo:include={}", include_dir);
    }
    bindings.header("lib/rsa/rsa_crt.h")
}

fn build_rsa() {
    // build rsa-crt
    cc::Build::new()
        .file("lib/rsa/rsa_crt.c")
        .include("/usr/include")
        .flag("-Wno-deprecated-declarations")
        .compile("librsa_crt.a");
    // Tell cargo to tell rustc to link the rsa_crt and crypto libraries
    println!("cargo:rustc-link-lib=rsa_crt");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rerun-if-changed=lib/rsa/rsa_crt.c");
}

fn bind_ptedit(bindings: bindgen::Builder) -> bindgen::Builder {
    println!("cargo:rerun-if-changed=lib/ptedit/ptedit.h");
    bindings.header("lib/ptedit/ptedit.h")
}

fn build_ptedit() {
    // build ptedit
    cc::Build::new()
        .flag("-Wno-strict-aliasing") // silence warning regarding ptedit_cast macro in lib/ptedit/ptedit.h:498:33
        .file("lib/ptedit/ptedit.c")
        .compile("libptedit.a")
}

fn run_bindgen(bindings: bindgen::Builder) -> bindgen::Bindings {
    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    bindings
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings")
}

fn write_bindings(bindings: bindgen::Bindings) {
    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    let mut bindings = bindgen::Builder::default();

    bindings = bind_rsa(bindings);
    bindings = bind_spoiler(bindings);

    bindings = bind_ptedit(bindings);

    let bindings = run_bindgen(bindings);

    build_rsa();
    build_spoiler();
    build_ptedit();

    write_bindings(bindings);
}
