use std::env;
use std::path::PathBuf;

fn bind_spoiler(bindings: bindgen::Builder) -> bindgen::Builder {
    println!("cargo:rustc-link-lib=spoiler");
    println!("cargo:rerun-if-changed=lib/spoiler/include/spoiler.h");
    bindings
        .header("lib/spoiler/include/spoiler.h")
        .header("lib/spoiler/include/misc.h")
        .allowlist_function("spoiler_measure")
        .allowlist_function("spoiler_free")
        .allowlist_function("measurements")
        .allowlist_function("diffs")
        .allowlist_function("auto_spoiler")
        .allowlist_function("memory_addresses")
        .allowlist_function("length")
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
        .flag("-Wall")
        .flag("-Werror")
        .flag("-Wno-sign-compare")
        .flag("-Wno-unused-parameter")
        .flag("-Wno-unused-variable")
        .flag("-g")
        .flag("-O0")
        .compile("libspoiler.a");
    for src in spoiler_srcs {
        println!("cargo:rerun-if-changed={}", src);
    }
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

    bindings = bind_spoiler(bindings);

    let bindings = run_bindgen(bindings);

    build_spoiler();

    write_bindings(bindings);
}
