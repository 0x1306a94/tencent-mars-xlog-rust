// build.rs
use std::env;
use std::path::PathBuf;

fn main() {
    cc::Build::new()
        .file("micro-uecc/uECC.c")
        .compile("micro-uecc");
    println!("cargo:rerun-if-changed=micro-uecc/uECC.c");
    println!("cargo:rustc-link-lib=micro-uecc");

    println!("cargo:rerun-if-changed=micro-uecc/uECC.h");
    let bindings = bindgen::Builder::default()
        .header("micro-uecc/uECC.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
    let out_path = PathBuf::from("src");
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
