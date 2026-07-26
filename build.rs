use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=ORLOP_BUILD_VERSION");

    let version = env::var("ORLOP_BUILD_VERSION")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| env::var("CARGO_PKG_VERSION").expect("Cargo sets CARGO_PKG_VERSION"));

    println!("cargo:rustc-env=ORLOP_BUILD_VERSION={version}");
}
