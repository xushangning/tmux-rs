use std::env;
use std::path::Path;

fn main() {
    // Get the directory of the Cargo.toml (project root)
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // Construct the path to the .libs directory relative to the project root
    let libs_path = Path::new(&manifest_dir).join(".libs");
    // Convert the path to a string and print the rustc-link-search directive
    println!("cargo:rustc-link-search={}", libs_path.display());
}
