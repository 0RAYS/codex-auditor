use std::env;
use std::path::PathBuf;

const DEFAULT_PREFIX: &str = "/usr/share/xref";
const XREF_DEFAULT_PREFIX_ENV: &str = "XREF_DEFAULT_PREFIX";
const PREFIX_ENV: &str = "PREFIX";

fn main() {
    println!("cargo:rerun-if-env-changed={XREF_DEFAULT_PREFIX_ENV}");
    println!("cargo:rerun-if-env-changed={PREFIX_ENV}");

    let prefix = env::var_os(XREF_DEFAULT_PREFIX_ENV)
        .or_else(|| env::var_os(PREFIX_ENV))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PREFIX));

    if !prefix.is_absolute() {
        panic!(
            "{XREF_DEFAULT_PREFIX_ENV}/{PREFIX_ENV} must be an absolute path, got {}",
            prefix.display()
        );
    }

    let prefix = prefix.to_str().expect("default prefix must be valid UTF-8");
    println!("cargo:rustc-env=XREF_DEFAULT_PREFIX={prefix}");
}
