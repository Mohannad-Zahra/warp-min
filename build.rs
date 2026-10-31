use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=wintun.dll");
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let src_dll = Path::new(&manifest_dir).join("wintun.dll");
    if src_dll.exists()
        && let Ok(out_dir) = env::var("OUT_DIR")
    {
        let out_path = PathBuf::from(out_dir);
        // Ancestor 3 levels up from OUT_DIR corresponds to target/(debug|release)
        if let Some(target_dir) = out_path.ancestors().nth(3) {
            let dest_dll = target_dir.join("wintun.dll");
            let _ = fs::copy(&src_dll, dest_dll);
        }
    }
}
