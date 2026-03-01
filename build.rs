//! Build script for dataward.
//!
//! When the `embedded-worker` feature is enabled:
//! 1. Compiles the TypeScript worker (npm run build)
//! 2. Creates a compressed tarball of worker/dist/ + package.json + package-lock.json
//! 3. Computes SHA-256 hash of the tarball
//! 4. Writes both to OUT_DIR for inclusion via include_bytes!/include_str!

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    // Only run worker embedding when the feature is enabled
    if env::var("CARGO_FEATURE_EMBEDDED_WORKER").is_ok() {
        build_worker_tarball();
    }

    // Re-run if worker sources change
    println!("cargo:rerun-if-changed=worker/src/");
    println!("cargo:rerun-if-changed=worker/package.json");
    println!("cargo:rerun-if-changed=worker/package-lock.json");
    println!("cargo:rerun-if-changed=worker/tsconfig.json");
    println!("cargo:rerun-if-changed=build.rs");
}

fn build_worker_tarball() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let worker_dir = manifest_dir.join("worker");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Step 1: Build the TypeScript worker
    eprintln!("build.rs: Compiling TypeScript worker...");
    let status = std::process::Command::new("npm")
        .args(["run", "build"])
        .current_dir(&worker_dir)
        .status()
        .expect("Failed to run 'npm run build' in worker/. Is npm installed?");

    if !status.success() {
        panic!("Worker TypeScript compilation failed. Run 'cd worker && npm run build' to debug.");
    }

    // Step 2: Create tarball of dist/ + package.json + package-lock.json
    let tarball_path = out_dir.join("worker.tar.gz");
    create_worker_tarball(&worker_dir, &tarball_path);

    // Step 3: Compute SHA-256 hash
    let hash = sha256_file(&tarball_path);
    let hash_path = out_dir.join("worker.tar.gz.sha256");
    fs::write(&hash_path, &hash).expect("Failed to write tarball hash");

    eprintln!(
        "build.rs: Worker tarball created ({} bytes, SHA-256: {})",
        fs::metadata(&tarball_path).unwrap().len(),
        &hash[..16],
    );
}

fn create_worker_tarball(worker_dir: &Path, output: &Path) {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let file = fs::File::create(output)
        .unwrap_or_else(|e| panic!("Failed to create tarball at {}: {}", output.display(), e));
    let enc = GzEncoder::new(file, Compression::best());
    let mut tar = tar::Builder::new(enc);

    // Add worker/dist/ directory
    let dist_dir = worker_dir.join("dist");
    if !dist_dir.exists() {
        panic!(
            "Worker dist directory not found: {}. Run 'cd worker && npm run build' first.",
            dist_dir.display()
        );
    }
    tar.append_dir_all("dist", &dist_dir)
        .expect("Failed to add dist/ to tarball");

    // Add package.json
    let pkg_json = worker_dir.join("package.json");
    tar.append_path_with_name(&pkg_json, "package.json")
        .expect("Failed to add package.json to tarball");

    // Add package-lock.json
    let pkg_lock = worker_dir.join("package-lock.json");
    if pkg_lock.exists() {
        tar.append_path_with_name(&pkg_lock, "package-lock.json")
            .expect("Failed to add package-lock.json to tarball");
    }

    tar.finish().expect("Failed to finalize tarball");
}

fn sha256_file(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = fs::File::open(path)
        .unwrap_or_else(|e| panic!("Failed to open tarball for hashing: {}: {}", path.display(), e));
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];

    loop {
        let n = file.read(&mut buf)
            .unwrap_or_else(|e| panic!("Failed to read {} for hashing: {}", path.display(), e));
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    hex::encode(hasher.finalize())
}
