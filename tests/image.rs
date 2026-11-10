//! The container image's build rules, read from the `Dockerfile`.
//!
//! The runtime image holds static binaries on `distroless/static`: no libc,
//! OpenSSL or zlib, which the gateway does not use and which the release's
//! vulnerability gate stopped on (zlib in 1.9.2 and 1.10.0). Every base image
//! is pinned by digest and the C toolchain (Zig) by hash.

use std::path::Path;

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn from_lines(dockerfile: &str) -> Vec<String> {
    dockerfile
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("FROM "))
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_runtime_image_is_distroless_static_pinned_by_digest() {
    let dockerfile = read("Dockerfile");
    let froms = from_lines(&dockerfile);
    let runtime = froms.last().expect("a FROM line");
    assert!(
        runtime.starts_with("FROM gcr.io/distroless/static-debian"),
        "runtime stage is {runtime}"
    );
    assert!(
        runtime.contains(":nonroot@sha256:"),
        "runtime stage is {runtime}"
    );
}

#[test]
fn every_base_image_is_pinned_by_digest() {
    for line in from_lines(&read("Dockerfile")) {
        assert!(line.contains("@sha256:"), "unpinned base image: {line}");
    }
}

#[test]
fn the_binaries_are_built_static_for_musl() {
    let dockerfile = read("Dockerfile");
    assert!(dockerfile.contains("cargo zigbuild --locked --release"));
    for arch in [
        "amd64) target=x86_64-unknown-linux-musl",
        "arm64) target=aarch64-unknown-linux-musl",
    ] {
        assert!(dockerfile.contains(arch), "missing {arch}");
    }
    assert!(
        !dockerfile.contains("unknown-linux-gnu"),
        "a glibc target is still built"
    );
}

#[test]
fn the_zig_toolchain_is_hash_pinned() {
    let requirements = read("docker/zig-requirements.txt");
    let pin = requirements
        .lines()
        .find(|line| line.starts_with("ziglang=="))
        .expect("a ziglang pin");
    assert!(pin
        .trim_end_matches(['\\', ' '])
        .split("==")
        .nth(1)
        .is_some_and(|v| !v.is_empty()));
    let hashes = requirements.matches("--hash=sha256:").count();
    assert!(hashes >= 2, "one hash per build platform, found {hashes}");
    assert!(read("Dockerfile").contains("--require-hashes -r /tmp/zig-requirements.txt"));
}
