//! Binary entrypoint for the Genesis Mesh gateway.
//!
//! All behaviour lives in [`genesis_mesh::gateway`] so integration tests can
//! drive the router directly; this file only starts the Tokio runtime.

#[tokio::main]
async fn main() {
    if let Err(err) = genesis_mesh::gateway::run().await {
        eprintln!("genesis-mesh-gateway: {err}");
        std::process::exit(1);
    }
}
