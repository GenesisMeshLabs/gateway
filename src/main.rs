//! Binary entrypoint for the Genesis Mesh gateway.
//!
//! All behaviour lives in [`genesis_mesh::gateway`] so integration tests can
//! drive the router directly; this file only starts a sized Tokio runtime.

fn main() {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let max_blocking = std::env::var("GATEWAY_MAX_BATCH_INFLIGHT")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4)
        .max(4);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(workers)
        .max_blocking_threads(max_blocking)
        .thread_name("gateway")
        .build()
        .expect("failed to build tokio runtime");

    if let Err(err) = rt.block_on(genesis_mesh::gateway::run()) {
        eprintln!("genesis-mesh-gateway: {err}");
        std::process::exit(1);
    }
}
