//! Binary entrypoint for the Genesis Mesh gateway.
//!
//! All behaviour lives in [`genesis_mesh::gateway`] so integration tests can
//! drive the router directly; this file only starts the Tokio runtime.

fn main() {
    if let Err(err) = start() {
        eprintln!("genesis-mesh-gateway: {err}");
        std::process::exit(1);
    }
}

fn start() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [arg] if arg == "--init-state" => {
            genesis_mesh::gateway::Config::initialize_state()?;
            println!("Durable state initialized from verified operator policy");
            return Ok(());
        }
        [arg] if arg == "--version" => {
            println!("genesis-mesh-gateway {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        [arg] if arg == "--check-config" => {
            genesis_mesh::gateway::Config::from_env().map_err(|e| format!("configuration: {e}"))?;
            println!("Configuration valid");
            return Ok(());
        }
        [arg] if arg == "--help" => {
            println!("genesis-mesh-gateway [--version | --check-config | --init-state | --help]\nConfigure with GATEWAY_POLICY_FILE. --init-state creates new durable state exactly once. --check-config requires exclusive state access when GATEWAY_STATE_FILE is set. See docs/platform.md.");
            return Ok(());
        }
        [] => {}
        _ => return Err("unknown arguments; use --help".into()),
    }
    let workers = setting("TOKIO_WORKER_THREADS", 2, 256)?;
    let blocking = setting("TOKIO_MAX_BLOCKING_THREADS", 16, 512)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(blocking)
        .enable_all()
        .build()?;
    let result = runtime.block_on(genesis_mesh::gateway::run());
    runtime.shutdown_timeout(std::time::Duration::from_secs(30));
    result
}

fn setting(name: &str, default: usize, maximum: usize) -> Result<usize, String> {
    let value = std::env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .parse::<usize>()
        .map_err(|_| format!("{name}: expected positive integer"))?;
    if !(1..=maximum).contains(&value) {
        return Err(format!("{name}: expected 1..={maximum}"));
    }
    Ok(value)
}
