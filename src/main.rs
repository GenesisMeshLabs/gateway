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
        [arg] if arg == "--healthcheck" => return healthcheck(),
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
            println!("genesis-mesh-gateway [--version | --check-config | --init-state | --healthcheck | --help]\nConfigure with GATEWAY_POLICY_FILE. --init-state creates new durable state exactly once. --check-config requires exclusive state access when GATEWAY_STATE_FILE is set. See docs/platform.md.");
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

// A bounded local HTTP probe keeps the runtime image free of a shell and curl.
fn healthcheck() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
    use std::time::Duration;
    let mut addr: SocketAddr = std::env::var("GATEWAY_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()?;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        });
    }
    let timeout = Duration::from_millis(750);
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut status = [0u8; 13];
    stream.read_exact(&mut status)?;
    if &status != b"HTTP/1.1 200 " && &status != b"HTTP/1.0 200 " {
        return Err("local health endpoint did not return HTTP 200".into());
    }
    Ok(())
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
