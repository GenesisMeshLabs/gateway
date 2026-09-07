//! `genesis-mesh` - command line access to the trust core.
//!
//! Deliberately dependency-free argument parsing: the crate is meant to build
//! on constrained edge targets, and a CLI arg parser is not worth a dependency
//! tree there.

use std::collections::BTreeMap;
use std::process::ExitCode;

use chrono::{Duration, Utc};
use genesis_mesh::canonical;
use genesis_mesh::crypto::KeyPair;
use genesis_mesh::models::{JoinCertificate, Signed};
use genesis_mesh::trust::{verify_join_certificate, Policy, TrustAnchors};

const USAGE: &str = "\
genesis-mesh - Genesis Mesh portable trust

USAGE:
    genesis-mesh keygen
    genesis-mesh issue --seed <b64> --key-id <id> --node-key <b64> \\
                       --network <name> [--role <r>]... [--days <n>]
    genesis-mesh verify --cert <file> --anchor <key-id>=<pubkey-b64> [--anchor ...] \\
                       [--crl <file>]
    genesis-mesh canonical --file <file>

COMMANDS:
    keygen     Generate an Ed25519 identity. Prints seed and public key.
    issue      Issue and sign a join certificate. Prints it as JSON.
    verify     Evaluate a certificate against trust anchors. Exit 0 if trusted.
    canonical  Print the canonical JSON of a file, for cross-checking with
               the Python implementation.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let result = match args[0].as_str() {
        "keygen" => keygen(),
        "issue" => issue(&args[1..]),
        "verify" => return verify(&args[1..]),
        "canonical" => show_canonical(&args[1..]),
        other => Err(format!("unknown command '{other}'\n\n{USAGE}")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Collect `--flag value` pairs. Repeated flags accumulate.
fn parse_flags(args: &[String]) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let key = args[i]
            .strip_prefix("--")
            .ok_or_else(|| format!("expected a --flag, found '{}'", args[i]))?;
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("--{key} needs a value"))?;
        out.entry(key.to_string()).or_default().push(value.clone());
        i += 2;
    }
    Ok(out)
}

fn one<'a>(flags: &'a BTreeMap<String, Vec<String>>, key: &str) -> Result<&'a String, String> {
    flags
        .get(key)
        .and_then(|v| v.first())
        .ok_or_else(|| format!("missing required --{key}"))
}

fn keygen() -> Result<(), String> {
    let kp = KeyPair::generate().map_err(|e| e.to_string())?;
    println!("seed_b64       {}", kp.seed_b64());
    println!("public_key_b64 {}", kp.public_key_b64());
    eprintln!("\nKeep the seed secret; it is the private key.");
    Ok(())
}

fn issue(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let keypair = KeyPair::from_seed_b64(one(&flags, "seed")?).map_err(|e| e.to_string())?;
    let days: i64 = flags
        .get("days")
        .and_then(|v| v.first())
        .map(|d| d.parse::<i64>())
        .transpose()
        .map_err(|e| format!("--days must be a whole number: {e}"))?
        .unwrap_or(7);

    let now = Utc::now();
    let mut cert = JoinCertificate {
        cert_id: format!("cert-{}", now.timestamp_millis()),
        node_public_key: one(&flags, "node-key")?.clone(),
        network_name: one(&flags, "network")?.clone(),
        roles: flags.get("role").cloned().unwrap_or_default(),
        issued_at: now,
        expires_at: now + Duration::days(days),
        issued_by: one(&flags, "key-id")?.clone(),
        signatures: vec![],
    };
    cert.sign(&keypair, one(&flags, "key-id")?)
        .map_err(|e| e.to_string())?;

    let rendered = serde_json::to_string_pretty(&cert).map_err(|e| e.to_string())?;
    println!("{rendered}");
    Ok(())
}

fn verify(args: &[String]) -> ExitCode {
    match verify_inner(args) {
        Ok(trusted) => {
            if trusted {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn verify_inner(args: &[String]) -> Result<bool, String> {
    let flags = parse_flags(args)?;

    let cert_raw = std::fs::read_to_string(one(&flags, "cert")?).map_err(|e| e.to_string())?;
    let cert: JoinCertificate = serde_json::from_str(&cert_raw).map_err(|e| e.to_string())?;

    let mut anchors = TrustAnchors::new();
    for entry in flags.get("anchor").into_iter().flatten() {
        let (key_id, public_key) = entry
            .split_once('=')
            .ok_or_else(|| format!("--anchor must be <key-id>=<pubkey-b64>, got '{entry}'"))?;
        anchors.insert(key_id.to_string(), public_key.to_string());
    }
    if anchors.is_empty() {
        return Err("at least one --anchor is required".into());
    }

    let crl = match flags.get("crl").and_then(|v| v.first()) {
        Some(path) => {
            let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            Some(serde_json::from_str(&raw).map_err(|e| e.to_string())?)
        }
        None => None,
    };

    let mut policy = Policy::new(&anchors);
    if let Some(ref list) = crl {
        policy = policy.with_crl(list);
    }

    let decision = verify_join_certificate(&cert, &policy).map_err(|e| e.to_string())?;
    if decision.trusted {
        println!("trusted");
    } else {
        println!("UNTRUSTED");
        for reason in &decision.reasons {
            println!("  - {reason:?}");
        }
    }
    Ok(decision.trusted)
}

fn show_canonical(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let raw = std::fs::read_to_string(one(&flags, "file")?).map_err(|e| e.to_string())?;
    let value: serde_json::Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    println!("{}", canonical::canonicalize(&value));
    Ok(())
}
