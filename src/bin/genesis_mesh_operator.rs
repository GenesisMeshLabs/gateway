//! Native, read-only operator preflight. No signing key or Python runtime required.
use genesis_mesh::federation;
use std::{collections::HashMap, time::Duration};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut values = HashMap::new();
    let mut allow_http = false;
    while let Some(arg) = args.next() {
        if arg == "--help" {
            println!("genesis-mesh-operator --origin HTTPS_ORIGIN --network NAME --authority-key BASE64 [--allow-http] [--report FILE] [--policy-fragment FILE]");
            return Ok(());
        }
        if arg == "--allow-http" {
            allow_http = true;
            continue;
        }
        if ![
            "--origin",
            "--network",
            "--authority-key",
            "--report",
            "--policy-fragment",
        ]
        .contains(&arg.as_str())
        {
            return Err(format!("Unknown option {arg}"));
        }
        let value = args.next().ok_or("Missing option value")?;
        if values.insert(arg, value).is_some() {
            return Err("Duplicate option".into());
        }
    }
    let required = |name: &str| {
        values
            .get(name)
            .ok_or_else(|| format!("Missing {name}; use --help"))
    };
    let base = federation::origin(required("--origin")?, allow_http)?;
    let network = required("--network")?;
    let key = required("--authority-key")?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|_| "HTTP client initialization failed")?;
    let (genesis, crl, feed, treaties) = tokio::try_join!(
        federation::read(&client, &base, "/genesis"),
        federation::read(&client, &base, "/crl"),
        federation::read(&client, &base, "/sovereign-revocation-feed"),
        federation::read(&client, &base, "/recognition-treaties")
    )?;
    let report = federation::assess(network, key, &genesis, &crl, &feed, &treaties);
    let rendered =
        serde_json::to_string_pretty(&report).map_err(|_| "Report serialization failed")?;
    println!("{rendered}");
    if let Some(path) = values.get("--report") {
        std::fs::write(path, &rendered).map_err(|_| "Cannot write report")?;
    }
    if report["passed"] != true {
        return Err("Preflight failed; no policy fragment written".into());
    }
    if let Some(path) = values.get("--policy-fragment") {
        let fragment = serde_json::json!({network:{"authority_url":base.as_str().trim_end_matches('/'),"crl_url":base.join("/crl").unwrap().as_str(),"allow_http":allow_http,"public_mesh":false,"anchors":{crl["issuer"].as_str().ok_or("Missing CRL issuer")?:key},"minimum_crl_sequence":crl["sequence"],"crl":crl,"required_roles":[]}});
        std::fs::write(
            path,
            serde_json::to_string_pretty(&fragment).map_err(|_| "Policy serialization failed")?,
        )
        .map_err(|_| "Cannot write policy fragment")?;
    }
    Ok(())
}
