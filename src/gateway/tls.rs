//! Native mutual TLS using mounted server identity and an explicitly approved client CA.
use rustls::pki_types::{pem, pem::PemObject, CertificateDer, PrivateKeyDer};
use std::sync::Arc;

pub(super) fn from_env() -> Result<Option<axum_server::tls_rustls::RustlsConfig>, String> {
    let paths = [
        "GATEWAY_TLS_CERT_FILE",
        "GATEWAY_TLS_KEY_FILE",
        "GATEWAY_TLS_CLIENT_CA_FILE",
    ]
    .map(|key| std::env::var(key).ok());
    if paths.iter().all(Option::is_none) {
        return Ok(None);
    }
    let [Some(cert), Some(key), Some(ca)] = paths else {
        return Err("mTLS requires server certificate, key and client CA files".into());
    };
    let cert = std::fs::read(cert).map_err(|_| "cannot read TLS certificate")?;
    let key = std::fs::read(key).map_err(|_| "cannot read TLS private key")?;
    let ca = std::fs::read(ca).map_err(|_| "cannot read client CA")?;
    configuration(&cert, &key, &ca).map(Some)
}

fn configuration(
    cert: &[u8],
    key: &[u8],
    ca: &[u8],
) -> Result<axum_server::tls_rustls::RustlsConfig, String> {
    let chain = CertificateDer::pem_slice_iter(cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid TLS certificate chain")?;
    let key = PrivateKeyDer::from_pem_slice(key).map_err(|error| match error {
        pem::Error::NoItemsFound => "missing TLS key",
        _ => "invalid TLS key",
    })?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca) {
        roots
            .add(cert.map_err(|_| "invalid client CA")?)
            .map_err(|_| "invalid client CA")?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .map_err(|_| "invalid client trust roots")?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "TLS protocol configuration failed")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|_| "TLS identity configuration failed")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(config),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn mtls_accepts_approved_client_and_rejects_missing_or_foreign_certificate() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca_params, &ca_key);
        let server_key = KeyPair::generate().unwrap();
        let server = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .signed_by(&server_key, &issuer)
            .unwrap();
        let client_key = KeyPair::generate().unwrap();
        let client = CertificateParams::new(vec!["client.example".into()])
            .unwrap()
            .signed_by(&client_key, &issuer)
            .unwrap();
        let tls = configuration(
            server.pem().as_bytes(),
            server_key.serialize_pem().as_bytes(),
            ca.pem().as_bytes(),
        )
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        // Tokio refuses blocking sockets handed over with from_std.
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let handle = axum_server::Handle::new();
        let control = handle.clone();
        let server = tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .unwrap()
                .handle(handle)
                .serve(
                    axum::Router::new()
                        .route("/health", axum::routing::get(|| async { "ok" }))
                        .into_make_service(),
                )
                .await
                .unwrap();
        });
        let root = reqwest::Certificate::from_pem(ca.pem().as_bytes()).unwrap();
        let url = format!("https://localhost:{}/health", address.port());
        let approved = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(root.clone())
            .identity(
                reqwest::Identity::from_pem(
                    format!("{}{}", client.pem(), client_key.serialize_pem()).as_bytes(),
                )
                .unwrap(),
            )
            .build()
            .unwrap();
        assert_eq!(
            approved.get(&url).send().await.unwrap().status(),
            reqwest::StatusCode::OK
        );
        let missing = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(root.clone())
            .build()
            .unwrap();
        assert!(missing.get(&url).send().await.is_err());
        let foreign_key = KeyPair::generate().unwrap();
        let foreign = CertificateParams::new(vec!["foreign.example".into()])
            .unwrap()
            .self_signed(&foreign_key)
            .unwrap();
        let untrusted = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(root)
            .identity(
                reqwest::Identity::from_pem(
                    format!("{}{}", foreign.pem(), foreign_key.serialize_pem()).as_bytes(),
                )
                .unwrap(),
            )
            .build()
            .unwrap();
        assert!(untrusted.get(&url).send().await.is_err());
        control.shutdown();
        server.await.unwrap();
    }
}
