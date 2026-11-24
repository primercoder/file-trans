use std::{error::Error, fs, path::Path};

use axum_server::tls_rustls::RustlsConfig;
use sha2::{Digest as _, Sha256};

pub struct DevelopmentTls {
    pub config: RustlsConfig,
    pub cert_der: Vec<u8>,
    pub fingerprint: String,
}

/// Generates a development certificate, its TLS config, and SHA-256(DER) fingerprint.
pub async fn self_signed() -> Result<DevelopmentTls, Box<dyn Error>> {
    // Multiple transitive rustls providers are present; select one explicitly.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.signing_key.serialize_der();
    let fingerprint = hex::encode(Sha256::digest(&cert_der));
    let config = RustlsConfig::from_der(vec![cert_der.clone()], key_der).await?;
    Ok(DevelopmentTls {
        config,
        cert_der,
        fingerprint,
    })
}

/// Loads an operator-supplied PEM certificate chain and private key.
/// The certificate fingerprint has the same meaning as for self-signed certificates.
pub async fn from_pem_files(cert: &Path, key: &Path) -> Result<DevelopmentTls, Box<dyn Error>> {
    // Keep provider selection consistent with self-signed mode.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert_der = fs::read(cert)?;
    let leaf = rustls_pemfile::certs(&mut cert_der.as_slice())
        .next()
        .transpose()?
        .ok_or("KITE_TLS_CERT contains no PEM certificate")?;
    let fingerprint = hex::encode(Sha256::digest(&leaf));
    let config = RustlsConfig::from_pem_file(cert, key).await?;
    Ok(DevelopmentTls {
        config,
        cert_der: leaf.to_vec(),
        fingerprint,
    })
}

pub fn write_fingerprint(db_path: &Path, fingerprint: &str) -> Result<(), Box<dyn Error>> {
    let directory = db_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(directory)?;
    fs::write(
        directory.join("fingerprint.txt"),
        format!("{fingerprint}\n"),
    )?;
    Ok(())
}
