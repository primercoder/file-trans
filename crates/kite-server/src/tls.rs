use std::{error::Error, fs, path::Path, sync::Arc};

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
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.signing_key.serialize_der();
    let fingerprint = hex::encode(Sha256::digest(&cert_der));
    let config = tls13_config(RustlsConfig::from_der(vec![cert_der.clone()], key_der).await?)?;
    Ok(DevelopmentTls {
        config,
        cert_der,
        fingerprint,
    })
}

/// Loads a stable development certificate from `dir`, generating and persisting
/// it on first use so the fingerprint does not change across restarts.
pub async fn self_signed_in(dir: &Path) -> Result<DevelopmentTls, Box<dyn Error>> {
    let cert_path = dir.join("tls-cert.pem");
    let key_path = dir.join("tls-key.pem");
    if cert_path.exists() && key_path.exists() {
        return from_pem_files(&cert_path, &key_path).await;
    }
    fs::create_dir_all(dir)?;
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
    fs::write(&cert_path, certified.cert.pem())?;
    fs::write(&key_path, certified.signing_key.serialize_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
    }
    from_pem_files(&cert_path, &key_path).await
}

/// Loads an operator-supplied PEM certificate chain and private key.
/// The certificate fingerprint has the same meaning as for self-signed certificates.
pub async fn from_pem_files(cert: &Path, key: &Path) -> Result<DevelopmentTls, Box<dyn Error>> {
    // Keep provider selection consistent with self-signed mode.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cert_der = fs::read(cert)?;
    let leaf = rustls_pemfile::certs(&mut cert_der.as_slice())
        .next()
        .transpose()?
        .ok_or("KITE_TLS_CERT contains no PEM certificate")?;
    let fingerprint = hex::encode(Sha256::digest(&leaf));
    let config = tls13_config(RustlsConfig::from_pem_file(cert, key).await?)?;
    Ok(DevelopmentTls {
        config,
        cert_der: leaf.to_vec(),
        fingerprint,
    })
}

fn tls13_config(base: RustlsConfig) -> Result<RustlsConfig, Box<dyn Error>> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(base.get_inner().cert_resolver.clone());
    config.alpn_protocols = base.get_inner().alpn_protocols.clone();
    Ok(RustlsConfig::from_config(Arc::new(config)))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn self_signed_certificate_is_stable_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let first = self_signed_in(dir.path()).await.unwrap();
        let second = self_signed_in(dir.path()).await.unwrap();
        assert_eq!(
            first.fingerprint, second.fingerprint,
            "a self-signed deployment must keep its fingerprint"
        );
        assert!(dir.path().join("tls-cert.pem").exists());
        assert!(dir.path().join("tls-key.pem").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(dir.path().join("tls-key.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "the private key must stay private");
        }
    }
}
