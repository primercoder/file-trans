use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = kite_server::config::Config::from_env()?;
    // Print unconditionally: operators must see the effective value even without RUST_LOG.
    // Enforcement is deliberately deferred to M2.
    println!(
        "Kite max storage bytes: {} (enforced in M2)",
        config.max_storage_bytes
    );
    let app = kite_server::router_with_db(&config.db_path).await?;
    let tls = match config.tls_paths {
        Some((cert, key)) => kite_server::tls::from_pem_files(&cert, &key).await?,
        None => kite_server::tls::self_signed().await?,
    };
    println!(
        "Kite TLS certificate SHA-256 fingerprint: {}",
        tls.fingerprint
    );
    kite_server::tls::write_fingerprint(&config.db_path, &tls.fingerprint)?;
    tracing::info!(bind = %config.bind, "kite-server listening");
    axum_server::bind_rustls(config.bind, tls.config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
