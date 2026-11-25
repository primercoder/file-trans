use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = kite_server::config::Config::from_env()?;
    // Print unconditionally: operators must see the effective value even without RUST_LOG.
    println!("Kite max storage bytes: {}", config.max_storage_bytes);
    let state = kite_server::state::AppState::with_quota(
        kite_server::db::Db::open(&config.db_path)?,
        config.max_storage_bytes,
    );
    let app = kite_server::router(state.clone());
    let health_app = kite_server::health_router(state);
    let tls = match config.tls_paths {
        Some((cert, key)) => kite_server::tls::from_pem_files(&cert, &key).await?,
        None => kite_server::tls::self_signed().await?,
    };
    println!(
        "Kite TLS certificate SHA-256 fingerprint: {}",
        tls.fingerprint
    );
    kite_server::tls::write_fingerprint(&config.db_path, &tls.fingerprint)?;
    println!(
        "Kite HTTPS API listening on {}; plaintext healthz probes on {}",
        config.bind, config.health_bind
    );
    let health_listener = tokio::net::TcpListener::bind(config.health_bind).await?;
    tokio::spawn(async move { axum::serve(health_listener, health_app).await });
    axum_server::bind_rustls(config.bind, tls.config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
