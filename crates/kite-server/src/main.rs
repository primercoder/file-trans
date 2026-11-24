use std::{error::Error, net::SocketAddr, path::PathBuf};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let bind: SocketAddr = std::env::var("KITE_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8443".to_owned())
        .parse()?;
    let db_path =
        PathBuf::from(std::env::var("KITE_DB_PATH").unwrap_or_else(|_| "./kite.db".to_owned()));
    let app = kite_server::router_with_db(&db_path).await?;
    let tls = kite_server::tls::self_signed().await?;
    println!(
        "Kite TLS certificate SHA-256 fingerprint: {}",
        tls.fingerprint
    );
    kite_server::tls::write_fingerprint(&db_path, &tls.fingerprint)?;
    tracing::info!(%bind, "kite-server listening");
    axum_server::bind_rustls(bind, tls.config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
