//! Headless peer used by local smoke tests.
//!
//! ```text
//! KITE_SERVER=https://127.0.0.1:8443 KITE_PIN=<sha256> KITE_NAME=peer \
//! KITE_DB=/tmp/peer.db cargo run -p kite-core --example dev_peer
//! ```
//!
//! It registers a device, accepts every pairing request, echoes text messages
//! and downloads offers into `KITE_DOWNLOAD_DIR` when set.

use std::{path::PathBuf, time::Duration};

use kite_core::{Engine, InboxEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = std::env::var("KITE_SERVER").expect("KITE_SERVER");
    let pin = std::env::var("KITE_PIN").unwrap_or_default();
    let name = std::env::var("KITE_NAME").unwrap_or_else(|_| "dev-peer".into());
    let db = std::env::var("KITE_DB").unwrap_or_else(|_| "/tmp/kite-dev-peer.db".into());
    let downloads = std::env::var("KITE_DOWNLOAD_DIR").ok().map(PathBuf::from);

    let mut engine = Engine::open(&db, &server, &pin)?;
    if !engine.is_registered() {
        engine.register(&name, "dev-peer-hardware").await?;
    }
    println!("PEER_ID={}", engine.device_id());
    println!("PEER_NAME={name}");

    if let Ok(text) = std::env::var("KITE_SEND_TEXT") {
        for (peer, status) in engine.paired_peers()? {
            if status == "paired" {
                engine.send_message(&peer, &text).await?;
                println!("SENT_TEXT to={peer}");
            }
        }
    }

    if let Ok(path) = std::env::var("KITE_SEND_FILE") {
        let bytes = std::fs::read(&path)?;
        let file_name = std::path::Path::new(&path)
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "file.bin".into());
        for (peer, status) in engine.paired_peers()? {
            if status == "paired" {
                let id = engine.send_file(&peer, &file_name, &bytes).await?;
                println!("SENT_FILE to={peer} id={id} name={file_name}");
            }
        }
    }

    loop {
        let events = match engine.poll_once().await {
            Ok(events) => events,
            Err(error) => {
                eprintln!("POLL_ERROR={error}");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        for event in events {
            match event {
                InboxEvent::PairRequest { from, name } => {
                    println!("PAIR_REQUEST from={from} name={name}");
                    engine.confirm_pairing(&from).await?;
                    println!("PAIRED {from}");
                }
                InboxEvent::Message { from, text } => {
                    println!("MESSAGE from={from} text={text}");
                    engine.send_message(&from, &format!("echo: {text}")).await?;
                }
                InboxEvent::FileOffer {
                    from,
                    file_id,
                    name,
                    size,
                } => {
                    println!("FILE from={from} id={file_id} name={name} size={size}");
                    let (saved_name, bytes) = engine.download_file(&file_id).await?;
                    if let Some(dir) = &downloads {
                        std::fs::create_dir_all(dir)?;
                        std::fs::write(dir.join(&saved_name), &bytes)?;
                        println!("FILE_SAVED {}", dir.join(&saved_name).display());
                    }
                }
                other => println!("EVENT {other:?}"),
            }
        }
        tokio::time::sleep(Duration::from_millis(1200)).await;
    }
}
