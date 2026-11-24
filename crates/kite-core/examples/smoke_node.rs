//! Two-process smoke client for the containerized server.
//!
//! Usage: smoke_node <name> <base_url> <fingerprint_hex> <store_path> <initiator|responder>
//! The peer's display name is supplied as SMOKE_PEER_NAME. SMOKE_MESSAGE can
//! override the fixed payload used by the initiator and checked by the responder.

use std::{env, error::Error, time::Duration};

use kite_core::{Engine, InboxEvent};
use tokio::time::{Instant, sleep};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 {
        return Err("usage: smoke_node <name> <base_url> <fingerprint_hex> <store_path> <initiator|responder>".into());
    }
    let (name, base_url, fingerprint, store, role) =
        (&args[1], &args[2], &args[3], &args[4], &args[5]);
    let peer_name = env::var("SMOKE_PEER_NAME")?;
    let expected_message =
        env::var("SMOKE_MESSAGE").unwrap_or_else(|_| "three-endpoint smoke: hello from A".into());
    let mut engine = Engine::open(store, base_url, fingerprint)?;
    engine.register(name, &format!("smoke-hardware-{name}")).await?;
    println!("REGISTER_OK name={name} device_id={}", engine.device_id());

    let deadline = Instant::now() + Duration::from_secs(30);
    let peer_id = loop {
        let peer = engine
            .refresh_devices()
            .await?
            .into_iter()
            .find(|device| device.name == peer_name);
        if let Some(peer) = peer {
            break peer.device_id;
        }
        ensure_time_left(deadline, "peer discovery")?;
        sleep(Duration::from_millis(500)).await;
    };
    println!("DISCOVERY_OK peer={peer_id}");

    match role.as_str() {
        "initiator" => {
            engine.start_pairing(&peer_id).await?;
            println!("PAIR_REQUEST_SENT peer={peer_id}");
            loop {
                if engine.poll_once().await?.iter().any(|event| matches!(
                    event,
                    InboxEvent::PairResponse { from, accepted: true } if *from == peer_id
                )) {
                    break;
                }
                ensure_time_left(deadline, "pair response")?;
                sleep(Duration::from_millis(500)).await;
            }
            println!("PAIR_OK peer={peer_id}");
            engine.send_message(&peer_id, &expected_message).await?;
            println!("SEND_OK peer={peer_id} message={expected_message}");
        }
        "responder" => {
            loop {
                if engine.poll_once().await?.iter().any(|event| matches!(
                    event,
                    InboxEvent::PairRequest { from, .. } if *from == peer_id
                )) {
                    break;
                }
                ensure_time_left(deadline, "pair request")?;
                sleep(Duration::from_millis(500)).await;
            }
            engine.confirm_pairing(&peer_id).await?;
            println!("PAIR_OK peer={peer_id}");
            loop {
                for event in engine.poll_once().await? {
                    if let InboxEvent::Message { from, text } = event
                        && from == peer_id
                        && text == expected_message
                    {
                        println!("RECEIVE_OK from={from} message={text}");
                        return Ok(());
                    }
                }
                ensure_time_left(deadline, "encrypted message")?;
                sleep(Duration::from_millis(500)).await;
            }
        }
        _ => return Err("role must be initiator or responder".into()),
    }
    Ok(())
}

fn ensure_time_left(deadline: Instant, action: &str) -> Result<(), Box<dyn Error>> {
    if Instant::now() >= deadline {
        return Err(format!("timed out waiting for {action}").into());
    }
    Ok(())
}
