//! Engine-driven two-node smoke client, usable on Linux and Windows.
//!
//! A writes its device ID to the invite file, discovers the newly registered B,
//! pairs, and sends text and optionally a file. B reads A's ID, accepts pairing,
//! downloads the file, verifies it against --file, and acknowledges receipt.

use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use kite_core::{Engine, InboxEvent};
use sha2::{Digest, Sha256};
use tokio::time::{Instant, sleep};

const MESSAGE: &str = "cross-machine smoke: hello from A";
const RECEIVED: &str = "cross-machine smoke: B received and verified A";

struct Args {
    server_url: String,
    fingerprint: String,
    role: String,
    invite_file: PathBuf,
    file: Option<PathBuf>,
    store: PathBuf,
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let mut server_url = None;
    let mut fingerprint = None;
    let mut role = None;
    let mut invite_file = None;
    let mut file = None;
    let mut store = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {arg}"))?;
        match arg.as_str() {
            "--server-url" => server_url = Some(value),
            "--ca-fingerprint" => fingerprint = Some(value),
            "--role" => role = Some(value),
            "--invite-file" => invite_file = Some(PathBuf::from(value)),
            "--file" => file = Some(PathBuf::from(value)),
            "--store" => store = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    let role = role.ok_or("missing --role A|B")?;
    if role != "A" && role != "B" {
        return Err("--role must be A or B".into());
    }
    let invite_file = invite_file.ok_or("missing --invite-file PATH")?;
    let store = store.unwrap_or_else(|| {
        invite_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(format!("smoke-{role}.db"))
    });
    Ok(Args {
        server_url: server_url.ok_or("missing --server-url URL")?,
        fingerprint: fingerprint.ok_or("missing --ca-fingerprint FP")?,
        role,
        invite_file,
        file,
        store,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;
    let expected = args.file.as_ref().map(fs::read).transpose()?;
    let mut engine = Engine::open(&args.store, &args.server_url, &args.fingerprint)?;
    engine
        .register(&format!("Smoke-{}", args.role), "cross-machine-smoke")
        .await?;
    let own_id = engine.device_id().to_owned();
    println!("REGISTER_OK role={} device_id={own_id}", args.role);
    let deadline = Instant::now() + Duration::from_secs(300);

    match args.role.as_str() {
        "A" => {
            fs::write(&args.invite_file, format!("{own_id}\n"))?;
            println!("INVITE_OK path={}", args.invite_file.display());
            let peer = loop {
                if let Some(device) = engine
                    .refresh_devices()
                    .await?
                    .into_iter()
                    .find(|device| device.device_id != own_id)
                {
                    break device.device_id;
                }
                ensure_time_left(deadline, "B registration").await?;
            };
            engine.start_pairing(&peer).await?;
            println!("PAIR_REQUEST_SENT peer={peer}");
            loop {
                if engine.poll_once().await?.iter().any(|event| {
                    matches!(event, InboxEvent::PairResponse { from, accepted: true } if *from == peer)
                }) {
                    break;
                }
                ensure_time_left(deadline, "pair response").await?;
            }
            println!("PAIR_OK peer={peer}");
            engine.send_message(&peer, MESSAGE).await?;
            println!("TEXT_SENT_OK");
            if let Some(path) = &args.file {
                let bytes = expected.as_deref().ok_or("file was not read")?;
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or("file name must be valid UTF-8")?;
                let file_id = engine.send_file(&peer, name, bytes).await?;
                println!("FILE_SENT_OK file_id={file_id} bytes={}", bytes.len());
            }
            loop {
                if engine.poll_once().await?.iter().any(|event| {
                    matches!(event, InboxEvent::Message { from, text } if *from == peer && text == RECEIVED)
                }) {
                    break;
                }
                ensure_time_left(deadline, "B receipt acknowledgement").await?;
            }
            println!("RECEIPT_OK peer={peer}");
        }
        "B" => {
            let peer = wait_for_invite(&args.invite_file, deadline).await?;
            if peer == own_id {
                return Err("invite refers to this node".into());
            }
            println!("INVITE_READ_OK peer={peer}");
            loop {
                if engine.poll_once().await?.iter().any(
                    |event| matches!(event, InboxEvent::PairRequest { from, .. } if *from == peer),
                ) {
                    break;
                }
                ensure_time_left(deadline, "pair request").await?;
            }
            engine.confirm_pairing(&peer).await?;
            println!("PAIR_OK peer={peer}");
            let mut text_ok = false;
            let mut file_ok = expected.is_none();
            while !text_ok || !file_ok {
                for event in engine.poll_once().await? {
                    match event {
                        InboxEvent::Message { from, text } if from == peer && text == MESSAGE => {
                            text_ok = true;
                            println!("TEXT_RECEIVED_OK");
                        }
                        InboxEvent::FileOffer {
                            from: _,
                            file_id,
                            name,
                            size,
                        } if expected.is_some() => {
                            let (download_name, bytes) = engine.download_file(&file_id).await?;
                            let expected_bytes = expected.as_deref().ok_or("file was not read")?;
                            if bytes != expected_bytes
                                || download_name != name
                                || size as usize != bytes.len()
                            {
                                return Err("downloaded file differs from source or offer".into());
                            }
                            file_ok = true;
                            println!(
                                "FILE_ROUNDTRIP_OK name={name} bytes={} sha256={}",
                                bytes.len(),
                                hex::encode(Sha256::digest(&bytes))
                            );
                        }
                        _ => {}
                    }
                }
                if !text_ok || !file_ok {
                    ensure_time_left(deadline, "text and file delivery").await?;
                }
            }
            engine.send_message(&peer, RECEIVED).await?;
            println!("RECEIPT_SENT_OK");
        }
        _ => unreachable!(),
    }
    println!("SMOKE-OK role={}", args.role);
    Ok(())
}

async fn wait_for_invite(
    path: &Path,
    deadline: Instant,
) -> Result<String, Box<dyn std::error::Error>> {
    loop {
        if let Ok(value) = fs::read_to_string(path) {
            let id = value.trim();
            if id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Ok(id.to_owned());
            }
        }
        ensure_time_left(deadline, "invite file").await?;
    }
}

async fn ensure_time_left(
    deadline: Instant,
    action: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if Instant::now() >= deadline {
        return Err(format!("timed out waiting for {action}").into());
    }
    sleep(Duration::from_millis(500)).await;
    Ok(())
}
