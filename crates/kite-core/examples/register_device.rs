//! Development helper: register a device store without the UI.
//! Usage: register_device <store.db> <server_url> <fingerprint> <name>
use kite_core::Engine;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: register_device <store.db> <server_url> <fingerprint> <name>");
        std::process::exit(2);
    }
    let mut engine = Engine::open(&args[1], &args[2], &args[3]).expect("open engine");
    engine
        .register(&args[4], "desktop-dev-helper")
        .await
        .expect("register");
    println!("REGISTERED {}", engine.device_id());
}
