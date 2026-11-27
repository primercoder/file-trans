mod chatlog;
mod settings;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chatlog::{ChatLog, ChatRecord, Conversation};
use kite_core::{Engine, GroupDto, InboxEvent};
use serde::Serialize;
use settings::{Account, Settings, account_id};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
#[cfg(desktop)]
use tauri::menu::{Menu, MenuItem};
#[cfg(desktop)]
use tauri::tray::TrayIconBuilder;
use tauri::{Emitter, Manager, WindowEvent};
use tauri_plugin_notification::NotificationExt;
use tokio::sync::Mutex;

struct Loaded {
    account_id: String,
    engine: Engine,
}

struct AppState {
    root: PathBuf,
    settings: Mutex<Settings>,
    engine: Mutex<Option<Loaded>>,
    /// Shared from Android intents or `--share` command line invocations.
    share: StdMutex<Option<SharePayload>>,
}

#[derive(Clone, Debug, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SharePayload {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    files: Vec<ShareFile>,
}

#[derive(Clone, Debug, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShareFile {
    path: String,
    name: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    configured: bool,
    registered: bool,
    device_id: Option<String>,
    name: Option<String>,
    server_url: Option<String>,
    theme: String,
    locale: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountView {
    id: String,
    server_url: String,
    device_id: Option<String>,
    name: Option<String>,
    active: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Peer {
    device_id: String,
    name: Option<String>,
    status: String,
}

/// Local identity material a user can compare out of band with the peer.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerSecurity {
    device_id: String,
    safety_number: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatView {
    peer: String,
    direction: String,
    kind: String,
    text: String,
    file_id: Option<String>,
    file_name: Option<String>,
    size: Option<u64>,
    ts: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PollResult {
    messages: Vec<ChatView>,
    devices_changed: bool,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn raw_hw_id() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            let id = id.trim();
            if !id.is_empty() {
                return id.to_owned();
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -Name MachineGuid).MachineGuid",
            ])
            .output()
        {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if !value.is_empty() {
                return value;
            }
        }
    }
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "kite-device".into());
    format!("{host}-{}", std::env::consts::OS)
}

/// Parses `--share <path>...` from a command line (Windows context menu, Linux
/// service menu, or a second-instance invocation).
fn parse_share_args(args: &[String]) -> Option<SharePayload> {
    let index = args.iter().position(|arg| arg == "--share")?;
    let files: Vec<ShareFile> = args[index + 1..]
        .iter()
        .filter(|arg| !arg.starts_with("--"))
        .filter_map(|path| {
            let path_buf = PathBuf::from(path);
            let name = path_buf.file_name()?.to_string_lossy().to_string();
            Some(ShareFile {
                path: path_buf.to_string_lossy().to_string(),
                name,
            })
        })
        .collect();
    if files.is_empty() {
        None
    } else {
        Some(SharePayload {
            text: None,
            files,
        })
    }
}

/// Android's MainActivity copies shared content into this directory because the
/// WebView cannot read `content://` URIs directly.
fn android_share_dir(root: &Path) -> PathBuf {
    root.join("incoming_share")
}

fn take_android_share(root: &Path) -> Option<SharePayload> {
    let path = android_share_dir(root).join("share.json");
    let bytes = std::fs::read(&path).ok()?;
    let payload: SharePayload = serde_json::from_slice(&bytes).ok()?;
    let _ = std::fs::remove_file(&path);
    Some(payload)
}

fn store_share(state: &AppState, payload: SharePayload) {
    if let Ok(mut slot) = state.share.lock() {
        *slot = Some(payload);
    }
}

fn profile_dir(root: &Path, id: &str) -> PathBuf {
    root.join("profiles").join(id)
}

async fn active_account(state: &AppState) -> Result<Account, String> {
    let settings = state.settings.lock().await;
    settings
        .active_account()
        .cloned()
        .ok_or_else(|| "尚未添加服务器".to_owned())
}

fn open_engine(state: &AppState, account: &Account) -> Result<Loaded, String> {
    let dir = profile_dir(&state.root, &account.id);
    std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    let engine = Engine::open(
        dir.join("kite.db"),
        &account.server_url,
        account.fingerprint.as_deref().unwrap_or(""),
    )
    .map_err(|error| {
        eprintln!("KITE_ENGINE_ERROR: {error}");
        error.to_string()
    })?;
    Ok(Loaded {
        account_id: account.id.clone(),
        engine,
    })
}

async fn ensure_engine(state: &AppState) -> Result<(), String> {
    let account = active_account(state).await?;
    let mut guard = state.engine.lock().await;
    if guard
        .as_ref()
        .is_some_and(|loaded| loaded.account_id == account.id)
    {
        return Ok(());
    }
    *guard = Some(open_engine(state, &account)?);
    Ok(())
}

async fn with_engine<T>(
    state: &AppState,
    f: impl FnOnce(&mut Engine) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kite_core::Result<T>> + Send + '_>,
    >,
) -> Result<T, String> {
    ensure_engine(state).await?;
    let mut guard = state.engine.lock().await;
    let loaded = guard.as_mut().ok_or("尚未初始化")?;
    f(&mut loaded.engine).await.map_err(|error| error.to_string())
}

async fn chat_log(state: &AppState) -> Result<ChatLog, String> {
    let account = active_account(state).await?;
    Ok(ChatLog::new(&profile_dir(&state.root, &account.id)))
}

async fn current_status(state: &AppState) -> Status {
    let _ = ensure_engine(state).await;
    let (engine_registered, engine_device) = {
        let guard = state.engine.lock().await;
        match guard.as_ref() {
            Some(loaded) => (
                Some(loaded.engine.is_registered()),
                Some(loaded.engine.device_id().to_owned()),
            ),
            None => (None, None),
        }
    };
    let mut settings = state.settings.lock().await;
    if let (Some(account), Some(device_id)) = (settings.active_account().cloned(), engine_device.clone()) {
        if account.device_id.as_deref() != Some(device_id.as_str()) {
            if let Some(stored) = settings
                .accounts
                .iter_mut()
                .find(|stored| stored.id == account.id)
            {
                stored.device_id = Some(device_id);
                let _ = settings.save(&state.root);
            }
        }
    }
    let account = settings.active_account();
    let registered = engine_registered
        .unwrap_or_else(|| account.and_then(|account| account.device_id.as_ref()).is_some());
    Status {
        configured: account.is_some(),
        registered,
        device_id: account.and_then(|account| account.device_id.clone()),
        name: account.and_then(|account| account.name.clone()),
        server_url: account.map(|account| account.server_url.clone()),
        theme: settings.theme.clone(),
        locale: settings.locale.clone(),
    }
}

#[tauri::command]
async fn status(state: tauri::State<'_, Arc<AppState>>) -> Result<Status, String> {
    Ok(current_status(&state).await)
}

#[tauri::command]
async fn accounts(state: tauri::State<'_, Arc<AppState>>) -> Result<Vec<AccountView>, String> {
    let settings = state.settings.lock().await;
    Ok(settings
        .accounts
        .iter()
        .map(|account| AccountView {
            id: account.id.clone(),
            server_url: account.server_url.clone(),
            device_id: account.device_id.clone(),
            name: account.name.clone(),
            active: settings.active.as_deref() == Some(account.id.as_str()),
        })
        .collect())
}

#[tauri::command]
async fn register(
    state: tauri::State<'_, Arc<AppState>>,
    server_url: String,
    fingerprint: Option<String>,
    name: String,
) -> Result<Status, String> {
    let url = server_url.trim().trim_end_matches('/').to_owned();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("服务器地址必须以 https:// 或 http:// 开头".into());
    }
    if url.starts_with("http://") {
        return Err("出于安全考虑，服务器地址必须使用 https://".into());
    }
    let name = name.trim().to_owned();
    if name.is_empty() {
        return Err("请填写设备名称".into());
    }
    let pin = fingerprint
        .map(|pin| pin.trim().to_owned())
        .filter(|pin| !pin.is_empty());
    if let Some(pin) = &pin {
        if pin.len() != 64 || !pin.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("证书指纹必须是 64 位十六进制字符".into());
        }
    }

    let id = account_id(&url);
    let account = Account {
        id: id.clone(),
        server_url: url.clone(),
        fingerprint: pin,
        device_id: None,
        name: Some(name.clone()),
    };
    let engine = open_engine(&state, &account)?.engine;
    // Registration is network-bound; do it before touching shared state.
    let mut engine = engine;
    engine
        .register(&name, &raw_hw_id())
        .await
        .map_err(|error| error.to_string())?;
    let device_id = engine.device_id().to_owned();
    {
        let mut settings = state.settings.lock().await;
        let mut stored = account;
        stored.device_id = Some(device_id.clone());
        stored.name = Some(name.clone());
        settings.upsert_account(stored);
        settings.active = Some(id.clone());
        settings.save(&state.root)?;
    }
    {
        let mut guard = state.engine.lock().await;
        *guard = Some(Loaded {
            account_id: id,
            engine,
        });
    }
    Ok(current_status(&state).await)
}

#[tauri::command]
async fn switch_account(
    state: tauri::State<'_, Arc<AppState>>,
    id: String,
) -> Result<Status, String> {
    {
        let mut settings = state.settings.lock().await;
        if settings.account(&id).is_none() {
            return Err("账户不存在".into());
        }
        settings.active = Some(id.clone());
        settings.save(&state.root)?;
    }
    *state.engine.lock().await = None;
    ensure_engine(&state).await?;
    Ok(current_status(&state).await)
}

/// Deletes an account on the server and removes its local profile.
#[tauri::command]
async fn delete_account(
    state: tauri::State<'_, Arc<AppState>>,
    id: String,
) -> Result<Status, String> {
    let account = {
        let settings = state.settings.lock().await;
        settings.account(&id).cloned().ok_or("账户不存在")?
    };
    // Delete remotely with the account's own token, even when it is not active.
    let mut engine = match open_engine(&state, &account) {
        Ok(loaded) => loaded.engine,
        Err(error) => return Err(error),
    };
    engine
        .delete_account()
        .await
        .map_err(|error| format!("服务器未能确认注销: {error}"))?;
    drop(engine);
    {
        let mut guard = state.engine.lock().await;
        if guard
            .as_ref()
            .is_some_and(|loaded| loaded.account_id == id)
        {
            *guard = None;
        }
    }
    let dir = profile_dir(&state.root, &id);
    let _ = std::fs::remove_dir_all(&dir);
    {
        let mut settings = state.settings.lock().await;
        settings.remove_account(&id);
        settings.save(&state.root)?;
    }
    if state.settings.lock().await.active.is_some() {
        ensure_engine(&state).await?;
    }
    Ok(current_status(&state).await)
}

#[tauri::command]
async fn update_preferences(
    state: tauri::State<'_, Arc<AppState>>,
    theme: String,
    locale: String,
) -> Result<Status, String> {
    {
        let mut settings = state.settings.lock().await;
        if matches!(theme.as_str(), "system" | "light" | "dark") {
            settings.theme = theme;
        }
        if matches!(locale.as_str(), "zh" | "en") {
            settings.locale = locale;
        }
        settings.save(&state.root)?;
    }
    Ok(current_status(&state).await)
}

/// Contacts include archived peers (removed by them or deleted accounts) so the
/// history stays reachable; the status tells the UI whether sending is allowed.
#[tauri::command]
async fn list_contacts(state: tauri::State<'_, Arc<AppState>>) -> Result<Vec<Peer>, String> {
    let rows = with_engine(&state, |engine| {
        Box::pin(async move { engine.contacts().map_err(kite_core::EngineError::from) })
    })
    .await?;
    Ok(rows
        .into_iter()
        .map(|(device_id, status)| Peer {
            device_id,
            name: None,
            status,
        })
        .collect())
}

#[tauri::command]
async fn conversations(state: tauri::State<'_, Arc<AppState>>) -> Result<Vec<Conversation>, String> {
    chat_log(&state).await?.conversations()
}

/// Manual contact removal also drops the local history.
#[tauri::command]
async fn remove_contact(state: tauri::State<'_, Arc<AppState>>, peer: String) -> Result<(), String> {
    with_engine(&state, |engine| {
        let peer = peer.clone();
        Box::pin(async move { engine.delete_contact(&peer).await })
    })
    .await?;
    chat_log(&state).await?.remove_peer(&peer)?;
    Ok(())
}

#[tauri::command]
async fn take_share(state: tauri::State<'_, Arc<AppState>>) -> Result<Option<SharePayload>, String> {
    let pending = state.share.lock().ok().and_then(|mut slot| slot.take());
    Ok(pending.or_else(|| take_android_share(&state.root)))
}

#[tauri::command]
async fn list_devices(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Vec<kite_core::DeviceInfo>, String> {
    with_engine(&state, |engine| {
        Box::pin(async move { engine.refresh_devices().await })
    })
    .await
}

#[tauri::command]
async fn list_peers(state: tauri::State<'_, Arc<AppState>>) -> Result<Vec<Peer>, String> {
    let rows = with_engine(&state, |engine| {
        Box::pin(async move { engine.paired_peers().map_err(kite_core::EngineError::from) })
    })
    .await?;
    Ok(rows
        .into_iter()
        .map(|(device_id, status)| Peer {
            device_id,
            name: None,
            status,
        })
        .collect())
}

#[tauri::command]
async fn peer_security(
    state: tauri::State<'_, Arc<AppState>>,
    peer: String,
) -> Result<PeerSecurity, String> {
    ensure_engine(&state).await?;
    let guard = state.engine.lock().await;
    let engine = guard.as_ref().ok_or("尚未初始化")?;
    let safety_number = engine
        .engine
        .safety_number(&peer)
        .map_err(|error| error.to_string())?;
    Ok(PeerSecurity {
        device_id: peer,
        safety_number,
    })
}

#[tauri::command]
async fn unpair(state: tauri::State<'_, Arc<AppState>>, peer: String) -> Result<(), String> {
    with_engine(&state, |engine| {
        let peer = peer.clone();
        Box::pin(async move { engine.unpair(&peer).await })
    })
    .await
}

#[tauri::command]
async fn list_groups(state: tauri::State<'_, Arc<AppState>>) -> Result<Vec<GroupDto>, String> {
    with_engine(&state, |engine| {
        Box::pin(async move { engine.groups().await })
    })
    .await
}

#[tauri::command]
async fn create_group(
    state: tauri::State<'_, Arc<AppState>>,
    name: String,
    members: Vec<String>,
) -> Result<GroupDto, String> {
    with_engine(&state, |engine| {
        let name = name.clone();
        let members = members.clone();
        Box::pin(async move { engine.create_group(&name, &members).await })
    })
    .await
}

#[tauri::command]
async fn send_group_message(
    state: tauri::State<'_, Arc<AppState>>,
    group_id: String,
    text: String,
) -> Result<(), String> {
    let text = text.trim().to_owned();
    if text.is_empty() {
        return Err("消息不能为空".into());
    }
    with_engine(&state, |engine| {
        let (group_id, text) = (group_id.clone(), text.clone());
        Box::pin(async move { engine.send_group_message(&group_id, &text).await })
    })
    .await?;
    chat_log(&state)
        .await?
        .append(&ChatRecord {
            peer: group_id,
            direction: "out".into(),
            kind: "text".into(),
            text,
            file_id: None,
            file_name: None,
            size: None,
            ts: now(),
        })?;
    Ok(())
}

#[tauri::command]
async fn pair(state: tauri::State<'_, Arc<AppState>>, peer: String) -> Result<(), String> {
    with_engine(&state, |engine| {
        let peer = peer.clone();
        Box::pin(async move { engine.start_pairing(&peer).await })
    })
    .await
}

#[tauri::command]
async fn confirm_pair(state: tauri::State<'_, Arc<AppState>>, peer: String) -> Result<(), String> {
    with_engine(&state, |engine| {
        let peer = peer.clone();
        Box::pin(async move { engine.confirm_pairing(&peer).await })
    })
    .await
}

#[tauri::command]
async fn reject_pair(state: tauri::State<'_, Arc<AppState>>, peer: String) -> Result<(), String> {
    with_engine(&state, |engine| {
        let peer = peer.clone();
        Box::pin(async move { engine.reject_pairing(&peer).await })
    })
    .await
}

#[tauri::command]
async fn send_message(
    state: tauri::State<'_, Arc<AppState>>,
    peer: String,
    text: String,
) -> Result<(), String> {
    let text = text.trim().to_owned();
    if text.is_empty() {
        return Err("消息不能为空".into());
    }
    with_engine(&state, |engine| {
        let (peer, text) = (peer.clone(), text.clone());
        Box::pin(async move { engine.send_message(&peer, &text).await })
    })
    .await?;
    chat_log(&state)
        .await?
        .append(&ChatRecord {
            peer,
            direction: "out".into(),
            kind: "text".into(),
            text,
            file_id: None,
            file_name: None,
            size: None,
            ts: now(),
        })?;
    Ok(())
}

#[tauri::command]
async fn send_file(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
    peer: String,
    path: String,
) -> Result<String, String> {
    let path_buf = PathBuf::from(&path);
    let name = path_buf
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .ok_or("无法读取文件名")?;
    let bytes = std::fs::read(&path_buf).map_err(|e| format!("读取文件失败: {e}"))?;
    if bytes.is_empty() {
        return Err("不能发送空文件".into());
    }
    let size = bytes.len() as u64;
    let peer_copy = peer.clone();
    let name_copy = name.clone();
    let file_id = with_engine(&state, move |engine| {
        Box::pin(async move { engine.send_file(&peer_copy, &name_copy, &bytes).await })
    })
    .await?;
    chat_log(&state)
        .await?
        .append(&ChatRecord {
            peer,
            direction: "out".into(),
            kind: "file".into(),
            text: name.clone(),
            file_id: Some(file_id.clone()),
            file_name: Some(name),
            size: Some(size),
            ts: now(),
        })?;
    let _ = app.emit("kite://chat", ());
    Ok(file_id)
}

/// Sends a file picked by the WebView file input.
///
/// Android's document picker returns a content:// URI that the Rust side cannot
/// open directly, so the frontend reads the bytes and hands them over base64.
#[tauri::command]
async fn send_file_data(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
    peer: String,
    name: String,
    data: String,
) -> Result<String, String> {
    let bytes = B64
        .decode(data.trim())
        .map_err(|error| format!("文件数据格式错误: {error}"))?;
    if bytes.is_empty() {
        return Err("不能发送空文件".into());
    }
    let name = Path::new(&name)
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "file.bin".into());
    let size = bytes.len() as u64;
    let peer_copy = peer.clone();
    let name_copy = name.clone();
    let file_id = with_engine(&state, move |engine| {
        Box::pin(async move { engine.send_file(&peer_copy, &name_copy, &bytes).await })
    })
    .await?;
    chat_log(&state)
        .await?
        .append(&ChatRecord {
            peer,
            direction: "out".into(),
            kind: "file".into(),
            text: name.clone(),
            file_id: Some(file_id.clone()),
            file_name: Some(name),
            size: Some(size),
            ts: now(),
        })?;
    let _ = app.emit("kite://chat", ());
    Ok(file_id)
}

#[tauri::command]
async fn download_file(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
    file_id: String,
) -> Result<String, String> {
    let (name, bytes) = with_engine(&state, |engine| {
        let file_id = file_id.clone();
        Box::pin(async move { engine.download_file(&file_id).await })
    })
    .await?;
    let account = active_account(&state).await?;
    let dir = profile_dir(&state.root, &account.id).join("downloads");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut target = dir.join(&name);
    let mut counter = 1;
    while target.exists() {
        let stem = Path::new(&name)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".into());
        let ext = Path::new(&name)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        target = dir.join(format!("{stem}-{counter}{ext}"));
        counter += 1;
    }
    std::fs::write(&target, bytes).map_err(|e| e.to_string())?;
    let _ = app.emit("kite://chat", ());
    Ok(target.to_string_lossy().to_string())
}

#[tauri::command]
async fn poll(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<PollResult, String> {
    ensure_engine(&state).await?;
    let (events, mut devices_changed) = {
        let mut guard = state.engine.lock().await;
        let loaded = guard.as_mut().ok_or("尚未初始化")?;
        let events = loaded.engine.poll_once().await.map_err(|e| e.to_string())?;
        (events, loaded.engine.take_directory_changed())
    };
    let log = chat_log(&state).await?;
    let mut views = Vec::new();
    for event in events {
        let view = match event {
            InboxEvent::Message { from, text } => {
                log.append(&ChatRecord {
                    peer: from.clone(),
                    direction: "in".into(),
                    kind: "text".into(),
                    text: text.clone(),
                    file_id: None,
                    file_name: None,
                    size: None,
                    ts: now(),
                })?;
                let _ = app
                    .notification()
                    .builder()
                    .title("Kite")
                    .body(&text)
                    .show();
                ChatView {
                    peer: from,
                    direction: "in".into(),
                    kind: "text".into(),
                    text,
                    file_id: None,
                    file_name: None,
                    size: None,
                    ts: now(),
                }
            }
            InboxEvent::FileOffer {
                from,
                file_id,
                name,
                size,
            } => {
                log.append(&ChatRecord {
                    peer: from.clone(),
                    direction: "in".into(),
                    kind: "file_offer".into(),
                    text: name.clone(),
                    file_id: Some(file_id.clone()),
                    file_name: Some(name.clone()),
                    size: Some(size),
                    ts: now(),
                })?;
                let _ = app
                    .notification()
                    .builder()
                    .title("Kite")
                    .body(&name)
                    .show();
                ChatView {
                    peer: from,
                    direction: "in".into(),
                    kind: "file_offer".into(),
                    text: name.clone(),
                    file_id: Some(file_id),
                    file_name: Some(name),
                    size: Some(size),
                    ts: now(),
                }
            }
            InboxEvent::FileUnavailable { file_id } => {
                log.append(&ChatRecord {
                    peer: String::new(),
                    direction: "system".into(),
                    kind: "file_unavailable".into(),
                    text: String::new(),
                    file_id: Some(file_id.clone()),
                    file_name: None,
                    size: None,
                    ts: now(),
                })?;
                ChatView {
                    peer: String::new(),
                    direction: "system".into(),
                    kind: "file_unavailable".into(),
                    text: String::new(),
                    file_id: Some(file_id),
                    file_name: None,
                    size: None,
                    ts: now(),
                }
            }
            InboxEvent::PairRequest { from, name } => ChatView {
                peer: from,
                direction: "system".into(),
                kind: "pair_request".into(),
                text: name,
                file_id: None,
                file_name: None,
                size: None,
                ts: now(),
            },
            InboxEvent::GroupReady { group_id } => ChatView {
                peer: group_id,
                direction: "system".into(),
                kind: "group_ready".into(),
                text: String::new(),
                file_id: None,
                file_name: None,
                size: None,
                ts: now(),
            },
            InboxEvent::GroupMessage {
                group_id,
                from: _,
                text,
            } => {
                log.append(&ChatRecord {
                    peer: group_id.clone(),
                    direction: "in".into(),
                    kind: "text".into(),
                    text: text.clone(),
                    file_id: None,
                    file_name: None,
                    size: None,
                    ts: now(),
                })?;
                let _ = app
                    .notification()
                    .builder()
                    .title("Kite")
                    .body(&text)
                    .show();
                ChatView {
                    peer: group_id,
                    direction: "in".into(),
                    kind: "text".into(),
                    text,
                    file_id: None,
                    file_name: None,
                    size: None,
                    ts: now(),
                    // Sender is carried in the record text prefix below when needed.
                }
            }
            InboxEvent::PairResponse { from, accepted } => ChatView {
                peer: from,
                direction: "system".into(),
                kind: if accepted { "pair_ok" } else { "pair_rejected" }.into(),
                text: String::new(),
                file_id: None,
                file_name: None,
                size: None,
                ts: now(),
            },
            InboxEvent::PeerRemoved { peer } => {
                log.append(&ChatRecord {
                    peer: peer.clone(),
                    direction: "system".into(),
                    kind: "peer_removed".into(),
                    text: String::new(),
                    file_id: None,
                    file_name: None,
                    size: None,
                    ts: now(),
                })?;
                ChatView {
                    peer,
                    direction: "system".into(),
                    kind: "peer_removed".into(),
                    text: String::new(),
                    file_id: None,
                    file_name: None,
                    size: None,
                    ts: now(),
                }
            }
            InboxEvent::PeerDeleted { peer } => {
                log.append(&ChatRecord {
                    peer: peer.clone(),
                    direction: "system".into(),
                    kind: "peer_deleted".into(),
                    text: String::new(),
                    file_id: None,
                    file_name: None,
                    size: None,
                    ts: now(),
                })?;
                ChatView {
                    peer,
                    direction: "system".into(),
                    kind: "peer_deleted".into(),
                    text: String::new(),
                    file_id: None,
                    file_name: None,
                    size: None,
                    ts: now(),
                }
            }
            InboxEvent::DevicesChanged => {
                devices_changed = true;
                continue;
            }
        };
        views.push(view);
    }
    if !views.is_empty() {
        let _ = app.emit("kite://inbox", &views);
    }
    Ok(PollResult {
        messages: views,
        devices_changed,
    })
}

#[tauri::command]
async fn history(
    state: tauri::State<'_, Arc<AppState>>,
    peer: String,
) -> Result<Vec<ChatView>, String> {
    Ok(chat_log(&state)
        .await?
        .history(&peer, 500)?
        .into_iter()
        .map(|record| ChatView {
            peer: record.peer,
            direction: record.direction,
            kind: record.kind,
            text: record.text,
            file_id: record.file_id,
            file_name: record.file_name,
            size: record.size,
            ts: record.ts,
        })
        .collect())
}

#[tauri::command]
async fn export_identity(
    state: tauri::State<'_, Arc<AppState>>,
    passphrase: String,
) -> Result<String, String> {
    let blob = with_engine(&state, |engine| {
        let passphrase = passphrase.clone();
        Box::pin(async move {
            Ok::<_, kite_core::EngineError>(engine.export_identity(&passphrase)?)
        })
    })
    .await?;
    Ok(B64.encode(blob))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init());
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.show();
            let _ = window.set_focus();
        }
        if let Some(payload) = parse_share_args(&argv) {
            let state = app.state::<Arc<AppState>>();
            store_share(state.inner().as_ref(), payload);
            let _ = app.emit("kite://share", ());
        }
    }));
    builder
        .setup(|app| {
            let root = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| PathBuf::from("."));
            std::fs::create_dir_all(&root).ok();
            let settings = Settings::load(&root);
            let startup_share = std::env::args().collect::<Vec<String>>();
            let pending = parse_share_args(&startup_share);
            app.manage(Arc::new(AppState {
                settings: Mutex::new(settings),
                engine: Mutex::new(None),
                share: StdMutex::new(pending),
                root,
            }));

            #[cfg(desktop)]
            {
                let show = MenuItem::with_id(app, "show", "Show Kite", true, None::<&str>)?;
                let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
                let menu = Menu::with_items(app, &[&show, &quit])?;
                let builder = TrayIconBuilder::new()
                    .menu(&menu)
                    .show_menu_on_left_click(true)
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "show" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "quit" => app.exit(0),
                        _ => {}
                    });
                let builder = match app.default_window_icon() {
                    Some(icon) => builder.icon(icon.clone()),
                    None => builder,
                };
                builder.build(app)?;
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            status,
            accounts,
            register,
            switch_account,
            delete_account,
            update_preferences,
            list_devices,
            list_peers,
            list_contacts,
            conversations,
            remove_contact,
            take_share,
            peer_security,
            unpair,
            list_groups,
            create_group,
            send_group_message,
            pair,
            confirm_pair,
            reject_pair,
            send_message,
            send_file,
            send_file_data,
            download_file,
            poll,
            history,
            export_identity
        ])
        .run(tauri::generate_context!())
        .expect("error while running Kite desktop");
}
