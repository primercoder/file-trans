mod chatlog;
mod settings;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chatlog::{ChatLog, ChatRecord};
use kite_core::{Engine, GroupDto, InboxEvent};
use serde::Serialize;
use settings::Settings;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(desktop)]
use tauri::menu::{Menu, MenuItem};
#[cfg(desktop)]
use tauri::tray::TrayIconBuilder;
use tauri::{Emitter, Manager, WindowEvent};
use tauri_plugin_notification::NotificationExt;
use tokio::sync::Mutex;

struct AppState {
    settings: Mutex<Settings>,
    engine: Mutex<Option<Engine>>,
    data_dir: PathBuf,
    chat: ChatLog,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    configured: bool,
    registered: bool,
    device_id: Option<String>,
    name: Option<String>,
    server_url: Option<String>,
    fingerprint: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Peer {
    device_id: String,
    name: Option<String>,
    status: String,
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

async fn ensure_engine(state: &AppState) -> Result<(), String> {
    let mut guard = state.engine.lock().await;
    if guard.is_some() {
        return Ok(());
    }
    let settings = state.settings.lock().await.clone();
    let (Some(url), Some(fingerprint)) = (settings.server_url, settings.fingerprint) else {
        return Err("尚未配置服务器".into());
    };
    let engine = Engine::open(state.data_dir.join("kite.db"), &url, &fingerprint)
        .map_err(|e| {
            eprintln!("KITE_ENGINE_ERROR: {e}");
            e.to_string()
        })?;
    *guard = Some(engine);
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
    let engine = guard.as_mut().ok_or("尚未初始化")?;
    f(engine).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn status(state: tauri::State<'_, Arc<AppState>>) -> Result<Status, String> {
    ensure_engine(&state).await.ok();
    let settings = state.settings.lock().await.clone();
    let guard = state.engine.lock().await;
    let (device_id, name, registered, registered_id) = match guard.as_ref() {
        Some(engine) => (
            Some(engine.device_id().to_owned()),
            settings.device_name.clone(),
            engine.is_registered(),
            Some(engine.device_id().to_owned()),
        ),
        None => (None, settings.device_name.clone(), false, None),
    };
    let device_id = if registered { device_id } else { None };
    let _ = registered_id;
    eprintln!(
        "KITE_STATUS dir={:?} configured={} registered={} device={:?}",
        state.data_dir,
        settings.server_url.is_some() && settings.fingerprint.is_some(),
        registered,
        device_id
    );
    Ok(Status {
        configured: settings.server_url.is_some() && settings.fingerprint.is_some(),
        registered,
        device_id,
        name,
        server_url: settings.server_url,
        fingerprint: settings.fingerprint,
    })
}

#[tauri::command]
async fn register(
    state: tauri::State<'_, Arc<AppState>>,
    server_url: String,
    fingerprint: String,
    name: String,
) -> Result<Status, String> {
    let server_url = server_url.trim().trim_end_matches('/').to_owned();
    let fingerprint = fingerprint.trim().to_owned();
    if !(server_url.starts_with("https://") || server_url.starts_with("http://")) {
        return Err("服务器地址必须以 https:// 或 http:// 开头".into());
    }
    if fingerprint.len() != 64 || !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("证书指纹必须是 64 位十六进制字符".into());
    }
    {
        let mut settings = state.settings.lock().await;
        settings.server_url = Some(server_url.clone());
        settings.fingerprint = Some(fingerprint.clone());
        settings.device_name = Some(name.clone());
        settings.save(&state.data_dir)?;
    }
    {
        let mut guard = state.engine.lock().await;
        *guard = None;
    }
    ensure_engine(&state).await?;
    let mut guard = state.engine.lock().await;
    let engine = guard.as_mut().ok_or("尚未初始化")?;
    engine
        .register(&name, &raw_hw_id())
        .await
        .map_err(|e| e.to_string())?;
    Ok(Status {
        configured: true,
        registered: true,
        device_id: Some(engine.device_id().to_owned()),
        name: Some(name),
        server_url: Some(server_url),
        fingerprint: Some(fingerprint),
    })
}

#[tauri::command]
async fn list_devices(state: tauri::State<'_, Arc<AppState>>) -> Result<Vec<kite_core::DeviceInfo>, String> {
    with_engine(&state, |engine| Box::pin(async move { engine.refresh_devices().await })).await
}

#[tauri::command]
async fn list_peers(state: tauri::State<'_, Arc<AppState>>) -> Result<Vec<Peer>, String> {
    let rows = with_engine(&state, |engine| {
        Box::pin(async move {
            engine
                .paired_peers()
                .map_err(kite_core::EngineError::from)
        })
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
async fn list_groups(state: tauri::State<'_, Arc<AppState>>) -> Result<Vec<GroupDto>, String> {
    with_engine(&state, |engine| Box::pin(async move { engine.groups().await })).await
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
    state.chat.append(&ChatRecord {
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
    state.chat.append(&ChatRecord {
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
    state.chat.append(&ChatRecord {
        peer,
        direction: "out".into(),
        kind: "file".into(),
        text: name.clone(),
        file_id: Some(file_id.clone()),
        file_name: Some(name.clone()),
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
    let dir = state.data_dir.join("downloads");
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
) -> Result<Vec<ChatView>, String> {
    let events = with_engine(&state, |engine| Box::pin(async move { engine.poll_once().await })).await?;
    let mut views = Vec::new();
    for event in events {
        let view = match event {
            InboxEvent::Message { from, text } => {
                state.chat.append(&ChatRecord {
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
                    .title("Kite 新消息")
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
            InboxEvent::FileOffer { from, file_id, name, size } => {
                state.chat.append(&ChatRecord {
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
                    .title("Kite 收到文件")
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
                state.chat.append(&ChatRecord {
                    peer: String::new(),
                    direction: "system".into(),
                    kind: "file_unavailable".into(),
                    text: "服务器空间不足，文件已被清理".into(),
                    file_id: Some(file_id.clone()),
                    file_name: None,
                    size: None,
                    ts: now(),
                })?;
                let _ = app
                    .notification()
                    .builder()
                    .title("Kite 文件已清理")
                    .body("服务器空间不足，文件已被清理")
                    .show();
                ChatView {
                    peer: String::new(),
                    direction: "system".into(),
                    kind: "file_unavailable".into(),
                    text: "服务器空间不足，文件已被清理".into(),
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
                text: format!("{name} 请求配对"),
                file_id: None,
                file_name: None,
                size: None,
                ts: now(),
            },
            InboxEvent::GroupReady { group_id } => {
                let _ = app
                    .notification()
                    .builder()
                    .title("Kite 群组")
                    .body("已收到群组密钥")
                    .show();
                ChatView {
                    peer: group_id.clone(),
                    direction: "system".into(),
                    kind: "group_ready".into(),
                    text: "已加入群组".into(),
                    file_id: None,
                    file_name: None,
                    size: None,
                    ts: now(),
                }
            }
            InboxEvent::GroupMessage { group_id, from, text } => {
                state.chat.append(&ChatRecord {
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
                    .title("Kite 群消息")
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
                }
            }
            InboxEvent::PairResponse { from, accepted } => ChatView {
                peer: from,
                direction: "system".into(),
                kind: "pair_response".into(),
                text: if accepted { "配对已接受".into() } else { "配对被拒绝".into() },
                file_id: None,
                file_name: None,
                size: None,
                ts: now(),
            },
        };
        views.push(view);
    }
    if !views.is_empty() {
        let _ = app.emit("kite://inbox", &views);
    }
    Ok(views)
}

#[tauri::command]
async fn history(
    state: tauri::State<'_, Arc<AppState>>,
    peer: String,
) -> Result<Vec<ChatView>, String> {
    Ok(state
        .chat
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

#[tauri::command]
async fn import_identity(
    state: tauri::State<'_, Arc<AppState>>,
    passphrase: String,
    blob: String,
) -> Result<Status, String> {
    let raw = B64.decode(blob.trim()).map_err(|e| format!("备份数据格式错误: {e}"))?;
    let settings = state.settings.lock().await.clone();
    let (Some(url), Some(fingerprint)) = (settings.server_url.clone(), settings.fingerprint.clone())
    else {
        return Err("请先配置服务器".into());
    };
    let engine = Engine::import_identity(
        state.data_dir.join("kite.db"),
        &url,
        &fingerprint,
        &passphrase,
        &raw,
    )
    .map_err(|e| e.to_string())?;
    let device_id = engine.device_id().to_owned();
    {
        let mut guard = state.engine.lock().await;
        *guard = Some(engine);
    }
    Ok(Status {
        configured: true,
        registered: true,
        device_id: Some(device_id),
        name: settings.device_name,
        server_url: Some(url),
        fingerprint: Some(fingerprint),
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| PathBuf::from("."));
            std::fs::create_dir_all(&data_dir).ok();
            let settings = Settings::load(&data_dir);
            let chat = ChatLog::new(&data_dir);
            app.manage(Arc::new(AppState {
                settings: Mutex::new(settings),
                engine: Mutex::new(None),
                data_dir,
                chat,
            }));

            #[cfg(desktop)]
            {
                let show = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
                let quit = MenuItem::with_id(app, "quit", "退出 Kite", true, None::<&str>)?;
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
            register,
            list_devices,
            list_peers,
            list_groups,
            create_group,
            send_group_message,
            pair,
            confirm_pair,
            reject_pair,
            send_message,
            send_file,
            download_file,
            poll,
            history,
            export_identity,
            import_identity
        ])
        .run(tauri::generate_context!())
        .expect("error while running Kite desktop");
}
