# Kite

Kite 是一款支持自建中继的端到端加密文件传输与消息应用，客户端覆盖 Linux、Windows 和 Android。设备通过同一个中继发现、配对和通信。中继暂存密文，接收设备上线后可以同步离线消息。

[下载已发布版本](https://github.com/primercoder/file-trans/releases/latest) · [查看构建手册](docs/release-build.md) · [了解加密设计](docs/encryption.md)

## 功能

- 一对一端到端加密文本和文件传输，支持拖拽发送、分块上传、断点续传和下载校验。
- 端到端加密群聊，群消息携带发送者签名。群组目前支持文本。
- 通过设备目录或设备 ID 添加联系人，通过 60 位安全码核对对方身份。
- 独立的多服务器账户、中文和英文界面、桌面托盘与系统通知。Android 通知需要应用进程保持运行。
- Android 系统分享、Windows 资源管理器右键分享，以及 Linux 的 `--share`、Dolphin 和 Nautilus 集成。
- 联系人移除本机或注销后，原有聊天历史仍可查看。

## 快速开始

### 1. 启动中继

准备 Docker 和 Docker Compose，然后在终端运行以下命令。

```bash
git clone https://github.com/primercoder/file-trans.git
cd file-trans
docker compose -f docker/docker-compose.yml up -d --build
curl --insecure https://localhost:8443/healthz
docker compose -f docker/docker-compose.yml exec kite-server cat /data/fingerprint.txt
```

健康检查返回包含 `version` 和 `uptime_s` 的 JSON。上面的 `--insecure` 只用于测试本机自签名服务的健康端点。默认数据目录为 `docker/data/`，保存 SQLite 数据库、加密文件块、自签证书和指纹。保留此目录即可在重启后继续使用原指纹。

也可以通过 Rust 在本机启动中继。需要 stable 工具链、C/C++ 编译器、CMake 和 pkg-config。

```bash
mkdir -p data
KITE_DB_PATH=./data/kite.db cargo run --locked --release -p kite-server
```

此时证书指纹位于 `data/fingerprint.txt`。使用预编译的 `kite-server` 时，可以用它替换命令中的 `cargo run --locked --release -p kite-server`。

### 2. 连接客户端

1. 从 [GitHub Releases](https://github.com/primercoder/file-trans/releases/latest) 下载安装包，或按 [构建手册](docs/release-build.md) 从源码构建。
2. 在两台设备上打开 Kite，输入相同的中继 HTTPS 地址和各自的设备名。手机或其他电脑需要填写中继所在机器的可达地址，例如 `https://192.168.1.20:8443`。
3. 使用自签证书时，通过可信渠道获取服务端的 SHA-256 指纹，在客户端「高级选项」中填入。使用公共 CA 签发的证书时，填写与证书匹配的域名即可。
4. 通过设备 ID 添加联系人，在另一台设备上接受请求，双方通过另外的渠道核对安全码，然后开始发送消息或文件。

## 服务端配置

| 环境变量 | 默认值 | 用途 |
| --- | --- | --- |
| `KITE_BIND` | `0.0.0.0:8443` | HTTPS API 监听地址 |
| `KITE_HEALTH_BIND` | `0.0.0.0:8444` | 明文 HTTP 健康探针地址 |
| `KITE_DB_PATH` | `./kite.db` | SQLite 路径。证书、指纹和文件块位于同一数据目录 |
| `KITE_MAX_STORAGE_BYTES` | `10737418240`（10 GiB） | 文件密文配额，包括进行中的上传 |
| `KITE_TLS_CERT` | 未设置 | 外部 PEM 证书路径，须与 `KITE_TLS_KEY` 一起设置 |
| `KITE_TLS_KEY` | 未设置 | 外部 PEM 私钥路径，须与 `KITE_TLS_CERT` 一起设置 |

默认生成并持久化自签证书。Compose 默认发布 HTTPS 端口 `8443`，可用 `KITE_PUBLISH_PORT` 修改宿主机端口、用 `KITE_DATA_DIR` 指定挂载路径。明文健康探针留在容器内。停止服务可运行 `docker compose -f docker/docker-compose.yml down`。

### 配额、淘汰与统计

`KITE_MAX_STORAGE_BYTES` 限制所有存活文件的**声明密文大小之和**，包括未完成上传；单个文件超过总配额会返回 413。空间不足时按创建时间先淘汰最早已接收文件，再淘汰最早未接收文件。后者删除前会为每位收件人写入 `file_evicted`，客户端轮询得到 `FileUnavailable`；该通知仅说明文件不可用，不携带文件密钥，也不应解释为发送者操作。

`/stats.storage_used` 同样按声明大小计算，是配额预留量而非目录实时磁盘占用。淘汰元数据与提示原子提交；块目录删除若因崩溃或 I/O 错误中断，会保留 `pending_cleanup` 债务，服务端启动时尽力重试，清理失败不阻止启动。

## 安全模型与已知限制

`kite-core` 以 Ed25519 标识设备，以 X3DH 建立配对会话，并使用 Double Ratchet 和 ChaCha20-Poly1305 保护消息。文件在客户端分块加密，每个文件的密钥和文件名经配对会话传递。中继仍可以看到设备名、路由、时间和密文大小等元数据，也能影响投递。首次配对时可通过可信渠道交换设备 ID，并在会话建立后核对安全码。

客户端 SQLite 保存身份私钥和会话状态。Unix 上通过目录 `0700` 和数据库 `0600` 限制访问。系统密钥存储集成、完整的密钥材料清零、群组文件传输和群成员变更后的密钥轮换仍有待实现。详见 [加密设计与威胁模型](docs/encryption.md)。

## 开发与测试

| 路径 | 内容 |
| --- | --- |
| `crates/kite-core` | 设备身份、密码协议、客户端存储、消息和文件传输引擎 |
| `crates/kite-server` | Axum HTTPS API、SQLite、信箱、设备目录和密文文件存储 |
| `apps/desktop` | Tauri 2、Vue 3 客户端和 Android 工程 |
| `docker` | 中继镜像和 Docker Compose 配置 |

从仓库根目录构建并运行 Rust 测试。跨 crate 集成测试通过环境变量定位中继二进制。

```bash
cargo build --locked --workspace --bins
env "CARGO_BIN_EXE_kite-server=$PWD/target/debug/kite-server" cargo test --locked --workspace
```

Linux 客户端依赖 WebKitGTK 4.1 等系统库。安装 [Tauri 构建依赖](https://v2.tauri.app/start/prerequisites/) 和 Node.js 后，可启动开发客户端并运行前端检查。

```bash
cd apps/desktop
npm ci
npm test
npm run build
npm run tauri dev
```

在 Linux 上运行 `./scripts/smoke_three_clients.sh` 可验证 Docker 中继、两个客户端的配对、消息和加密文件传输。各次运行使用独立的数据目录和端口。配置了 `vmwin` SSH 主机的环境还会检查 Windows 到中继的连通性。Linux 与 Windows 的端到端测试详见 [跨机验证](docs/windows-dev.md)，平台构建步骤见 [发布手册](docs/release-build.md)。

## Rust SDK

### 文件传输

配对完成后，`Engine` 直接收发内存中的文件内容；应用负责文件 I/O 与 UI：

```rust
// 发送方：返回不透明 file_id；中断后再次发送相同内容会复用本地 pending_uploads。
let file_id = engine.send_file(peer_device_id, "report.pdf", &bytes).await?;

// 已持有 upload_id 时，仅补传服务端尚未收到的块，再完成上传并发送文件通知。
engine.resume_upload(&file_id, &upload_id, &bytes).await?;

// 接收方：poll_once 将文件消息转换为 FileOffer，FK 仅保存在本地，不暴露在事件中。
for event in engine.poll_once().await? {
    match event {
        InboxEvent::FileOffer { file_id, name, size } => {
            let (name, plaintext) = engine.download_file(&file_id).await?;
            // 校验并解密成功后才会 ACK，服务端据此标记该收件人已接收。
        }
        InboxEvent::FileUnavailable { file_id } => {
            // 文件已被配额淘汰；这是服务端 advisory 通知，并非发送者的加密消息。
        }
        _ => {}
    }
}
```

`send_file` / `resume_upload` 要求原始 `bytes` 与持久化上传记录匹配；`resume_upload` 遇到未知上传会报错，不会静默创建另一份文件。未完成上传不可下载。

### 身份导出与导入

```rust
let blob = engine.export_identity("一个足够长且唯一的口令")?;
let migrated = Engine::import_identity(
    "fresh.db",
    "https://server:8443",
    server_fingerprint,
    "一个足够长且唯一的口令",
    &blob,
)?;
```

V1 档案为 `KITE-BACKUP-V1 || 16 字节盐 || 12 字节 nonce || ChaCha20-Poly1305 密文`，以 Argon2id 从口令派生 KEK。应使用高熵、唯一口令并妥善保管档案；口令错误或档案被篡改会拒绝导入。

导入只接受**全新 Store**（已有身份或会话会被拒绝），不会自动联网或重新注册。待接收的文件 offer（未下载文件）和进行中的上传**不会迁移**，应先下载待接收文件再迁移。备份采用**单活动设备**语义：迁移后不得让新旧设备同时与相同 peer 通信，否则 Double Ratchet 会分叉；应停用并安全处置旧设备 Store。
