# Kite

Kite 是一个使用 Rust 构建的跨平台端到端加密（E2EE）文件与消息传输应用。

## 架构

```text
 Linux 客户端          Windows 客户端          Android 客户端（M4）
      │                      │                        │
      └──────────────────────┼────────────────────────┘
                             │ HTTPS / TLS 1.3（REST）
                    ┌────────▼────────┐
                    │   Kite Server   │
                    │  Rust / axum    │
                    │     SQLite      │
                    └─────────────────┘
                             │
                 服务端仅保存、转发密文信封

 E2EE：X3DH（3DH / 4DH）建立共享密钥，Double Ratchet 加密消息。
 开发环境使用自签名证书；kite-core 客户端通过证书 SHA-256 指纹锁定服务端。
```

M2 已提供平台无关的 `kite-core` 客户端引擎和 `kite-server` 服务端，并支持 E2EE 文件传输；Linux 与 Windows 均通过全量测试及跨机文件冒烟，Android 客户端尚未实现。

## 快速启动

### 构建与测试

需要 Rust 1.99（工具链版本见 `rust-toolchain.toml`）。

```bash
cargo build --workspace

# 集成测试通过外部环境变量定位跨 crate 的 kite-server 可执行文件。
# 含连字符的变量名须用 env 设置，不能直接写成 shell 的 VAR=value 前缀。
env "CARGO_BIN_EXE_kite-server=$PWD/target/debug/kite-server" cargo test --workspace
cargo clippy --workspace -- -D warnings
```

### Docker Compose

需要 Docker 及 Compose 插件：

```bash
docker compose -f docker/docker-compose.yml up -d --build
curl -k https://localhost:8443/healthz
```

健康检查应返回包含 `version` 和 `uptime_s` 的 JSON。自签证书的 SHA-256 指纹保存在 `docker/data/fingerprint.txt`，SQLite 数据默认保存在 `docker/data/kite.db`。

```bash
docker compose -f docker/docker-compose.yml down
```

默认 Compose 仅发布 HTTPS 端口 `8443`；服务端另在容器内默认地址 `0.0.0.0:8444` 提供仅含 `/healthz` 的明文 HTTP 探针。如需从宿主机使用该探针，请另行发布 `8444` 端口。

### 三端冒烟

在仓库根目录运行：

```bash
./scripts/smoke_three_clients.sh
```

脚本会构建并启动 Compose 服务，执行两个 Linux 示例客户端的注册、发现、异步配对、加密消息收发与解密断言。若可通过 SSH 主机别名 `vmwin` 访问 Windows 虚拟机，还会验证 Windows 到 HTTPS `/healthz` 的连通性；虚拟机不可达时明确输出 `SKIP`，Linux 全链路结果不受影响。脚本退出时停止 Compose，但保留 `docker/data` 以便检查。

## 功能范围（M1 + M2 已完成）

### 已支持

- **设备身份**：Ed25519 身份；`device_id` 为身份公钥 SHA-256 前 16 字节的小写 hex；默认设备名为 `{hostname}-{os}-{公钥前4字节hex}`。
- **端到端加密**：X3DH 4DH，以及 OPK 池耗尽后的 3DH 回退；可序列化的 Double Ratchet 会话，支持乱序消息与重启恢复。已消费的 OPK 不会静默降级为 3DH。
- **客户端能力**：仅 TLS 1.3；默认使用系统/WebPKI 根证书，自签名部署可在“高级选项”里填可选证书指纹。注册、设备发现（服务器目录 epoch 随每次同步下发，新设备注册后所有客户端自动刷新，也可手动刷新）、通过加密信封异步配对、E2EE 文本与文件收发、离线消息补投；SQLite 原子持久化身份、配对状态、棘轮会话、信箱处置和同步游标。原始硬件标识在客户端经随机盐 Argon2id 哈希为 PHC 字符串，服务端只保存该字符串。重复/恶意信箱项记录失败并跳过，不会阻塞后续消息。
- **E2EE 文件传输（M2）**：随机 FK + ChaCha20-Poly1305 分块加密，HKDF 派生逐块 nonce；文件名与 FK 只存在于加密消息信封。客户端支持上传、授权下载、内容校验与确认接收；`pending_uploads` 持久化上传意图，重试复用 FK 并确定性重建密文，支持断点续传。
- **存储配额与淘汰（M2）**：文件声明大小（含未完成上传）预留配额；空间不足时先淘汰最早已接收文件，再淘汰最早未接收文件并发送 `file_evicted` 提示。`/stats.storage_used` 返回实时预留字节数。
- **身份导出/导入（M2）**：口令加密的 `KITE-BACKUP-V1` 档案可迁移身份、预密钥及棘轮会话，支持换机后续聊。
- **服务端 API**：REST over TLS 1.3，支持 rcgen 自签证书或外部 PEM；Ed25519 注册签名（`register||device_id||name`）、挑战应答认证、设备目录、预密钥包与一次性 OPK。任一成功的 Bearer 认证刷新在线活动，90 秒无活动后目录显示离线。
- **信箱与配对中继**：每设备单调递增序号、高水位 `since` 游标同步、ACK 删除、最长 25 秒长轮询、`pair_req` / `pair_resp` 离线中继。配对信封采用 ±120 秒时间窗和持久化 EK 重放缓存；已有会话的重复配对请求不会替换现有会话。
- **桌面与移动客户端**：统一的通讯录列表（联系人与群组同列，显示最后一条消息与时间、未读圆点）、联系人安全码核验、删除联系人并通知对方、注销账户（服务端清除数据并通知所有设备）、多服务器账户（每个服务器独立身份、通讯录、消息与文件，可随时切换）、中文/英文与浅色/深色/跟随系统、拖拽发送文件与下载落盘。
- **联系人生命周期**：对方移除本机或注销账户时保留只读会话与历史记录（带「对方已移除 / 对方已注销」标识，不能再发送）；只有自己手动删除联系人才会清除本地历史与连接。
- **系统分享**：Android 注册为 ACTION_SEND/SEND_MULTIPLE 目标，可从文件管理器等应用分享文件或文字并选择联系人或群组；Windows 安装包写入资源管理器右键「Send with Kite」并支持单实例转发；Linux 提供 `--share` 参数、KDE Dolphin 服务菜单与 Nautilus 脚本。
- **服务器不可信假设**：配对时客户端校验预密钥包的身份公钥必须等于所请求的设备 ID（`SHA-256(ik_pub)` 前 16 字节）；即使服务器篡改目录或数据库，也无法把对端替换成自己的密钥。已配对会话可显示 60 位安全码供带外核验，也可按 32 位设备 ID 直接配对，不依赖服务器目录。服务端只接触密文、路由与必要元数据。
- **群组发言认证**：群消息由发送者 Ed25519 签名，成员身份表（roster）随群密钥经各自的加密会话分发；即使成员与服务器合谋，也不能把一条消息冒充为其他成员。
- **通知**：桌面端（Windows/Linux）在窗口隐藏到托盘时仍通过系统通知提示新消息与文件；Android 在应用进程存活时发送系统通知（进程被系统杀死后的推送需要 FCM 或前台服务，暂未实现）。
- **运维**：HTTPS `/healthz`、独立明文 `/healthz` 探针、带认证的 `/stats`、SQLite 持久化、Docker 多阶段构建与 Compose 部署；自签名证书在数据目录持久化（`tls-cert.pem` / `tls-key.pem`），重启后指纹保持不变。

### 尚未支持

- 桌面 UI 和完整 Windows 客户端（M3）
- Android 客户端（M4）
- 群组（M5）
- 密钥材料全面 zeroization

`KITE_MAX_STORAGE_BYTES` 从 M2 起强制执行文件存储配额；未 ACK 的普通信箱消息不占文件配额。

> **本地密钥存储限制**：客户端 SQLite 存放身份私钥和棘轮密钥；目前仅在 Unix 上强制目录 `0700`、数据库文件 `0600`（其他平台为 best-effort no-op）。这**尚未满足**设计要求的平台安全存储；Keyring / DPAPI / Android Keystore 集成推迟到 M3+，在此之前数据库文件失窃仍会暴露密钥材料。

## 文件传输用法

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

## 配额、淘汰与统计

`KITE_MAX_STORAGE_BYTES` 限制所有存活文件的**声明密文大小之和**，包括未完成上传；单个文件超过总配额会返回 413。空间不足时按创建时间先淘汰最早已接收文件，再淘汰最早未接收文件。后者删除前会为每位收件人写入 `file_evicted`，客户端轮询得到 `FileUnavailable`；该通知仅说明文件不可用，不携带文件密钥，也不应解释为发送者操作。

`/stats.storage_used` 同样按声明大小计算，是配额预留量而非目录实时磁盘占用。淘汰元数据与提示原子提交；块目录删除若因崩溃或 I/O 错误中断，会保留 `pending_cleanup` 债务，服务端启动时尽力重试，清理失败不阻止启动。

## 身份导出/导入

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

## Windows 开发与跨机验证

详见 [`docs/windows-dev.md`](docs/windows-dev.md)：Windows 11 VM 的源码位于 `C:\Users\win\Desktop\kite`，文档包含构建/测试命令、Cargo PATH、CRLF、Defender 延迟、防火墙和代理等注意事项。从 Linux 执行 `./scripts/deploy_vmwin.sh` 可部署源码、运行远端全量测试并保留日志；配置好免交互 `ssh vmwin` 后，执行 `./scripts/smoke_cross_machine.sh [测试文件]` 可验证 Linux↔Windows 注册、配对、消息及文件互传（省略参数时生成 1 MiB 随机测试文件）。

## 服务端管理

M2 新增 Bearer 鉴权文件 API：

- `POST /api/v1/files/init`
- `PUT /api/v1/files/{upload_id}/chunk/{index}`、`GET /api/v1/files/{file_id}/chunk/{index}`
- `POST /api/v1/files/{upload_id}/complete`
- `GET /api/v1/files/{file_id}/meta`、`GET /api/v1/files/{upload_id}/status`
- `POST /api/v1/files/{file_id}/ack-download`

上传块上限为 256 KiB；下载按文件收件人授权，上传状态仅 owner 可查。配额淘汰遗留的 `pending_cleanup` 债务会在启动时协调清理，无需管理员手工删除元数据。

## 服务端配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `KITE_BIND` | `0.0.0.0:8443` | HTTPS REST API 监听地址 |
| `KITE_DB_PATH` | `./kite.db` | SQLite 数据库路径；证书指纹写到同目录的 `fingerprint.txt` |
| `KITE_MAX_STORAGE_BYTES` | `10737418240`（10 GiB） | 文件声明大小总配额；包含未完成上传，不足时执行淘汰 |
| `KITE_TLS_CERT` | 未设置 | 外部 PEM 证书路径；必须与 `KITE_TLS_KEY` 同时设置 |
| `KITE_TLS_KEY` | 未设置 | 外部 PEM 私钥路径；必须与 `KITE_TLS_CERT` 同时设置 |
| `KITE_HEALTH_BIND` | `0.0.0.0:8444` | 明文 HTTP `/healthz` 探针监听地址 |

未同时设置证书和私钥路径时，服务端生成 rcgen 自签证书。**默认自签证书每次重启都会改变 SHA-256 指纹**，指纹锁定的客户端需随之更新；稳定部署应设置 `KITE_TLS_CERT` / `KITE_TLS_KEY` 并妥善轮换。无效配置会在启动时直接报错。

## 设计文档

完整设计见 `reference/tech-design.md`（§2 安全设计、§3 架构、§4 数据模型、§6 传输协议）。`reference/` 为本地参考资料且已被 Git 排除；核心约定为设备持有 Ed25519 身份，X3DH 与 Double Ratchet 保护消息，服务端只处理认证后的 REST 请求和密文信箱数据。

## 桌面客户端（M3）

`apps/desktop` 是基于 Tauri 2 + Vue 3 的桌面客户端（Linux / Windows），复用 `kite-core`
的协议与加密能力：

```bash
cd apps/desktop
npm install
npm run tauri dev      # 开发模式（需系统 WebView：Linux 为 webkit2gtk-4.1）
npm run tauri build    # 生产打包
```

功能：设备注册（服务器地址 + 设备名，自签名证书可选填指纹）、统一通讯录、配对接受/拒绝、
消息与文件传输、拖拽发送文件、安全码核验、删除联系人与注销账户、多服务器账户切换、
中文/英文界面、系统托盘常驻与系统通知。

首次启动填写服务器地址与 `fingerprint.txt` 中的 SHA-256 指纹即可注册；界面按
`icon.png` 的蓝白配色设计。Linux 无图形会话的 CI 环境可用
`xvfb-run` + `dbus-run-session` 做启动冒烟。

