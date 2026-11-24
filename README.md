# Kite

Kite 是一个使用 Rust 构建的跨平台端到端加密（E2EE）文件与消息传输应用。

## 架构

```text
 Linux 客户端          Windows 客户端          Android 客户端（M4）
      │                      │                        │
      └──────────────────────┼────────────────────────┘
                             │ HTTPS / TLS（REST）
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

M1 已提供平台无关的 `kite-core` 客户端引擎和 `kite-server` 服务端；Linux 冒烟测试使用示例客户端，Windows 当前验证 HTTPS 连通性，Android 客户端尚未实现。

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

## M1 功能范围

### 已支持

- **设备身份**：Ed25519 身份；`device_id` 为身份公钥 SHA-256 前 16 字节的小写 hex；默认设备名为 `{hostname}-{os}-{公钥前4字节hex}`。
- **端到端加密**：X3DH 4DH，以及 OPK 池耗尽后的 3DH 回退；可序列化的 Double Ratchet 会话，支持乱序消息与重启恢复。
- **客户端能力**：TLS 证书指纹锁定；注册、设备发现、通过加密信封异步配对、E2EE 文本消息收发、离线消息补投；SQLite 持久化身份、配对状态、棘轮会话和每设备同步游标。
- **服务端 API**：REST over TLS，支持 rcgen 自签证书或外部 PEM；Ed25519 注册签名（`register||device_id||name`）、挑战应答认证、设备目录、预密钥包与一次性 OPK。
- **信箱与配对中继**：每设备单调递增序号、高水位 `since` 游标同步、ACK 删除、最长 25 秒长轮询、`pair_req` / `pair_resp` 离线中继。
- **运维**：HTTPS `/healthz`、独立明文 `/healthz` 探针、带认证的 `/stats`、SQLite 持久化、Docker 多阶段构建与 Compose 部署。

### 尚未支持

- 文件传输、存储配额强制执行（M2）
- 桌面 UI 和完整 Windows 客户端（M3）
- Android 客户端（M4）
- 群组（M5）
- 身份导出/导入工作流、密钥材料全面 zeroization

`KITE_MAX_STORAGE_BYTES` 当前仅解析并在启动时打印，M1 不据此淘汰或拒绝信箱数据。

## 服务端配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `KITE_BIND` | `0.0.0.0:8443` | HTTPS REST API 监听地址 |
| `KITE_DB_PATH` | `./kite.db` | SQLite 数据库路径；证书指纹写到同目录的 `fingerprint.txt` |
| `KITE_MAX_STORAGE_BYTES` | `10737418240`（10 GiB） | 存储上限配置；M1 仅打印，不执行配额 |
| `KITE_TLS_CERT` | 未设置 | 外部 PEM 证书路径；必须与 `KITE_TLS_KEY` 同时设置 |
| `KITE_TLS_KEY` | 未设置 | 外部 PEM 私钥路径；必须与 `KITE_TLS_CERT` 同时设置 |
| `KITE_HEALTH_BIND` | `0.0.0.0:8444` | 明文 HTTP `/healthz` 探针监听地址 |

未同时设置证书和私钥路径时，服务端生成 rcgen 自签证书。无效配置会在启动时直接报错。

## 设计文档

完整设计见 `reference/tech-design.md`（§2 安全设计、§3 架构、§4 数据模型、§6 传输协议）。`reference/` 为本地参考资料且已被 Git 排除；核心约定为设备持有 Ed25519 身份，X3DH 与 Double Ratchet 保护消息，服务端只处理认证后的 REST 请求和密文信箱数据。
