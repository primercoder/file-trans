# Release 构建手册

从待发布的 Git 标签检出源码。下文以 `v0.1.0` 为例，各平台的发布附件可归集到仓库根目录 `dist/`。

## 前置条件

- Rust stable，由仓库的工具链配置选择。交叉编译时运行 `rustup target add aarch64-unknown-linux-gnu aarch64-pc-windows-msvc`
- 客户端需要 Node.js 和对应平台的 [Tauri 构建依赖](https://v2.tauri.app/start/prerequisites/)。
- Linux 交叉工具：`gcc-aarch64-linux-gnu`、`clang`、`lld`、`cargo-xwin`
- Android：Android SDK/NDK + 自签 keystore + `apps/desktop/src-tauri/gen/android/keystore.properties`
- Windows 打包：`nsis`（Linux 版 makensis 即可）
- Linux 打包：Tauri 自带 AppImage 打包（需要网络；也可用 appimagetool 手工打包）

## 图标

所有平台共用仓库根目录的 `icon.png`：

```bash
cd apps/desktop
npx tauri icon ../../icon.png   # 桌面、Android、iOS 图标一次性生成
```

Android 自适应图标的背景色在 `gen/android/.../values/ic_launcher_background.xml`，应与 `icon.png` 边缘颜色一致。

## 1. 服务端

```bash
# Linux x64
cargo build --locked --release -p kite-server
strip target/release/kite-server

# Linux arm64
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
cargo build --locked --release -p kite-server --target aarch64-unknown-linux-gnu
aarch64-linux-gnu-strip target/aarch64-unknown-linux-gnu/release/kite-server

# Windows x64（在 Windows 构建机 / VM 内）
cargo build --locked --release -p kite-server

# Windows arm64（x64 Linux 上交叉编译）
cargo xwin build --locked --release -p kite-server --target aarch64-pc-windows-msvc
```

打包：每个平台一个压缩包，内含 `kite-server`(`.exe`) 与 `README.txt`。

### glibc 兼容性

开发机的 glibc 往往比部署机新。发布给旧系统（如 Ubuntu 22.04 / glibc 2.35）的服务端必须在旧环境中构建：

```bash
./scripts/build_server_glibc.sh    # Docker + ubuntu:22.04，产出 target/glibc-22.04/
objdump -T target/glibc-22.04/kite-server-linux-x64 | grep -oE 'GLIBC_[0-9.]+' | sort -Vu | tail -1
```

脚本同时交叉编译 `arm64`，并打印两个产物所需的最高 GLIBC 版本。

## 2. Linux 桌面端

```bash
cd apps/desktop
npm ci
npm run tauri build -- --bundles deb -- --locked
```

构建产物在 `apps/desktop/src-tauri/target/release/`。可使用 `--bundles deb,rpm,appimage` 生成多种格式。归集时可用以下文件名。

- `dist/linux/kite-desktop-linux-x64`（裸二进制）
- `dist/linux/kite-0.1.0-amd64.deb`
- `dist/linux/kite-0.1.0-x86_64.AppImage`
- `dist/linux/kite-0.1.0-linux-x64-portable.tar.gz`（`kite-desktop` + `README.txt`）

在仓库根目录运行以下命令，将 KDE 服务菜单和 Nautilus 脚本加入 `.deb`。

```bash
./scripts/add_desktop_integration.sh apps/desktop/src-tauri/target/release/bundle/deb/Kite_0.1.0_amd64.deb
```

若 Tauri 打包 AppImage 时无法下载 AppRun，可手工打包：

```bash
# AppDir 里放 AppRun、kite.desktop、.DirIcon、usr/bin/kite-desktop、usr/share/icons/...
ARCH=x86_64 appimagetool --no-appstream Kite.AppDir kite-0.1.0-x86_64.AppImage
```

## 3. Windows 桌面端

在 Windows 构建机内：

```bat
cd apps\desktop
npm ci
npm run tauri build -- --no-bundle -- --locked
```

取回 `kite-desktop.exe` 后：

- 免安装包：`zip` 内含 `kite-desktop.exe` + `README.txt`
- NSIS 安装包：`scripts/windows-installer.nsi`

```bash
makensis -DSOURCE_EXE=/path/to/kite-desktop.exe scripts/windows-installer.nsi
```

安装包行为：安装到 `%ProgramFiles%\Kite`，创建公共桌面与开始菜单快捷方式，写入"应用和功能"卸载项，
并注册资源管理器右键菜单 `Send with Kite`（`--share "%1"`，单实例转发给已运行的窗口）；
支持 `/S` 静默安装与 `uninstall.exe /S` 静默卸载。

## 4. Android

```bash
cd apps/desktop
npm ci
npm run tauri android build -- --apk --split-per-abi --target aarch64 x86_64 -- --locked
```

APK 位于 `apps/desktop/src-tauri/gen/android/app/build/outputs/apk/`。构建使用本机 `apps/desktop/src-tauri/gen/android/keystore.properties` 指定的签名密钥。将通过 `apksigner verify --print-certs <apk>` 校验的 APK 复制到发布目录。更新 APK 时应沿用原有签名密钥。

## 5. 校验清单

把本次发布的二进制压缩包、安装包和 APK 复制到独立的发布目录，为实际发布的文件执行 `sha256sum`，生成 `SHA256SUMS` 并和附件一起上传。下载后可在同一目录运行 `sha256sum -c SHA256SUMS`。签名密钥和签名配置留在构建环境。

## 6. 常见问题

- **ring 与 aws-lc-rs**：Windows arm64 交叉编译时 `ring` 的 arm64 汇编无法用 clang 生成，因此 TLS 后端统一为
  `aws-lc-rs`；`reqwest` 使用 `rustls-tls-webpki-roots-no-provider` 并在进程启动时安装默认 provider。
- **Windows GUI 冒烟**：NSIS 安装包与桌面端必须在交互式会话中验证；通过 SSH（session 0）启动 GUI 会报
  `WebView2 0x80070578 无效的窗口句柄`，属于环境限制。
- **arm64 Windows 服务端**：可在 x64 Linux 上用 `cargo xwin` 交叉编译，但无法在本机实机运行验证。
