# Release 构建手册（0.1.0）

所有产物最终归集到仓库根目录 `dist/`（已 gitignore，不入库）。

## 0. 前置条件

- Rust 1.100 + `rustup target add aarch64-unknown-linux-gnu aarch64-pc-windows-msvc`
- Linux 交叉工具：`gcc-aarch64-linux-gnu`、`clang`、`lld`、`cargo-xwin`
- Android：Android SDK/NDK + 自签 keystore + `apps/desktop/src-tauri/gen/android/keystore.properties`
- Windows 打包：`nsis`（Linux 版 makensis 即可）
- Linux 打包：Tauri 自带 AppImage 打包（需要网络；也可用 appimagetool 手工打包）

## 1. 服务端

```bash
# Linux x64
cargo build --release -p kite-server
strip target/release/kite-server

# Linux arm64
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
cargo build --release -p kite-server --target aarch64-unknown-linux-gnu
aarch64-linux-gnu-strip target/aarch64-unknown-linux-gnu/release/kite-server

# Windows x64（在 Windows 构建机 / VM 内）
cargo build --release -p kite-server

# Windows arm64（x64 Linux 上交叉编译）
cargo xwin build --release -p kite-server --target aarch64-pc-windows-msvc
```

打包：每个平台一个压缩包，内含 `kite-server`(`.exe`) 与 `README.txt`。

## 2. Linux 桌面端

```bash
cd apps/desktop
npx tauri build          # 产出 kite-desktop、deb、rpm、AppImage
```

归集：

- `dist/linux/kite-desktop-linux-x64`（裸二进制）
- `dist/linux/kite-0.1.0-amd64.deb`
- `dist/linux/kite-0.1.0-x86_64.AppImage`
- `dist/linux/kite-0.1.0-linux-x64-portable.tar.gz`（`kite-desktop` + `README.txt`）

若 Tauri 打包 AppImage 时无法下载 AppRun，可手工打包：

```bash
# AppDir 里放 AppRun、kite.desktop、.DirIcon、usr/bin/kite-desktop、usr/share/icons/...
ARCH=x86_64 appimagetool --no-appstream Kite.AppDir kite-0.1.0-x86_64.AppImage
```

## 3. Windows 桌面端

在 Windows 构建机内：

```bat
cd apps\desktop\src-tauri
cargo build --release
```

取回 `kite-desktop.exe` 后：

- 免安装包：`zip` 内含 `kite-desktop.exe` + `README.txt`
- NSIS 安装包：`scripts/windows-installer.nsi`

```bash
makensis -DSOURCE_EXE=/path/to/kite-desktop.exe scripts/windows-installer.nsi
```

安装包行为：安装到 `%ProgramFiles%\Kite`，创建公共桌面与开始菜单快捷方式，写入"应用和功能"卸载项；
支持 `/S` 静默安装与 `uninstall.exe /S` 静默卸载。

## 4. Android

```bash
cd apps/desktop
npx tauri android build --target x86_64     # → dist/android/kite-0.1.0-x64-release.apk
npx tauri android build --target aarch64    # → dist/android/kite-0.1.0-arm64-release.apk
```

签名使用 `apps/desktop/src-tauri/gen/android/keystore.properties`（不入库）指向的自签 keystore；
校验：`apksigner verify --print-certs <apk>`。

## 5. 校验清单

```bash
cd dist
sha256sum android/*.apk linux/* windows/* server/* docs/* > checksums.txt
```

## 6. 常见问题

- **ring 与 aws-lc-rs**：Windows arm64 交叉编译时 `ring` 的 arm64 汇编无法用 clang 生成，因此 TLS 后端统一为
  `aws-lc-rs`；`reqwest` 使用 `rustls-tls-webpki-roots-no-provider` 并在进程启动时安装默认 provider。
- **Windows GUI 冒烟**：NSIS 安装包与桌面端必须在交互式会话中验证；通过 SSH（session 0）启动 GUI 会报
  `WebView2 0x80070578 无效的窗口句柄`，属于环境限制。
- **arm64 Windows 服务端**：可在 x64 Linux 上用 `cargo xwin` 交叉编译，但无法在本机实机运行验证。
