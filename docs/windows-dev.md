# Windows VM development and verification

The `vmwin` SSH host is a Windows 11 VM (build 26300.9974) with user `win`.
Source deployed by the scripts lives at `C:\Users\win\Desktop\kite`.

## Installed tools

| Tool | Version / location |
| --- | --- |
| Rust / Cargo | 1.100.0, `%USERPROFILE%\.cargo\bin` |
| Python | 3.15.2, `C:\Python315\python.exe` |
| Node.js | 26.13.1 |
| npm | 11.20.0 (use `npm.cmd`, not the PowerShell shim) |

Non-interactive SSH sessions do **not** have Cargo in `PATH`. PowerShell's
execution policy may also reject `npm.ps1`; use `npm.cmd` or `cmd /c`.

## Build and test

From an interactive PowerShell session in the source directory:

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo build --locked --workspace --bins --examples
[Environment]::SetEnvironmentVariable("CARGO_BIN_EXE_kite-server", "$PWD\target\debug\kite-server.exe")
cargo test --locked --workspace
cargo clippy --locked --workspace -- -D warnings
```

The `kite-core` integration tests use `CARGO_BIN_EXE_kite-server` to locate the
binary from the `kite-server` crate. Both command examples and the deploy script
set the variable before calling Cargo.

The equivalent `cmd.exe` commands are:

```bat
set PATH=%USERPROFILE%\.cargo\bin;%PATH%
cargo build --locked --workspace --bins --examples
set CARGO_BIN_EXE_kite-server=C:\Users\win\Desktop\kite\target\debug\kite-server.exe
cargo test --locked --workspace
```

From Linux, deploy, stream the complete build/test log, and get explicit
PASS/FAIL summary lines with:

```bash
./scripts/deploy_vmwin.sh
```

Logs are retained under `target/vmwin-test-*.log`. The deployment transfers a
source archive over SCP and expands it with Windows' bundled `tar`; it excludes
`target/`, `.git`, local databases, and logs. The VM retains its target
directory, making subsequent builds incremental.

## Cross-machine file smoke

Ensure `ssh vmwin` uses non-interactive key authentication, then run:

```bash
./scripts/smoke_cross_machine.sh
# Or provide an existing payload:
./scripts/smoke_cross_machine.sh /path/to/file.bin
```

With no argument, the script generates 1 MiB of random data. It:

1. starts a Linux server on `0.0.0.0` with ephemeral API and health ports;
2. reads the self-signed certificate fingerprint written next to the server DB;
3. probes Linux host addresses from Windows to find a reachable HTTPS URL;
4. builds and runs Engine client B with `cargo run --example smoke_node` on Windows;
5. runs Engine client A locally, copies A's invite to Windows, and performs
   discovery/pairing/text/file transfer;
6. requires `SMOKE-OK` on both sides and checks B's decrypted SHA-256 against
   the source file, then cleans up processes and temporary state.

The example can also be run independently:

```text
smoke_node --server-url https://HOST:PORT --ca-fingerprint HEX \
  --role A|B --invite-file PATH [--file PATH] [--store PATH]
```

A writes its device ID to the invite file and B polls for that file. Use a
shared directory when running the two processes on different machines, or have
the orchestrator place the invite on B's machine. The smoke script copies this
invite with SCP while A uses the device directory to discover B. `--store`
selects an isolated SQLite state path (defaults beside the
invite). The invite is a discovery hint, not a replacement for authenticated
X3DH pairing: A still sends a pair request and B must accept it.

## Known pitfalls

- **Cargo PATH:** always prepend `%USERPROFILE%\.cargo\bin` for SSH commands.
- **CRLF:** `.gitattributes` forces LF for Rust, shell, TOML, and documentation
  files. Do not run checkout conversion or text-mode transfer on shell scripts;
  a CRLF shebang produces `bad interpreter` errors on Linux. The deployment
  archive preserves the committed bytes.
- **Console encoding:** non-interactive `cmd.exe` output is GBK. Keep script and
  test diagnostics ASCII; set `CARGO_TERM_COLOR=never` for clean captured logs.
- **Antivirus latency:** Defender may scan newly linked executables and the
  first uncached dependency build can take 5-15 minutes. Use generous SSH and
  process timeouts, and retain the target directory between runs.
- **Firewall:** tests bind ephemeral loopback listeners; the cross-machine
  server binds `0.0.0.0`. Windows may prompt for or block inbound listeners.
  Prefer a private network profile. Add a `netsh advfirewall` rule only if a
  connection timeout proves this is necessary, and record that rule explicitly.
- **Path separators:** remote `cmd` commands need backslashes; archive/SCP target
  syntax uses `C:/Users/win/Desktop/...`. Quote complete remote command strings.
- **Proxy**
  The cross-machine smoke clears proxy variables and sets `NO_PROXY` for the
  Linux host address. If Windows needs a proxy to reach the package registry,
  use a VM-local proxy or an address reachable from the VM, then set
  `HTTP_PROXY` and `HTTPS_PROXY` for the dependency build.
- **PowerShell shims:** `where` is unreliable over non-interactive SSH and
  `npm.ps1` can be blocked. Use full executable paths and `.cmd` shims.
