#!/usr/bin/env bash
# Builds the server for glibc 2.35 hosts (Ubuntu 22.04) on x86_64 and arm64.
#
# The host toolchain is newer than the user's server, so the release binaries are
# produced inside an Ubuntu 22.04 container. Outputs land in target/glibc-22.04/.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=${IMAGE:-ubuntu:22.04}
OUT="$ROOT/target/glibc-22.04"

mkdir -p "$OUT"

docker run --rm \
  -v "$ROOT":/src \
  -v kite-cargo-registry:/root/.cargo/registry \
  -v kite-cargo-git:/root/.cargo/git \
  -v "$HOME/.rustup:/root/.rustup:ro" \
  -v "$HOME/.cargo/bin:/root/.cargo/bin:ro" \
  -v kite-target-jammy:/target \
  -w /src \
  -e HOST_UID="$(id -u)" \
  -e HOST_GID="$(id -g)" \
  "$IMAGE" bash -lc '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
      curl ca-certificates build-essential pkg-config cmake clang \
      gcc-aarch64-linux-gnu libc6-dev-arm64-cross >/dev/null
    export PATH="/root/.cargo/bin:$PATH"
    if ! command -v cargo >/dev/null 2>&1; then
      curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
      # shellcheck disable=SC1091
      source "$HOME/.cargo/env"
    fi
    export CARGO_TARGET_DIR=/target
    rustup target add aarch64-unknown-linux-gnu >/dev/null
    cargo build --release -p kite-server
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
    export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
    cargo build --release -p kite-server --target aarch64-unknown-linux-gnu
    strip /target/release/kite-server
    aarch64-linux-gnu-strip /target/aarch64-unknown-linux-gnu/release/kite-server
    mkdir -p /src/target/glibc-22.04
    cp /target/release/kite-server /src/target/glibc-22.04/kite-server-linux-x64
    cp /target/aarch64-unknown-linux-gnu/release/kite-server /src/target/glibc-22.04/kite-server-linux-arm64
    chmod 755 /src/target/glibc-22.04/kite-server-linux-x64 /src/target/glibc-22.04/kite-server-linux-arm64
    chown "$HOST_UID:$HOST_GID" /src/target/glibc-22.04/kite-server-linux-x64 /src/target/glibc-22.04/kite-server-linux-arm64
  '

echo "== glibc requirements =="
for binary in "$OUT"/*; do
  echo "-- $(basename "$binary")"
  objdump -T "$binary" 2>/dev/null | grep -oE 'GLIBC_[0-9.]+' | sort -Vu | tail -1
done
echo "outputs: $OUT"
