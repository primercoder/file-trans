#!/usr/bin/env bash
# Deploy source without build/state artifacts, then build and test on vmwin.
# Remote output is intentionally ASCII because cmd's GBK output is not UTF-8.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="${KITE_VM_HOST:-vmwin}"
REMOTE_DIR='C:\Users\win\Desktop\kite'
REMOTE_HOME='C:\Users\win'
RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
WORK_DIR="$(mktemp -d /tmp/opencode/kite-vmwin-deploy.XXXXXX)"
ARCHIVE="$WORK_DIR/kite-source.tar"
LOG="${KITE_DEPLOY_LOG:-$ROOT/target/vmwin-test-$RUN_ID.log}"
STATUS=FAIL

cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

mkdir -p "$(dirname "$LOG")"
echo "DEPLOY_START host=$HOST source=$ROOT log=$LOG"
tar --exclude='./target' --exclude='./.git' --exclude='./.superpowers' --exclude='./dist' \
    --exclude='./apps/desktop/node_modules' --exclude='./apps/desktop/src-tauri/target' \
    --exclude='*.db' --exclude='*.db-*' --exclude='*.log' \
    -C "$ROOT" -cf "$ARCHIVE" .

ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST" \
    "cmd /c \"if not exist $REMOTE_DIR mkdir $REMOTE_DIR\""
scp -q -o BatchMode=yes "$ARCHIVE" "$HOST:C:/Users/win/Desktop/kite-source.tar"
ssh -o BatchMode=yes "$HOST" \
    "cmd /c \"cd /d $REMOTE_DIR && tar -xf C:\\Users\\win\\Desktop\\kite-source.tar && del /q C:\\Users\\win\\Desktop\\kite-source.tar\""
echo "DEPLOY_COPY_OK destination=$REMOTE_DIR"

# Cargo sets CARGO_BIN_EXE_kite-server for integration tests. Setting it explicitly
# as well makes the contract clear and supports older/custom Cargo harnesses.
# Keep the existing remote target directory so repeated deployments are incremental.
set +e
ssh -o BatchMode=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=60 "$HOST" \
    "cmd /c \"cd /d $REMOTE_DIR && set \"PATH=$REMOTE_HOME\\.cargo\\bin;%PATH%\" && set \"CARGO_TERM_COLOR=never\" && cargo build --locked --workspace --examples && set \"CARGO_BIN_EXE_kite-server=$REMOTE_DIR\\target\\debug\\kite-server.exe\" && cargo test --locked --workspace\"" \
    2>&1 | tee "$LOG"
remote_status=${PIPESTATUS[0]}
set -e

if [[ "$remote_status" -eq 0 ]]; then
    STATUS=PASS
    echo "DEPLOY_TEST_PASS host=$HOST log=$LOG"
    echo "WINDOWS_TEST_PASS"
else
    echo "DEPLOY_TEST_FAIL host=$HOST exit=$remote_status log=$LOG" >&2
    echo "WINDOWS_TEST_FAIL" >&2
    exit "$remote_status"
fi

# Keep STATUS referenced in the trap-free success path as an explicit final state.
printf 'DEPLOY_SUMMARY %s\n' "$STATUS"
