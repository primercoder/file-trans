#!/usr/bin/env bash
# Linux server + client A, Windows client B, with a real encrypted file transfer.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="${KITE_VM_HOST:-vmwin}"
REMOTE_DIR='C:\Users\win\Desktop\kite'
REMOTE_HOME='C:\Users\win'
FILE_PATH="${1:-}"
RUN_ID="$(date +%s%N)-$$"
WORK_DIR="$(mktemp -d /tmp/opencode/kite-cross-smoke.XXXXXX)"
SERVER_PID=''
A_PID=''
B_PID=''

cleanup() {
    status=$?
    trap - EXIT
    for pid in "$A_PID" "$B_PID" "$SERVER_PID"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$HOST" \
        "cmd /c \"del /q $REMOTE_DIR\\cross-smoke-invite-$RUN_ID.txt $REMOTE_DIR\\cross-smoke-B-$RUN_ID.db $REMOTE_DIR\\cross-smoke-payload.bin 2>NUL\"" \
        >/dev/null 2>&1 || true
    if [[ "$status" -ne 0 ]]; then
        echo "CROSS_SMOKE_FAIL logs preserved in $WORK_DIR" >&2
        for log in server linux-a windows-b; do
            if [[ -f "$WORK_DIR/$log.log" ]]; then
                echo "--- $log.log ---" >&2
                tail -n 80 "$WORK_DIR/$log.log" >&2
            fi
        done
    else
        rm -rf "$WORK_DIR"
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

if [[ -n "$FILE_PATH" ]]; then
    if [[ ! -f "$FILE_PATH" ]]; then
        echo "file does not exist: $FILE_PATH" >&2
        exit 2
    fi
else
    FILE_PATH="$WORK_DIR/payload.bin"
    dd if=/dev/urandom of="$FILE_PATH" bs=1M count=1 status=none
fi

cargo build --locked --workspace --examples
NODE="$ROOT/target/debug/examples/smoke_node"
SERVER="$ROOT/target/debug/kite-server"
pick_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("0.0.0.0", 0)); print(s.getsockname()[1]); s.close()'
}
API_PORT="$(pick_port)"
HEALTH_PORT="$(pick_port)"
KITE_BIND="0.0.0.0:$API_PORT" \
KITE_HEALTH_BIND="127.0.0.1:$HEALTH_PORT" \
KITE_DB_PATH="$WORK_DIR/server.db" \
    "$SERVER" >"$WORK_DIR/server.log" 2>&1 &
SERVER_PID=$!

fingerprint=''
for _ in $(seq 1 200); do
    if [[ -s "$WORK_DIR/fingerprint.txt" ]]; then
        fingerprint="$(tr -d '[:space:]' <"$WORK_DIR/fingerprint.txt")"
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "server exited before writing its fingerprint" >&2
        exit 1
    fi
    sleep 0.05
done
if [[ ! "$fingerprint" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "server did not provide a valid fingerprint" >&2
    exit 1
fi
curl --noproxy '*' -fsS "http://127.0.0.1:$HEALTH_PORT/healthz" >"$WORK_DIR/health.json"
echo "SERVER_OK bind=0.0.0.0:$API_PORT fingerprint=$fingerprint"

# Ship exactly the tested source (not target/, VCS metadata, or local databases).
tar --exclude='./target' --exclude='./.git' --exclude='./.superpowers' --exclude='./dist' \
    --exclude='./apps/desktop/node_modules' --exclude='./apps/desktop/src-tauri/target' \
    --exclude='./apps/desktop/src-tauri/gen/android/app/build' \
    --exclude='./apps/desktop/src-tauri/gen/android/build' \
    --exclude='./apps/desktop/src-tauri/gen/android/.gradle' \
    --exclude='*.db' --exclude='*.db-*' --exclude='*.log' \
    -C "$ROOT" -cf "$WORK_DIR/source.tar" .
ssh -o BatchMode=yes "$HOST" "cmd /c \"if not exist $REMOTE_DIR mkdir $REMOTE_DIR\""
scp -q -o BatchMode=yes "$WORK_DIR/source.tar" "$HOST:C:/Users/win/Desktop/kite-smoke-source.tar"
ssh -o BatchMode=yes "$HOST" \
    "cmd /c \"cd /d $REMOTE_DIR && tar -xf C:\\Users\\win\\Desktop\\kite-smoke-source.tar && del /q C:\\Users\\win\\Desktop\\kite-smoke-source.tar\""

HOST_IP=''
for candidate in $(hostname -I); do
    case "$candidate" in *:*) continue ;; esac
    if ssh -o BatchMode=yes -o ConnectTimeout=5 "$HOST" \
        "curl.exe --noproxy * -k -s -o NUL -w \"%{http_code}\" https://$candidate:$API_PORT/healthz" \
        2>/dev/null | grep -qx '200'; then
        HOST_IP="$candidate"
        break
    fi
done
if [[ -z "$HOST_IP" ]]; then
    echo "Windows could not reach the Linux HTTPS server on any host address" >&2
    exit 1
fi
BASE_URL="https://$HOST_IP:$API_PORT"
echo "WINDOWS_CONNECTIVITY_OK $BASE_URL"

# Finish first-run compilation before the protocol timeout starts. This also
# avoids masking a slow linker/antivirus scan as a messaging failure.
ssh -o BatchMode=yes -o ServerAliveInterval=30 "$HOST" \
    "cmd /c \"cd /d $REMOTE_DIR && set \"PATH=$REMOTE_HOME\\.cargo\\bin;%PATH%\" && set \"CARGO_TERM_COLOR=never\" && cargo build --locked --example smoke_node -p kite-core\""

REMOTE_INVITE="$REMOTE_DIR\\cross-smoke-invite-$RUN_ID.txt"
REMOTE_STORE="$REMOTE_DIR\\cross-smoke-B-$RUN_ID.db"
# Run through cargo on Windows as well: this verifies the example builds there.
# Clearing proxy variables is important for a host-local LAN connection.
ssh -o BatchMode=yes -o ServerAliveInterval=30 "$HOST" \
    "cmd /c \"cd /d $REMOTE_DIR && set \"PATH=$REMOTE_HOME\\.cargo\\bin;%PATH%\" && set \"CARGO_TERM_COLOR=never\" && set \"HTTP_PROXY=\" && set \"HTTPS_PROXY=\" && set \"http_proxy=\" && set \"https_proxy=\" && set \"ALL_PROXY=\" && set \"all_proxy=\" && set \"NO_PROXY=$HOST_IP\" && set \"no_proxy=$HOST_IP\" && cargo run --locked --quiet --example smoke_node -p kite-core -- --server-url $BASE_URL --ca-fingerprint $fingerprint --role B --invite-file $REMOTE_INVITE --file $REMOTE_DIR\\cross-smoke-payload.bin --store $REMOTE_STORE\"" \
    >"$WORK_DIR/windows-b.log" 2>&1 &
B_PID=$!

# B compares its decrypted download against this local copy of the original.
scp -q -o BatchMode=yes "$FILE_PATH" "$HOST:C:/Users/win/Desktop/kite/cross-smoke-payload.bin"

"$NODE" --server-url "$BASE_URL" --ca-fingerprint "$fingerprint" --role A \
    --invite-file "$WORK_DIR/invite.txt" --file "$FILE_PATH" \
    --store "$WORK_DIR/A.db" >"$WORK_DIR/linux-a.log" 2>&1 &
A_PID=$!

# Transfer A's invite to B's independent filesystem. B also uses authenticated
# device-directory discovery and X3DH; the invite is not a trusted credential.
for _ in $(seq 1 100); do
    if [[ -s "$WORK_DIR/invite.txt" ]]; then
        scp -q -o BatchMode=yes "$WORK_DIR/invite.txt" "$HOST:C:/Users/win/Desktop/kite/cross-smoke-invite-$RUN_ID.txt"
        break
    fi
    sleep 0.05
done
if [[ ! -s "$WORK_DIR/invite.txt" ]]; then
    echo "Linux A did not write its invite" >&2
    exit 1
fi

set +e
wait "$B_PID"
b_status=$?
B_PID=''
wait "$A_PID"
a_status=$?
A_PID=''
set -e
cat "$WORK_DIR/linux-a.log"
cat "$WORK_DIR/windows-b.log"
if [[ "$a_status" -ne 0 || "$b_status" -ne 0 ]]; then
    echo "client exit status: Linux A=$a_status Windows B=$b_status" >&2
    exit 1
fi
for assertion in 'SMOKE-OK role=A' 'RECEIPT_OK' 'FILE_SENT_OK'; do
    grep -qF "$assertion" "$WORK_DIR/linux-a.log"
done
for assertion in 'SMOKE-OK role=B' 'TEXT_RECEIVED_OK' 'FILE_ROUNDTRIP_OK'; do
    grep -qF "$assertion" "$WORK_DIR/windows-b.log"
done
EXPECTED_SHA="$(sha256sum "$FILE_PATH" | cut -d' ' -f1)"
grep -qF "sha256=$EXPECTED_SHA" "$WORK_DIR/windows-b.log"
ssh -o BatchMode=yes "$HOST" \
    "cmd /c \"del /q $REMOTE_INVITE $REMOTE_STORE $REMOTE_DIR\\cross-smoke-payload.bin 2>NUL\"" || true
echo "CROSS_SMOKE_PASS linux_A=SMOKE-OK windows_B=SMOKE-OK file_bytes=$(stat -c %s "$FILE_PATH") sha256=$EXPECTED_SHA"
