#!/usr/bin/env bash
# Use an isolated Compose project, database and host port for each run.
# Preserve server logs and data on failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT/docker/docker-compose.yml"
RUN_ID="$(date +%s%N)-$$"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}"/kite-smoke.XXXXXX)"
export KITE_DATA_DIR="$WORK_DIR/data"
export KITE_PUBLISH_PORT=0
export KITE_CONTAINER_USER="$(id -u):$(id -g)"
compose=(docker compose -f "$COMPOSE_FILE" -p "kite-smoke-$RUN_ID")
cleanup() {
    status=$?
    trap - EXIT
    if [[ "$status" -ne 0 ]]; then
        "${compose[@]}" logs --no-color kite-server >"$WORK_DIR/server.log" 2>&1 || true
        echo "FAIL: server logs and test data preserved at $WORK_DIR" >&2
        tail -n 50 "$WORK_DIR/server.log" >&2
    fi
    "${compose[@]}" down --rmi local || true
    if [[ "$status" -eq 0 ]]; then
        rm -rf "$WORK_DIR"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$KITE_DATA_DIR"
"${compose[@]}" up -d --build
endpoint="$("${compose[@]}" port kite-server 8443)"
port="${endpoint##*:}"
BASE_URL="https://localhost:$port"

healthy=0
health_deadline=$((SECONDS + 60))
while (( SECONDS < health_deadline )); do
    remaining=$((health_deadline - SECONDS))
    curl_timeout=$((remaining < 2 ? remaining : 2))
    if curl --noproxy '*' -ksS --max-time "$curl_timeout" -o "$WORK_DIR/health.json" -w '%{http_code}' \
        "$BASE_URL/healthz" | grep -qx '200'; then
        healthy=1
        break
    fi
    remaining=$((health_deadline - SECONDS))
    if (( remaining >= 1 )); then
        sleep 1
    fi
done
if [[ "$healthy" -ne 1 ]]; then
    echo "FAIL: server did not become healthy within 60 seconds" >&2
    "${compose[@]}" logs --tail=50 kite-server >&2
    exit 1
fi
echo "HEALTH_OK $(cat "$WORK_DIR/health.json")"

fingerprint="$(tr -d '[:space:]' < "$KITE_DATA_DIR/fingerprint.txt")"
if [[ ! "$fingerprint" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "FAIL: invalid server fingerprint in $KITE_DATA_DIR/fingerprint.txt" >&2
    exit 1
fi

cargo build --manifest-path "$ROOT/Cargo.toml" --locked --example smoke_node -p kite-core
NODE="$ROOT/target/debug/examples/smoke_node"
payload="$WORK_DIR/payload.bin"
dd if=/dev/urandom of="$payload" bs=1M count=1 status=none
expected_hash="$(sha256sum "$payload" | cut -d' ' -f1)"

"$NODE" --server-url "$BASE_URL" --ca-fingerprint "$fingerprint" --role A \
    --invite-file "$WORK_DIR/alice-invite.txt" --file "$payload" --store "$WORK_DIR/alice.db" \
    >"$WORK_DIR/alice.log" 2>&1 &
alice_pid=$!
"$NODE" --server-url "$BASE_URL" --ca-fingerprint "$fingerprint" --role B \
    --invite-file "$WORK_DIR/alice-invite.txt" --file "$payload" --store "$WORK_DIR/bob.db" \
    >"$WORK_DIR/bob.log" 2>&1 &
bob_pid=$!

linux_ok=1
if ! wait "$alice_pid"; then
    linux_ok=0
fi
if ! wait "$bob_pid"; then
    linux_ok=0
fi
cat "$WORK_DIR/alice.log" "$WORK_DIR/bob.log"
for expected in \
    'REGISTER_OK role=A' 'INVITE_OK' 'PAIR_REQUEST_SENT' 'PAIR_OK' 'TEXT_SENT_OK' \
    'REGISTER_OK role=B' 'TEXT_RECEIVED_OK' 'FILE_ROUNDTRIP_OK' \
    "sha256=$expected_hash" 'SMOKE-OK role=A' 'SMOKE-OK role=B'; do
    if ! grep -qF "$expected" "$WORK_DIR/alice.log" "$WORK_DIR/bob.log"; then
        echo "FAIL: missing smoke assertion: $expected" >&2
        linux_ok=0
    fi
done
if [[ "$linux_ok" -ne 1 ]]; then
    echo "FAIL: Linux encrypted message or file transfer failed" >&2
    exit 1
fi
echo "LINUX_CLIENTS_OK register/discovery/pair/send/decrypt/file_sha256"

if ! ssh -o BatchMode=yes -o ConnectTimeout=5 vmwin whoami >/dev/null 2>&1; then
    echo "SKIP: Windows leg: vmwin is unreachable; Linux legs passed"
    exit 0
fi

windows_ok=0
for host_ip in $(hostname -I); do
    case "$host_ip" in *:*) continue ;; esac
    # Prefer PowerShell for the connectivity assertion. Some VM TLS stacks
    # cannot negotiate with rustls, so fall back to Windows' built-in curl.
    ps_command="[Net.ServicePointManager]::ServerCertificateValidationCallback={\$true}; \$r=Invoke-WebRequest -UseBasicParsing -Uri 'https://${host_ip}:$port/healthz' -TimeoutSec 10; if (\$r.StatusCode -ne 200) { exit 1 }; exit 0"
    encoded="$(printf '%s' "$ps_command" | iconv -f UTF-8 -t UTF-16LE | base64 -w0)"
    if ssh -o BatchMode=yes -o ConnectTimeout=5 vmwin \
        "powershell -NoProfile -EncodedCommand $encoded" >/dev/null 2>&1 ||
        ssh -o BatchMode=yes -o ConnectTimeout=5 vmwin \
            "curl.exe --noproxy * --max-time 10 -k -s -o NUL -w \"%{http_code}\" https://${host_ip}:$port/healthz" |
        grep -qx '200'; then
        echo "WINDOWS_CONNECTIVITY_OK https://${host_ip}:$port/healthz returned HTTP 200"
        windows_ok=1
        break
    fi
    echo "Windows could not reach ${host_ip}; trying next host address" >&2
done

if [[ "$windows_ok" -ne 1 ]]; then
    echo "FAIL: vmwin is reachable but no host address passed the HTTPS health check" >&2
    exit 1
fi
echo "SMOKE_OK all three endpoints passed"
