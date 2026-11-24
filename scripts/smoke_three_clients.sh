#!/usr/bin/env bash
# State contract: Compose is always stopped on exit (without -v, so docker/data
# and its database/fingerprint survive for inspection and later runs). Temporary
# client state is deleted. On failure, full server logs are preserved under
# /tmp/opencode and the last 50 lines are printed before cleanup.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT/docker/docker-compose.yml"
DATA_DIR="$ROOT/docker/data"
BASE_URL="https://localhost:8443"
RUN_ID="$(date +%s%N)-$$"
ALICE_NAME="Alice-$RUN_ID"
BOB_NAME="Bob-$RUN_ID"
MESSAGE="three-endpoint smoke: hello from A"
WORK_DIR="$(mktemp -d /tmp/opencode/kite-smoke.XXXXXX)"
cleanup() {
    status=$?
    trap - EXIT
    if [[ "$status" -ne 0 ]]; then
        log_dir="/tmp/opencode/kite-smoke-failure-$RUN_ID"
        mkdir -p "$log_dir"
        docker compose -f "$COMPOSE_FILE" logs --no-color kite-server \
            >"$log_dir/server.log" 2>&1 || true
        echo "FAIL: full server log preserved at $log_dir/server.log" >&2
        tail -n 50 "$log_dir/server.log" >&2
    fi
    # Keep the bind-mounted data volume for post-run inspection; only the
    # generated TLS certificate/fingerprint changes when Compose is rebuilt.
    docker compose -f "$COMPOSE_FILE" down || true
    rm -rf "$WORK_DIR"
    exit "$status"
}
trap cleanup EXIT

mkdir -p "$DATA_DIR"
docker compose -f "$COMPOSE_FILE" up -d --build

healthy=0
health_deadline=$((SECONDS + 60))
while (( SECONDS < health_deadline )); do
    remaining=$((health_deadline - SECONDS))
    curl_timeout=$((remaining < 2 ? remaining : 2))
    if curl -ksS --max-time "$curl_timeout" -o "$WORK_DIR/health.json" -w '%{http_code}' \
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
    docker compose -f "$COMPOSE_FILE" logs --tail=50 kite-server >&2
    exit 1
fi
echo "HEALTH_OK $(cat "$WORK_DIR/health.json")"

fingerprint="$(tr -d '[:space:]' < "$DATA_DIR/fingerprint.txt")"
if [[ ! "$fingerprint" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "FAIL: invalid server fingerprint in $DATA_DIR/fingerprint.txt" >&2
    exit 1
fi

cargo build --locked --example smoke_node -p kite-core
NODE="$ROOT/target/debug/examples/smoke_node"

SMOKE_PEER_NAME="$BOB_NAME" SMOKE_MESSAGE="$MESSAGE" \
    "$NODE" "$ALICE_NAME" "$BASE_URL" "$fingerprint" "$WORK_DIR/alice.db" initiator \
    >"$WORK_DIR/alice.log" 2>&1 &
alice_pid=$!
SMOKE_PEER_NAME="$ALICE_NAME" SMOKE_MESSAGE="$MESSAGE" \
    "$NODE" "$BOB_NAME" "$BASE_URL" "$fingerprint" "$WORK_DIR/bob.db" responder \
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
    "REGISTER_OK name=$ALICE_NAME" 'DISCOVERY_OK' 'PAIR_REQUEST_SENT' 'PAIR_OK' 'SEND_OK' \
    "REGISTER_OK name=$BOB_NAME" 'RECEIVE_OK'; do
    if ! grep -qF "$expected" "$WORK_DIR/alice.log" "$WORK_DIR/bob.log"; then
        echo "FAIL: missing smoke assertion: $expected" >&2
        linux_ok=0
    fi
done
if [[ "$linux_ok" -ne 1 ]]; then
    echo "FAIL: Linux register/discovery/pair/send/receive leg failed" >&2
    exit 1
fi
echo "LINUX_CLIENTS_OK register/discovery/pair/send/decrypt"

if ! ssh -o BatchMode=yes -o ConnectTimeout=5 vmwin 'exit 0' >/dev/null 2>&1; then
    echo "SKIP: Windows leg: vmwin is unreachable; Linux legs passed"
    exit 0
fi

windows_ok=0
for host_ip in $(hostname -I); do
    # Prefer PowerShell for the connectivity assertion. Some VM TLS stacks
    # cannot negotiate with rustls, so fall back to Windows' built-in curl.
    ps_command="[Net.ServicePointManager]::ServerCertificateValidationCallback={\$true}; \$r=Invoke-WebRequest -UseBasicParsing -Uri 'https://${host_ip}:8443/healthz' -TimeoutSec 10; if (\$r.StatusCode -ne 200) { exit 1 }; exit 0"
    encoded="$(printf '%s' "$ps_command" | iconv -f UTF-8 -t UTF-16LE | base64 -w0)"
    if ssh -o BatchMode=yes -o ConnectTimeout=5 vmwin \
        "powershell -NoProfile -EncodedCommand $encoded" >/dev/null 2>&1 ||
        ssh -o BatchMode=yes -o ConnectTimeout=5 vmwin \
            "curl.exe -k -s -o NUL -w \"%{http_code}\" https://${host_ip}:8443/healthz" |
        grep -qx '200'; then
        echo "WINDOWS_CONNECTIVITY_OK https://${host_ip}:8443/healthz returned HTTP 200"
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
