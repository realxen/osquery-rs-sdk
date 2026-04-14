#!/usr/bin/env bash
set -euo pipefail

OSQUERYD_BIN="${OSQUERYD_BIN:-/opt/osquery/bin/osqueryd}"
SOCKET="${OSQUERY_EXTENSION_SOCKET:-/var/osquery/osquery.em}"
SOCKET_DIR="$(dirname "$SOCKET")"
DB_DIR="${OSQUERY_DB_DIR:-/var/osquery/osquery.db}"
LOG_DIR="${OSQUERY_LOG_DIR:-/var/log/osquery}"
RUNTIME_DIR="${OSQUERY_RUNTIME_DIR:-/tmp/osquery-rs-sdk-devcontainer}"
PIDFILE="${RUNTIME_DIR}/osqueryd.pid"
SERVICE_PIDFILE="${RUNTIME_DIR}/osqueryd.service.pid"
LOGFILE="${LOG_DIR}/osqueryd-devcontainer.log"
FLAGSFILE="${RUNTIME_DIR}/osquery.flags"

mkdir -p "$SOCKET_DIR" "$DB_DIR" "$LOG_DIR" "$RUNTIME_DIR"

if [[ -f "$PIDFILE" ]]; then
    pid="$(cat "$PIDFILE")"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        echo "osqueryd already running (pid $pid)"
        exit 0
    fi
    rm -f "$PIDFILE"
fi

if [[ -S "$SOCKET" ]]; then
    rm -f "$SOCKET"
fi

cat >"$FLAGSFILE" <<EOF
--disable_events=true
--disable_watchdog=true
--ephemeral=false
--database_path=${DB_DIR}
--extensions_socket=${SOCKET}
--logger_plugin=filesystem
--logger_path=${LOG_DIR}
--pidfile=${SERVICE_PIDFILE}
--utc=true
EOF

nohup "$OSQUERYD_BIN" --flagfile="$FLAGSFILE" >>"$LOGFILE" 2>&1 &
pid=$!
echo "$pid" >"$PIDFILE"

for _ in $(seq 1 50); do
    if [[ -S "$SOCKET" ]]; then
        echo "osqueryd ready on $SOCKET"
        exit 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "osqueryd exited unexpectedly" >&2
        tail -n 50 "$LOGFILE" >&2 || true
        exit 1
    fi
    sleep 0.2
done

echo "timed out waiting for osqueryd socket at $SOCKET" >&2
tail -n 50 "$LOGFILE" >&2 || true
exit 1
