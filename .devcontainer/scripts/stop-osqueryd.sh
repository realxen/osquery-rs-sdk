#!/usr/bin/env bash
set -euo pipefail

RUNTIME_DIR="${OSQUERY_RUNTIME_DIR:-/tmp/osquery-rs-sdk-devcontainer}"
PIDFILE="${RUNTIME_DIR}/osqueryd.pid"
SERVICE_PIDFILE="${RUNTIME_DIR}/osqueryd.service.pid"
SOCKET="${OSQUERY_EXTENSION_SOCKET:-/var/osquery/osquery.em}"

if [[ ! -f "$PIDFILE" ]]; then
    echo "osqueryd is not running"
    exit 0
fi

pid="$(cat "$PIDFILE")"
if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    for _ in $(seq 1 25); do
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        sleep 0.2
    done
fi

rm -f "$PIDFILE" "$SERVICE_PIDFILE" "$SOCKET"
echo "osqueryd stopped"
