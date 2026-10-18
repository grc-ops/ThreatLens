#!/bin/sh
# Make sure the state folder (database, refreshed ATT&CK data) is writable, then drop root.
set -e
STATE_DIR="${STATE_DIR:-/data}"
mkdir -p "$STATE_DIR"
if [ "$(id -u)" = "0" ]; then
  chown -R app:app "$STATE_DIR"
  exec runuser -u app -- "$@"
fi
exec "$@"
