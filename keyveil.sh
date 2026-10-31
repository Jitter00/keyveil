#!/usr/bin/env bash
# keyveil.sh — start/stop the in-memory API-key proxy (see README.md).
#   keyveil.sh start    # decrypts with age/rage (e.g. YubiKey touch); key lives only in RAM
#   keyveil.sh stop | status
#
# Settings come from the environment or from an optional (gitignored) config file:
#   ./keyveil.conf  or  ${XDG_CONFIG_HOME:-~/.config}/keyveil/config
#     KEYVEIL_IDENTITY   age identity file (required)        e.g. ~/.config/age/yubikey.txt
#     KEYVEIL_ENV_FILE   encrypted env file (default: ./.env.age)
#     KEYVEIL_PORT       listen port (default: 8787)
#     KEYVEIL_AGE        age binary (default: rage if installed, else age)
#     KEYVEIL_ROUTES     JSON file with extra routes (default: ./routes.json if present)
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for conf in "$DIR/keyveil.conf" "${XDG_CONFIG_HOME:-$HOME/.config}/keyveil/config"; do
  # shellcheck disable=SC1090
  [ -f "$conf" ] && . "$conf"
done

PORT="${KEYVEIL_PORT:-8787}"
ENC="${KEYVEIL_ENV_FILE:-$DIR/.env.age}"
IDENTITY="${KEYVEIL_IDENTITY:-}"
AGE="${KEYVEIL_AGE:-$(command -v rage >/dev/null 2>&1 && echo rage || echo age)}"
LOG="${XDG_CACHE_HOME:-$HOME/.cache}/keyveil.log"   # no secrets are ever logged
PROXY="$DIR/src/keyveil/proxy.py"
ROUTES="${KEYVEIL_ROUTES:-$DIR/routes.json}"
ROUTE_ARGS=(); [ -f "$ROUTES" ] && ROUTE_ARGS=(--routes "$ROUTES")

up() { (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; }
PAT="keyveil/[p]roxy\.py.* --port $PORT\$"   # [p] stops pgrep matching its own shell

case "${1:-start}" in
  start)
    if up; then echo "keyveil already running on :$PORT"; exit 0; fi
    [ -n "$IDENTITY" ] || { echo "set KEYVEIL_IDENTITY (see README.md)" >&2; exit 1; }
    [ -f "$ENC" ] || { echo "encrypted env file not found: $ENC" >&2; exit 1; }
    mkdir -p "$(dirname "$LOG")"
    echo "Unlocking identity (touch your YubiKey if prompted)..."
    # Decrypt into a shell variable (RAM), then pipe via printf (bash builtin:
    # no argv exposure, no temp file) into the detached proxy.
    env_data="$("$AGE" -d -i "$IDENTITY" "$ENC")" || { echo "decryption failed" >&2; exit 1; }
    printf '%s\n' "$env_data" | setsid python3 -I "$PROXY" "${ROUTE_ARGS[@]}" --port "$PORT" >>"$LOG" 2>&1 &
    unset env_data
    for _ in $(seq 50); do up && { echo "ok — keyveil on 127.0.0.1:$PORT"; exit 0; }; sleep 0.1; done
    echo "keyveil failed to start; see $LOG" >&2; exit 1
    ;;
  stop)
    if pkill -f "$PAT"; then echo "stopped"; else echo "not running"; fi
    ;;
  status)
    if up; then echo "running on :$PORT (pid $(pgrep -f "$PAT"))"; else echo "not running"; fi
    ;;
  *) echo "usage: $0 {start|stop|status}" >&2; exit 2 ;;
esac
