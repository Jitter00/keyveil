#!/usr/bin/env bash
# Packaging smoke test: build the wheel, install it into a throwaway uv tool environment, and
# drive the *installed* `keyveil` command. Needs uv (and network the first time it fetches a
# Python). Uses its own config/state dirs and a free port; never touches your real setup.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
export UV_TOOL_DIR="$tmp/tools" UV_TOOL_BIN_DIR="$tmp/bin"
export XDG_CONFIG_HOME="$tmp/config" XDG_STATE_HOME="$tmp/state" XDG_RUNTIME_DIR="$tmp/run"
mkdir -m 700 "$tmp/run"
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
kv="$tmp/bin/keyveil"
cleanup() { "$kv" stop >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }

step "build and install the wheel"
uv build --wheel --out-dir "$tmp/dist" "$repo" >/dev/null
uv tool install "$tmp"/dist/keyveil-*.whl >/dev/null
"$kv" --version

step "the tool runs on Python >= 3.11 (system python3 is $(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])'))"
"$UV_TOOL_DIR/keyveil/bin/python" -c 'import sys; assert sys.version_info >= (3, 11), sys.version; print(sys.version.split()[0])'

step "start / status / request / stop with a stub decrypt command"
mkdir -p "$XDG_CONFIG_HOME/keyveil"
printf 'port = %s\n[decrypt]\ncommand = %s\n' "$port" "'printf \"DEEPSEEK_API_KEY=smoke-test\\n\"'" \
  > "$XDG_CONFIG_HOME/keyveil/config.toml"
"$kv" start
"$kv" status
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/nope/x")"
[ "$code" = 404 ] || { echo "expected 404 from the proxy, got $code" >&2; exit 1; }
"$kv" stop
if "$kv" status >/dev/null; then echo "still running after stop" >&2; exit 1; fi

printf '\nSMOKE OK\n'
