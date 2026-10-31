# keyveil

A tiny localhost reverse proxy that adds your **API credentials to HTTP requests from
memory**, so the tools making those requests — editors, coding agents, scripts, SDKs —
never see, store, or inherit the real key.

```
 editor extensions   ─┐                          ┌─▶ api.anthropic.com   (x-api-key)
 coding agents       ─┼─(dummy key)─▶ 127.0.0.1:8787 ─┼─▶ api.openai.com      (Bearer)
 scripts, SDKs, curl ─┘          keyveil          └─▶ any other API       (Token / custom header)
                      real keys live only in this process's RAM
```

Keys stay encrypted at rest (`.env.age`, decrypted with [age]/[rage], ideally with a hardware
key such as a YubiKey). They are decrypted once, piped straight into the proxy's stdin, and
never touch the disk — not even `/run/user` or `/tmp`.

It was built to keep LLM provider keys away from AI coding tools, but nothing in it is
provider-specific: it works for any HTTP API that authenticates with a key or token in a
request header. Built-in routes cover a few common providers; anything else is a few lines in
a JSON file.

## What is it good for?

- **AI coding tools in an editor** (Continue, Cline, Roo, Copilot-style extensions…): the
  extension gets a dummy key and a local base URL instead of your real credential.
- **Autonomous agents** (Claude Code, Aider, OpenHands, custom agents) that run shell
  commands or read untrusted content. A prompt injection can no longer exfiltrate the key
  with `printenv` or `cat ~/.config/…`, because the key isn't there.
- **Scripts, notebooks and SDK clients** that call LLM or other APIs: point `base_url` at the
  proxy and drop the key from your code, `.env` files and shell history.
- **Any other header-authenticated API**: inventory/IPAM tools such as NetBox, internal
  services, self-hosted gateways (LiteLLM, vLLM or Ollama behind auth), and similar — add a
  route in a small JSON file, no code changes. See [Custom routes](#custom-routes).
- **Shared or recorded machines** (screen sharing, demos, pairing): nothing sensitive in
  environment variables or dotfiles to leak.

It is **not** a fit for anything that is not plain HTTP with a static header credential; see
[Limitations](#security-notes-and-limitations).

## Why not just export the env var and launch the tool?

That is the obvious approach, and it has real downsides:

- If an editor window is already open, `code .` hands off to it and your exported variables
  never arrive.
- Everything the tool starts inherits the key: every integrated terminal, every command an
  agent runs (often auto-approved), MCP servers, other extensions. Any process of yours can
  also read it from `/proc/<pid>/environ`.
- Tools that read secrets from files (Continue's `~/.continue/.env`, Cline's
  `~/.cline/data/secrets.json`) leave plaintext credentials on disk.

With keyveil, only one hardened process holds the key. Code running in your editor or agent
can *use* the proxy while it is up, but it can never *read* the key.

## How it works

- Listens on `127.0.0.1` only. Routes are `/<name>/...` → an upstream API
  (`/openai/v1/chat/completions` → `https://api.openai.com/v1/chat/completions`).
- Drops any credential header the client sent and sets the real one.
- Streams responses chunk by chunk, so SSE / streaming responses work.
- Verifies upstream TLS certificates.
- Logs only method, path and status — never headers or bodies.
- On Linux it calls `mlockall` (key never swapped to disk) and `prctl(PR_SET_DUMPABLE, 0)`
  (no core dumps; blocks same-user `/proc/<pid>/mem` and `environ` reads).
- A route is enabled only if its key is present in the decrypted input.

Built-in routes:

| Route         | Upstream                    | Env var             | Auth        |
|---------------|-----------------------------|---------------------|-------------|
| `/anthropic/` | `https://api.anthropic.com` | `ANTHROPIC_API_KEY` | `x-api-key` |
| `/openai/`    | `https://api.openai.com`    | `OPENAI_API_KEY`    | `bearer`    |
| `/deepseek/`  | `https://api.deepseek.com`  | `DEEPSEEK_API_KEY`  | `bearer`    |

Any other provider, including other OpenAI-compatible ones, is a custom route.

Only the routes listed under "Verified" below have been exercised end to end against a real
API by the author. The others, and all auth styles, are covered by offline tests that use a
local fake upstream and share the same code path.

**Verified:** DeepSeek.

### Auth styles

| `auth` value      | Header keyveil sets               | Typical use                         |
|-------------------|-----------------------------------|-------------------------------------|
| `bearer` (default)| `Authorization: Bearer <key>`     | OpenAI-compatible APIs, most SaaS   |
| `token`           | `Authorization: Token <key>`      | NetBox, Django REST Framework APIs  |
| `x-api-key`       | `x-api-key: <key>`                | Anthropic                           |
| `header:<Name>`   | `<Name>: <key>`                   | Any custom header, e.g. `header:X-Auth-Token` |

### Custom routes

Add services without touching the code. Copy [`routes.example.json`](routes.example.json) to
`routes.json` (gitignored; the launcher picks it up automatically, or pass `--routes FILE` /
set `KEYVEIL_ROUTES`). The file holds only env var **names**, never secrets:

```json
{
  "routes": {
    "netbox":  { "upstream": "https://netbox.example.com", "env": "NETBOX_TOKEN", "auth": "token" },
    "gateway": { "upstream": "http://127.0.0.1:4000",      "env": "GATEWAY_KEY",  "auth": "bearer" }
  }
}
```

Put the matching variables (`NETBOX_TOKEN=…`) in the file you encrypt to `.env.age`. Then use
`http://127.0.0.1:8787/netbox/api/…` with any dummy token. Upstreams must be `https://`;
plain `http://` is accepted only for loopback (`localhost`, `127.0.0.1`), so a key never
crosses a network in clear. A bad routes file makes the proxy refuse to start, with a message.

## Requirements

- Linux (the hardening calls are Linux/glibc; elsewhere it still runs, just without them)
- Python 3.10+ (standard library only — no dependencies)
- [age] or [rage] to decrypt; for hardware-backed keys,
  [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey)
- Optional: [uv](https://docs.astral.sh/uv/) for development and installing the CLI

## Setup

1. **Create an age identity** (a YubiKey-backed one is recommended — see the
   age-plugin-yubikey README), or a plain one with `rage-keygen`.

2. **Encrypt your keys.** Copy [`.env.example`](.env.example) to `.env`, fill in the keys
   you need, then encrypt and delete the plaintext:

   ```bash
   rage -r <your-age-recipient> -o .env.age .env && shred -u .env
   ```

   Keep the variable names the routes expect (e.g. `ANTHROPIC_API_KEY`).

3. **Tell the launcher where your identity is.** Copy `keyveil.conf.example` to
   `keyveil.conf` (gitignored) and set `KEYVEIL_IDENTITY`. Other options
   (`KEYVEIL_ENV_FILE`, `KEYVEIL_PORT`, `KEYVEIL_AGE`, `KEYVEIL_ROUTES`) are documented in
   the file.

4. **Optional shell aliases** (adjust the path):

   ```bash
   alias veilup='~/path/to/keyveil/keyveil.sh start'
   alias veildown='~/path/to/keyveil/keyveil.sh stop'
   alias veilstatus='~/path/to/keyveil/keyveil.sh status'
   ```

## Usage

```bash
./keyveil.sh start    # touch your YubiKey; prints "ok" when listening
./keyveil.sh status
./keyveil.sh stop     # also stops when you log out / reboot
```

Check it (the credential you send is ignored and replaced):

```bash
curl -s http://127.0.0.1:8787/<route>/<path> -H 'Authorization: Bearer anything'
# e.g. list models on an OpenAI-compatible route:
curl -s http://127.0.0.1:8787/openai/v1/models -H 'Authorization: Bearer anything'
```

Without the launcher, the same thing by hand:

```bash
rage -d -i identity.txt .env.age | python3 -I src/keyveil/proxy.py --port 8787
```

### Point your tools at it

Use any non-empty dummy key (e.g. `local-proxy`) — it is not a credential. The pattern is always
the same: base URL `http://127.0.0.1:8787/<route>/…`, dummy key.

**Claude Code** (needs `ANTHROPIC_API_KEY` in `.env.age`; keep that name there — the dummy
below is only a client-side placeholder). In `~/.claude/settings.json`:

```json
{ "env": { "ANTHROPIC_BASE_URL": "http://127.0.0.1:8787/anthropic",
           "ANTHROPIC_AUTH_TOKEN": "local-proxy" } }
```

Notes:
- Don't also export the real key in your shell, or Claude's environment would hold it again.
- With this in the user-level file, `claude` fails with a connection error whenever keyveil
  isn't running. To limit it to one project use `.claude/settings.local.json`, or to one
  session use `claude --settings '{"env": {...}}'`.
- Values in a settings file's `env` block override variables set in your shell. If you have
  an alias that sets its own `ANTHROPIC_BASE_URL` (say, for another gateway), pass it with
  `--settings` too — that flag outranks the user-level file.

**OpenAI-compatible tools** (Continue, Cline, Aider, SDKs…): set the base URL to
`http://127.0.0.1:8787/<route>/v1` and the API key to the dummy. For example, Continue
(`~/.continue/config.yaml`):

```yaml
models:
  - name: My model
    provider: openai
    model: <model-id>
    apiBase: http://127.0.0.1:8787/openai/v1/    # or /<your-route>/v1/
    apiKey: local-proxy
```

Cline: Settings → API Provider **OpenAI Compatible** → Base URL
`http://127.0.0.1:8787/<route>/v1`, API key `local-proxy`, Model ID of your choice. (Providers
with a dedicated, base-URL-less entry in a tool's menu generally can't be redirected; use the
tool's OpenAI-compatible option.)

**SDKs / scripts**:

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8787/openai/v1", api_key="local-proxy")

from anthropic import Anthropic
client = Anthropic(base_url="http://127.0.0.1:8787/anthropic", api_key="local-proxy")
```

**Any other HTTP client** (custom route, e.g. NetBox):

```bash
curl -s http://127.0.0.1:8787/netbox/api/dcim/sites/ -H 'Authorization: Token unused'
```

## Security notes and limitations

- **No client authentication.** Any process running as you (or any local user, if you
  change `--host`) can make requests through the proxy while it is up — it just can't
  read the key. Stop it when you're not using it. Keep the default bind address of
  `127.0.0.1`.
- Protects against leaking the key via files, environment variables, process listings and
  agents. It does **not** protect against root, a compromised kernel, or someone who can
  already use your unlocked YubiKey.
- **Header credentials only.** Keys in the URL/query string, OAuth flows with token refresh,
  request signing (e.g. AWS SigV4) and mutual TLS are not supported.
- **HTTP only.** No other protocols (SSH, database connections, …), and no WebSocket or
  HTTP/2 upstream features.
- `mlockall` needs a sufficient `ulimit -l`; if it fails it is silently skipped.
- Prompts and responses pass through the proxy's memory but are never logged.
- If decryption yields none of the expected variables, the proxy exits and logs the variable
  **names** it found (never values) to `~/.cache/keyveil.log`.

## Development

```bash
uv sync                                          # create the venv
uv run python -m unittest discover -s tests -v   # offline tests (fake upstream, no real keys)
uv run keyveil --help
uv tool install .                                # optional: install the `keyveil` command
```

Layout:

```
src/keyveil/proxy.py     the proxy (self-contained, stdlib only)
keyveil.sh               launcher: decrypt → pipe into the proxy; start/stop/status
tests/test_proxy.py      offline tests
.env.example             template for the file you encrypt
routes.example.json      template for custom routes
keyveil.conf.example     launcher settings template
```

## License

[MIT](LICENSE)

[age]: https://github.com/FiloSottile/age
[rage]: https://github.com/str4d/rage
