# keyveil

A tiny localhost reverse proxy that adds your **API credentials to HTTP requests from
memory**, so the tools making those requests — editors, coding agents, scripts, SDKs —
never see, store, or inherit the real key.

```
  editor extensions ──┐                           ┌──▶ api.anthropic.com  (x-api-key)
  coding agents     ──┼──(dummy key)──▶ keyveil ──┼──▶ api.openai.com     (Bearer)
  scripts, curl     ──┘                           └──▶ any other API      (Token / header)
                                     127.0.0.1:8787
                                     real keys: RAM only
```

Keys stay encrypted at rest (by default an `.env.age` file decrypted with [age]/[rage],
ideally with a hardware key such as a YubiKey; any other decrypt command works too, see
[Other secret sources](#other-secret-sources)). They are decrypted once, piped straight into
the proxy's stdin, and never touch the disk — not even `/run/user` or `/tmp`.

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

It is **not** a fit for anything that is not an HTTP(S) API with a static header credential; see
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

At start, once (this is the only moment you unlock anything):

```
  encrypted file ──▶ decrypt command ──▶ KEY=VALUE text ──▶ keyveil process
  (.env.age)         (age, gpg, sops…)   (a pipe, no file)   keeps keys in RAM
                            ▲
                      YubiKey touch
                      or passphrase
```

For every request afterwards:

```
  your tool ──(dummy key)──────▶ keyveil ──(real key, https)──▶ upstream API
  your tool ◀──(streamed reply)─ keyveil ◀──(reply)──────────── upstream API
```

The details:

- Listens on `127.0.0.1` only. Routes are `/<name>/...` → an upstream API
  (`/openai/v1/chat/completions` → `https://api.openai.com/v1/chat/completions`).
- Clients connect to keyveil over plain `http://` on loopback, which never leaves your machine.
  keyveil always connects to the upstream over `https://`, so the real key only travels
  encrypted. (The one exception is a `http://` upstream on loopback, e.g. a local gateway.)
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

### Compatibility

keyveil works with any API key that is sent in an HTTP request header. It never inspects the
request or the key, so there is no per-provider logic: a provider works if its route has the
right upstream, variable name and auth style.

Test coverage: every auth style and the routing logic are covered by offline tests against a
local fake upstream. The author has also run it against the real DeepSeek and Anthropic APIs
(including streaming). Other providers use the same code path but haven't been tried by the
author; if one doesn't work, please open an issue.

### Auth styles

| `auth` value      | Header keyveil sets               | Typical use                         |
|-------------------|-----------------------------------|-------------------------------------|
| `bearer` (default)| `Authorization: Bearer <key>`     | OpenAI-compatible APIs, most SaaS   |
| `token`           | `Authorization: Token <key>`      | NetBox, Django REST Framework APIs  |
| `x-api-key`       | `x-api-key: <key>`                | Anthropic                           |
| `header:<Name>`   | `<Name>: <key>`                   | Any custom header, e.g. `header:X-Auth-Token` |

### Custom routes

Add services without touching the code. Copy [`routes.example.json`](routes.example.json) to
`~/.config/keyveil/routes.json` (picked up automatically; or set `routes_file` in the config
file). The file holds only env var **names**, never secrets:

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

- **Linux.** The memory protections and process checks use Linux features (`/proc`, glibc);
  macOS and Windows are not supported.
- Python 3.11+ (standard library only, no dependencies). With [uv](https://docs.astral.sh/uv/)
  you don't need to have it: uv downloads a suitable Python on first use.
- Something to decrypt your keys: [age] or [rage] by default (for hardware-backed keys,
  [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey)), or any command that prints
  `KEY=VALUE` lines — see [Other secret sources](#other-secret-sources)

## Setup

1. **Install** (from a clone of this repository for now):

   ```bash
   uv tool install .
   ```

   This puts a `keyveil` command on your PATH (run `uv tool update-shell` if `~/.local/bin`
   isn't on it) and uses its own isolated environment. If your system Python is older than 3.11,
   uv fetches a newer one by itself. With pipx instead: `pipx install --python python3.11 .`

2. **Create an age identity** (a YubiKey-backed one is recommended — see the
   age-plugin-yubikey README), or a plain one with `rage-keygen`.

3. **Encrypt your keys.** Copy [`.env.example`](.env.example) to `.env`, fill in the keys
   you need, then encrypt and delete the plaintext:

   ```bash
   rage -r <your-age-recipient> -o .env.age .env && shred -u .env
   ```

   Keep the variable names the routes expect (e.g. `ANTHROPIC_API_KEY`).

4. **Create the config file.** `keyveil init` writes a commented starter to
   `~/.config/keyveil/config.toml`. Set your age identity and the encrypted file:

   ```toml
   [age]
   identity = "~/.config/age/identity.txt"
   file = "~/.config/keyveil/env.age"
   ```

   Other settings: `port` (default 8787), `routes_file`, and `[age] binary`. Not using age?
   See [Other secret sources](#other-secret-sources). The file is plain TOML that keyveil reads
   as data; it is never run as a script.

### Other secret sources

keyveil itself never touches encryption: the proxy just reads `KEY=VALUE` lines on stdin.
`keyveil start` produces them by running a decrypt step, which is age by default but can be any
command. Add a `[decrypt]` section to `config.toml` (or pass `--decrypt-cmd`) with a command
that prints the variables to stdout; it takes priority over `[age]`:

```toml
[decrypt]
command = 'gpg -d "$HOME/keys.gpg"'
# command = 'sops -d --output-type dotenv "$HOME/secrets.yaml"'
# command = 'pass show keyveil'     # an entry holding KEY=VALUE lines
# one secret per command: wrap it in the variable name the route expects
# command = 'printf "ANTHROPIC_API_KEY=%s\n" "$(op read op://Private/Anthropic/credential)"'
# command = 'printf "OPENAI_API_KEY=%s\n" "$(secret-tool lookup service openai)"'
```

The command runs with `/bin/sh`. Only its output is captured; stdin and stderr stay on your
terminal, so hardware-key and passphrase prompts work. Only age/rage has been tried by the
author; the others are plausible examples, not tested recipes. Without a config file, the same
idea works by pipe: `<any command> | keyveil run --stdin`.

Which source is best depends on what you are defending against. Roughly:

| Source | Good for | Watch out for |
|---|---|---|
| **age + hardware key** (default) | Solo use; touch per unlock | You manage the identity and the file |
| **gpg** (smartcard) | You already use it | `gpg-agent` may cache the unlock, so a program can decrypt without a prompt |
| **sops** | Teams, secrets in git | A wrapper over age/gpg/KMS; output must be dotenv |
| **TPM / `systemd-creds`** | Servers, unattended boot | Tied to the machine, no touch step |
| **OS keyring**, **password manager CLI** | Convenience | Often unlocked at login, so any program running as you can read it |
| **Vault / cloud secret manager** | Teams, rotation, audit | A server to run; overkill for one person |

Prefer a source that needs a deliberate action each time you unlock (a hardware-key touch, a
passphrase, a biometric prompt). Then an agent running as you cannot silently re-decrypt your
keys, and you notice if something tries. Avoid commands that put the secret itself in a
process's arguments (visible in `ps`).

## Usage

```bash
keyveil start     # touch your YubiKey; prints "ok" when listening
keyveil status    # exit code 0 if running, 3 if not
keyveil stop      # the keys vanish with the process; it does not survive a reboot
keyveil run       # same as start, but in the foreground (Ctrl-C to stop)
```

`--config FILE` and `--port N` work with every command (handy for a second instance).

Check it (the credential you send is ignored and replaced):

```bash
curl -s http://127.0.0.1:8787/<route>/<path> -H 'Authorization: Bearer anything'
# e.g. list models on an OpenAI-compatible route:
curl -s http://127.0.0.1:8787/openai/v1/models -H 'Authorization: Bearer anything'
```

Without a config file, pipe the decrypted text in yourself:

```bash
rage -d -i identity.txt .env.age | keyveil run --stdin --port 8787
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
- **HTTP(S) only.** No other protocols (SSH, database connections, …), and no WebSocket or
  HTTP/2 upstream features.
- **Tampering.** A program running as you can't read the key from the proxy, but it could edit
  what runs when you unlock: the config file (its `[decrypt] command` is run with `/bin/sh`),
  the installed package, or your shell aliases and PATH. Your hardware-key touch authorizes
  whatever is there at that moment. Keep those files writable only by you, and be suspicious of
  a touch prompt you didn't trigger. Running untrusted agents as a different user or in a
  container closes this gap.
- `mlockall` needs a sufficient `ulimit -l`; if it fails it is silently skipped.
- Prompts and responses pass through the proxy's memory but are never logged.
- If decryption yields none of the expected variables, the proxy exits and logs the variable
  **names** it found (never values) to `~/.local/state/keyveil/keyveil.log`.

## Development

```bash
uv sync                                          # create the venv (uv fetches Python 3.11+)
uv run python -m unittest discover -s tests -v   # offline tests: no YubiKey, network or real keys
uv run --python 3.11 python -m unittest discover -s tests   # also try the oldest supported Python
./scripts/smoke-install.sh                       # build the wheel, install it, drive the real command
uv run keyveil --help
```

The tests run `keyveil` in a sandbox with its own `HOME`, config and port, so they never touch
your real setup or a running proxy.

Layout:

```
src/keyveil/cli.py       the `keyveil` command: init, start, stop, status, run
src/keyveil/config.py    config file (TOML) loading and XDG paths
src/keyveil/proxy.py     the proxy (self-contained, stdlib only)
tests/                   offline tests for the proxy, config and CLI
scripts/smoke-install.sh packaging smoke test (builds and installs the wheel)
config.example.toml      the config template (same as `keyveil init` writes)
routes.example.json      template for custom routes
.env.example             template for the file you encrypt
```

## License

[MIT](LICENSE)

[age]: https://github.com/FiloSottile/age
[rage]: https://github.com/str4d/rage
