# keyveil

A tiny program that keeps your **cloud API keys** (OpenAI, Anthropic, DeepSeek, …) away from
the tools that use them. Editors, coding agents and scripts talk to keyveil on your own
computer with a fake key; keyveil swaps in the real key from memory and forwards the request.
The tools never see, store, or inherit the real key.

```
  editor extensions ──┐                           ┌──▶ api.anthropic.com  (x-api-key)
  coding agents     ──┼──(dummy key)──▶ keyveil ──┼──▶ api.openai.com     (Bearer)
  scripts, curl     ──┘                           └──▶ any other API      (Token / header)
                                     127.0.0.1:8787
                                     real keys: RAM only
```

Your keys stay encrypted on disk (a passphrase-protected file, or a hardware key such as a
YubiKey). They are decrypted once when you start keyveil, passed straight into the program's
memory, and never written to disk in plain text — not even to `/run/user` or `/tmp`.

**Contents:** [Is this for you?](#is-this-for-you) ·
[Quick start](#quick-start) · [Words used here](#words-used-here) ·
[How it works](#how-it-works) · [Setup with a hardware key](#setup-with-a-hardware-key) ·
[Usage](#usage) · [Point your tools at it](#point-your-tools-at-it) ·
[Confine your agents](#confine-your-agents-keyveil-sandbox) ·
[Troubleshooting](#troubleshooting) · [Threat model](#threat-model) ·
[Limitations](#limitations) · [Development](#development)

## Is this for you?

keyveil protects **keys for cloud services**. Two cases:

- **You only run models locally** (Ollama, llama.cpp, LM Studio, vLLM…) and they need no key:
  there is nothing to protect, and you don't need keyveil. Tools talk to your local model
  directly; keyveil only handles requests you point at it.
- **You also use paid cloud APIs** from tools like Cline, Continue, Claude Code, Aider or your
  own scripts, or you put a key in front of your own server (LiteLLM, vLLM behind auth…):
  this is what keyveil is for. A tool that is tricked by a malicious web page, README or
  dependency (a "prompt injection") can't leak a key it never had.

It works on **Linux** (tested on Ubuntu 22.04). macOS and Windows are not supported.

## Quick start

About 10 minutes on Ubuntu or Debian. This path uses a **passphrase** you choose; no special
hardware needed. (If you have a YubiKey, see [Setup with a hardware key](#setup-with-a-hardware-key)
instead of steps 4–5.)

**Terminal basics, if you need them:**
- Open a terminal with <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>T</kbd>. Each grey box below is a
  command: type or paste it, then press <kbd>Enter</kbd>. Lines starting with `#` are
  comments; don't type them.
- `~` means your home folder (like `/home/yourname`).
- `sudo` asks for your password. Nothing appears on screen while you type it; that is normal.
- To edit a text file, run `nano <file>`, type, press <kbd>Ctrl</kbd>+<kbd>O</kbd> then
  <kbd>Enter</kbd> to save, and <kbd>Ctrl</kbd>+<kbd>X</kbd> to quit.

**Step 1 — install `uv`** (a tool that installs Python programs; it also fetches the right
Python version for you):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Close the terminal and open a new one, then check it works: `uv --version`.

**Step 2 — download and install keyveil** (needs `git`; if missing: `sudo apt install git`):

```bash
git clone <URL of this repository> keyveil
cd keyveil
uv tool install .
keyveil --version
```

If it says `keyveil: command not found`, run `uv tool update-shell` and open a new terminal.
To update later: `cd keyveil && git pull && uv tool install --force .`

**Step 3 — install `age`** (the encryption tool):

```bash
sudo apt install age
```

**Step 4 — put your API keys in an encrypted file.** First write them in a temporary file in
`/dev/shm`, a folder that lives in memory instead of on your disk:

```bash
nano /dev/shm/keys.env
```

Type one line per key, using **exactly** these names (keyveil recognises keys by name):

| Service | Name to use |
|---|---|
| Anthropic | `ANTHROPIC_API_KEY` |
| OpenAI | `OPENAI_API_KEY` |
| DeepSeek | `DEEPSEEK_API_KEY` |

```
ANTHROPIC_API_KEY=sk-ant-paste-your-key-here
OPENAI_API_KEY=sk-paste-your-key-here
```

Save and quit nano, then encrypt the file and delete the plain-text copy:

```bash
mkdir -p ~/.config/keyveil
age -p -o ~/.config/keyveil/env.age /dev/shm/keys.env
shred -u /dev/shm/keys.env
```

`age` asks for a passphrase twice (nothing shows while you type). **Pick a long one you will
remember: without it the keys cannot be recovered.**

**Step 5 — tell keyveil how to unlock the file.** Create its settings file and edit it:

```bash
keyveil init
nano ~/.config/keyveil/config.toml
```

Add these two lines at the very end of the file, then save:

```toml
[decrypt]
command = 'age -d "$HOME/.config/keyveil/env.age"'
```

**Step 6 — start it:**

```bash
keyveil start
```

Type your passphrase when asked. You should see `ok — keyveil on 127.0.0.1:8787`. It now runs
in the background. (After a reboot, run `keyveil start` again.) Useful: `keyveil status`,
`keyveil stop`.

**Step 7 — point a tool at it.** For example Claude Code, for one session:

```bash
claude --settings '{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8787/anthropic","ANTHROPIC_AUTH_TOKEN":"local-proxy"}}'
```

`local-proxy` is a made-up placeholder, not a credential. Don't put those two variables in
`~/.claude/settings.json`: they would override your Claude subscription login for every
session ([why, and how to make a short command for this](#claude-code-subscription-or-api-key)).
Settings for Cline, Continue, Python scripts and others are in
[Point your tools at it](#point-your-tools-at-it).

**Step 8 (recommended) — run coding agents confined.** An agent running as you can do
anything you can do. This runs it in a sandbox where it can edit your project and use
keyveil, but can't read your SSH keys, use `sudo`, or change your shell settings
([details](#confine-your-agents-keyveil-sandbox)):

```bash
sudo apt install bubblewrap
cd ~/path/to/your/project
keyveil sandbox -- claude
```

**Changing a key later:**

```bash
age -d -o /dev/shm/keys.env ~/.config/keyveil/env.age      # asks for your passphrase
nano /dev/shm/keys.env                                      # edit, save, quit
age -p -o ~/.config/keyveil/env.age.new /dev/shm/keys.env && mv ~/.config/keyveil/env.age.new ~/.config/keyveil/env.age
shred -u /dev/shm/keys.env
keyveil stop && keyveil start
```

A passphrase protects the file on disk. A hardware key is stronger, because it can't be
copied and every unlock needs a physical touch. Use that if you have one.

Something not working? See [Troubleshooting](#troubleshooting).

## Words used here

| Term | Meaning |
|---|---|
| **API key** | A secret password that lets a program use a paid service (e.g. your Anthropic account). Anyone who has it can spend your money. |
| **Proxy** | A middleman program. Your tool sends its request to keyveil, and keyveil passes it on to the real service. |
| **Dummy (placeholder) key** | A fake key like `local-proxy` that you give to your tools. keyveil ignores it and uses the real one. It is not a secret. |
| **`127.0.0.1` / localhost** | "This computer". keyveil only listens there, so nothing on your network can reach it. |
| **Port (`8787`)** | The "door number" keyveil listens on at `127.0.0.1`. Changeable in the settings file. |
| **Route** | The first part of the address, e.g. `/anthropic/…`, which tells keyveil which service to forward to and which key to use. |
| **Prompt injection** | Malicious instructions hidden in a web page, file or dependency that trick an AI agent into doing something you didn't intend. |
| **Sandbox** | A restricted environment: the program runs on your computer but sees only what you allow. |
| **age / passphrase** | `age` is a small encryption tool. A passphrase is a password you choose to lock the file with. |
| **YubiKey** | A USB security key. The decryption key lives inside it and can't be copied out. |

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
[Limitations](#limitations).

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
  (env.age)          (age, gpg, sops…)   (a pipe, no file)   keeps keys in RAM
                            ▲
                      passphrase, or
                      YubiKey touch
```

For every request afterwards:

```
  your tool ──(dummy key)──────▶ keyveil ──(real key, https)──▶ upstream API
  your tool ◀──(streamed reply)─ keyveil ◀──(reply)──────────── upstream API
```

The details:

- Listens on `127.0.0.1` only, and refuses to start on any non-loopback address. Routes are `/<name>/...` → an upstream API
  (`/openai/v1/chat/completions` → `https://api.openai.com/v1/chat/completions`).
- Clients connect to keyveil over plain `http://` on loopback, which never leaves your machine.
  keyveil always connects to the upstream over `https://`, so the real key only travels
  encrypted. (The one exception is a `http://` upstream on loopback, e.g. a local gateway.)
- Answers only local, non-browser clients: requests whose `Host` isn't `127.0.0.1:<port>` /
  `localhost:<port>`, or that carry browser headers (`Origin`, `Referer`, cross-site
  `Sec-Fetch-Site`), get `403`. This stops web pages you visit (and DNS-rebinding tricks) from using your keys.
- Drops any credential header the client sent and sets the real one.
- Checks request framing strictly: bodies up to 64 MiB (`413` above), chunked uploads
  supported, ambiguous or malformed lengths rejected, `.`/`..` path segments rejected.
- Optional per-route path allowlists and an idle auto-shutdown (see below).
- Streams responses chunk by chunk, so SSE / streaming responses work.
- Verifies upstream TLS certificates.
- Logs only method, path and status — never headers or bodies.
- On Linux it calls `mlockall` (key never swapped to disk) and `prctl(PR_SET_DUMPABLE, 0)`
  (no core dumps; blocks same-user `/proc/<pid>/mem` and `environ` reads). If either fails,
  it says so in the log.
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
file), then restart keyveil. The file holds only env var **names**, never secrets:

```json
{
  "routes": {
    "netbox":  { "upstream": "https://netbox.example.com", "env": "NETBOX_TOKEN", "auth": "token" },
    "gateway": { "upstream": "http://127.0.0.1:4000",      "env": "GATEWAY_KEY",  "auth": "bearer" }
  }
}
```

Put the matching variables (`NETBOX_TOKEN=…`) in the file you encrypt. Then use
`http://127.0.0.1:8787/netbox/api/…` with any dummy token. Upstreams must be `https://`;
plain `http://` is accepted only for loopback (`localhost`, `127.0.0.1`), so a key never
crosses a network in clear. A bad routes file (including a misspelled key) makes the proxy
refuse to start, with a message.

**Plain `http://` to a device on your private network.** A NetBox in a virtual machine on
your own computer, or a lab server, often has no HTTPS. For that case a route can opt in with
`"allow_http": true`:

```json
"netbox": { "upstream": "http://192.168.1.50:8000", "env": "NETBOX_TOKEN", "auth": "token",
            "allow_http": true }
```

It only works for an `http://` upstream given as a **literal private IP address** (`10.x.x.x`,
`172.16–31.x.x`, `192.168.x.x`). Hostnames and public addresses are always refused, because
DNS could point a name somewhere else and the key would cross a network unencrypted. Even with
the opt-in, the key is sent unencrypted from your computer to that address: use it only for
machines you trust and a network nobody else can listen on (a VM on your own computer is the
safest case). `auth` must match the token type: NetBox's older tokens use `token`, but its newer
ones (they start with `nbt_`) need `bearer`.

**Limit what a route can do** with an optional `allow` list of `"METHOD /path"` patterns
(`*` is a wildcard, the query string is ignored, `HEAD` counts as `GET`). Anything else gets
`403`. Without `allow`, every path is permitted. On a route with an `allow` list, paths the
upstream might read differently from the list get `400`: a `;`, `//`, or a percent-encoded
`/`, `\`, `.`, NUL or `%` (`%2f`, `%5c`, `%2e`, `%00`, `%25`) before the query string.

```json
"netbox": { "upstream": "https://netbox.example.com", "env": "NETBOX_TOKEN", "auth": "token",
            "allow": ["GET /api/*"] }
```

This makes a key read-only through the proxy, or limits an LLM key to inference
(`["POST /v1/messages", "GET /v1/models*"]`) so nothing using the proxy can reach account,
file or admin endpoints.

## Requirements

- **Linux.** The memory protections and process checks use Linux features (`/proc`, glibc);
  macOS and Windows are not supported. The author uses Ubuntu 22.04; other distributions are
  untested.
- Python 3.11+ (standard library only, no dependencies). With [uv](https://docs.astral.sh/uv/)
  you don't need to have it: uv downloads a suitable Python on first use.
- Something to decrypt your keys: [age] or [rage] (a passphrase, or a hardware key via
  [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey)), or any command that
  prints `KEY=VALUE` lines — see [Other secret sources](#other-secret-sources)
- Optional: `bubblewrap` and `slirp4netns` for [`keyveil sandbox`](#confine-your-agents-keyveil-sandbox)

## Setup with a hardware key

The Quick start uses a passphrase. With a hardware key (e.g. a YubiKey with
[age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey)) the decryption key can't be
copied off the device and every unlock needs a physical touch, which is the strongest option.
Do Quick start steps 1–3 (install `uv`, keyveil, `age`/[rage]), then:

1. **Create an age identity on the key** (see the age-plugin-yubikey README), or a plain one
   with `rage-keygen`. Note the *recipient* it prints (`age1…`).

2. **Encrypt your keys** to that recipient. Write them in `/dev/shm/keys.env` as in Quick start
   step 4 (use the exact variable names from the table there), then:

   ```bash
   mkdir -p ~/.config/keyveil
   rage -r <your-age-recipient> -o ~/.config/keyveil/env.age /dev/shm/keys.env
   shred -u /dev/shm/keys.env
   ```

3. **Create the config file.** `keyveil init` writes a commented starter to
   `~/.config/keyveil/config.toml`. Add your identity file and the encrypted file:

   ```toml
   [age]
   identity = "~/.config/age/identity.txt"
   file = "~/.config/keyveil/env.age"
   ```

   Other settings: `port` (default 8787), `routes_file`, `idle_timeout`, and `[age] binary`.
   The file is plain TOML that keyveil reads as data; it is never run as a script.

4. `keyveil start`, and touch the key when it blinks.

### Other secret sources

keyveil itself never touches encryption: the proxy just reads `KEY=VALUE` lines on stdin.
`keyveil start` produces them by running a decrypt step, which is age by default but can be any
command. Add a `[decrypt]` section to `config.toml` (or pass `--decrypt-cmd`) with a command
that prints the variables to stdout; it takes priority over `[age]`:

```toml
[decrypt]
command = 'age -d "$HOME/.config/keyveil/env.age"'      # passphrase (the Quick start)
# command = 'gpg -d "$HOME/keys.gpg"'
# command = 'sops -d --output-type dotenv "$HOME/secrets.yaml"'
# command = 'pass show keyveil'     # an entry holding KEY=VALUE lines
# one secret per command: wrap it in the variable name the route expects
# command = 'printf "ANTHROPIC_API_KEY=%s\n" "$(op read op://Private/Anthropic/credential)"'
# command = 'printf "OPENAI_API_KEY=%s\n" "$(secret-tool lookup service openai)"'
```

The command runs with `/bin/sh`. Only its output is captured; stdin and stderr stay on your
terminal, so hardware-key and passphrase prompts work. The author has tried age with a
passphrase and rage with a YubiKey; the others are plausible examples, not tested recipes.
Without a config file, the same idea works by pipe: `<any command> | keyveil run --stdin`.

Which source is best depends on what you are defending against. Roughly:

| Source | Good for | Watch out for |
|---|---|---|
| **age + hardware key** | Solo use; touch per unlock | You manage the identity and the file |
| **age + passphrase** | Simple, no hardware | Only as strong as the passphrase |
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
keyveil start     # unlock (passphrase or key touch); prints "ok" when listening
keyveil status    # exit code 0 if running, 3 if not
keyveil stop      # the keys vanish with the process; it does not survive a reboot
keyveil run       # same as start, but in the foreground (Ctrl-C to stop)
keyveil sandbox -- claude   # run an agent confined (see "Confine your agents")
```

`--config FILE` and `--port N` work with every command (handy for a second instance). To
have the proxy stop by itself when unused, set `idle_timeout = <minutes>` in `config.toml`
(requests in progress are never cut off).

Check it (the credential you send is ignored and replaced):

```bash
curl -s http://127.0.0.1:8787/<route>/<path> -H 'Authorization: Bearer anything'
# e.g. list models on an OpenAI-compatible route:
curl -s http://127.0.0.1:8787/openai/v1/models -H 'Authorization: Bearer anything'
```

Without a config file, pipe the decrypted text in yourself:

```bash
rage -d -i identity.txt env.age | keyveil run --stdin --port 8787
```

**Where things live:**

| What | Where |
|---|---|
| Settings | `~/.config/keyveil/config.toml` |
| Your encrypted keys (Quick start) | `~/.config/keyveil/env.age` |
| Extra routes (optional) | `~/.config/keyveil/routes.json` |
| Log (never contains keys or prompts) | `~/.local/state/keyveil/keyveil.log` |
| "Is it running" marker (just a process number) | `/run/user/<your id>/keyveil/<port>.pid` |

### Point your tools at it

Use any non-empty dummy key (e.g. `local-proxy`) — it is not a credential. The pattern is always
the same: base URL `http://127.0.0.1:8787/<route>/…`, dummy key.

**Claude Code:** see [Claude Code: subscription or API key](#claude-code-subscription-or-api-key)
below. (It needs `ANTHROPIC_API_KEY` in the encrypted file; keep that name there.)

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

### Claude Code: subscription or API key

Claude Code can authenticate in two ways, and uses only one at a time:

| Mode | How you start it | Billing | Uses keyveil? |
|---|---|---|---|
| **Subscription** (claude.ai login) | plain `claude` | your Claude plan | no |
| **API key through keyveil** | `claude --settings '…'` (below) | Anthropic API, pay per use | yes |

**Why they can't both be "on".** Claude Code uses the first credential it finds, in this order:
a cloud-provider setting, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY`, `apiKeyHelper`,
`CLAUDE_CODE_OAUTH_TOKEN`, and only then your saved login. The placeholder token that keyveil
mode needs (`ANTHROPIC_AUTH_TOKEN`) therefore outranks your subscription, and Claude prints
*"claude.ai connectors are disabled because ANTHROPIC_API_KEY or another auth source is set…"*.
So **don't put the proxy variables in `~/.claude/settings.json` or your shell profile**: give
them only to the sessions that should use keyveil. Your saved login stays on disk and works
again as soon as those variables are absent.

**Log in with your subscription** (once, in a normal terminal): `claude auth login`, or
`/login` inside Claude. A browser opens; if there is none (a server, SSH), press `c` to copy
the link, open it on another device, and paste the code back. `claude auth status --text`
shows which credential is active.

**Use keyveil for one session:**

```bash
claude --settings '{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8787/anthropic","ANTHROPIC_AUTH_TOKEN":"local-proxy"}}'
```

`--settings` outranks your user settings file and applies to that session only. **Always set
both variables, never just one:** with only the base URL set, Claude would send your
subscription token to keyveil, which replaces it with the API key, so you would be billed on
the API without noticing. In this mode `claude` fails with "connection refused" whenever
keyveil isn't running.

**Short commands.** Add these to `~/.bashrc`, then open a new terminal:

```bash
claude-proxy()     { claude --settings '{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8787/anthropic","ANTHROPIC_AUTH_TOKEN":"local-proxy"}}' "$@"; }
claude-box()       { keyveil sandbox -- claude "$@"; }
claude-proxy-box() { keyveil sandbox --hide "$HOME/.claude/.credentials.json" -- claude --settings '{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8787/anthropic","ANTHROPIC_AUTH_TOKEN":"local-proxy"}}' "$@"; }
```

| Command | Auth | Confined? |
|---|---|---|
| `claude` | subscription | no |
| `claude-box` | subscription | yes ([sandbox](#confine-your-agents-keyveil-sandbox)) |
| `claude-proxy` | API key via keyveil | no |
| `claude-proxy-box` | API key via keyveil | yes, and your subscription login file is hidden from the agent |

**Heads-up: keyveil does not protect your subscription login.** Claude Code stores it as a
plain token in `~/.claude/.credentials.json` (readable only by you, but by any program running
as you). A confined agent in `claude-box` can read it too, because Claude needs its own folder.
In `claude-proxy-box` that file is hidden, since the agent doesn't need it. For agents you
trust less, prefer the keyveil modes.

Also: values in a settings file's `env` block override variables set in your shell. If you
have an alias that sets its own `ANTHROPIC_BASE_URL` (say, for another gateway), pass it with
`--settings` too.

## Confine your agents: `keyveil sandbox`

Editors and agents run as **you**. If an agent is tricked by a prompt injection (a malicious
README, issue, web page or dependency), it can do anything you can: edit `~/.bashrc` or the
code your next unlock runs, use `sudo` if it doesn't need a password, or use Docker
(membership in the `docker`, `lxd` or `libvirt` groups is root-equivalent). Root can read
any process's memory, including keyveil's.

`keyveil sandbox` runs an agent under [bubblewrap](https://github.com/containers/bubblewrap)
(the sandbox Flatpak uses; no root or Docker needed) so those paths are closed while
everything else keeps working:

```
  Normal terminal                                  Sandbox: keyveil sandbox -- claude
  ┌───────────────────────────────┐                ┌────────────────────────────────┐
  │ keyveil: holds the real keys  │                │ the agent (claude, aider, …)   │
  │ your SSH keys and passwords   │◀───────────────│ can edit:  the project folder  │
  │ sudo, Docker                  │  127.0.0.1     │ can use:   keyveil, internet   │
  │ your shell settings           │     :8787      │ can't see: keys, SSH, sudo,    │
  └───────────────────────────────┘                │            Docker, shell setup │
                                                   └────────────────────────────────┘
```

### How to use it

1. Start keyveil in a **normal** terminal: `keyveil start`.
2. Go into the folder of the project you want the agent to work on, then start the agent
   through the sandbox:

   ```bash
   cd ~/projects/my-app
   keyveil sandbox -- claude
   ```

   Everything after the `--` is the command to run, with its own options if it has any
   (`keyveil sandbox -- claude --resume`). Any agent works: `aider`, `codex`, a shell
   (`keyveil sandbox -- bash`) to look around.
3. To check you are inside, run `touch ~/.bashrc` in the agent's terminal. Inside the
   sandbox it fails with "Read-only file system"; outside, it succeeds silently.

### Rules of thumb

- **Start every agent session this way.** An agent started the normal way is not confined.
- **Run `keyveil start`, `stop` and `status` in a normal terminal.** Inside the sandbox
  keyveil's own files are hidden on purpose, so the command isn't available there.
- **Start it from inside the project folder**, never from your home folder (keyveil refuses).
  The agent can change everything in that folder, so keep secrets out of it.
- **Anything outside the project is read-only** for the agent: it can't edit other projects,
  `~/.bashrc` or installed programs, and global installs (`pip install --user`, `npm -g`)
  fail. Use a project-local virtual environment instead.
- **`sudo` and Docker don't work inside.** Run those yourself in a normal terminal.
- **Tool caches start empty** (`~/.cache` is private), so the first run may re-download
  things. To keep one, allow it: `keyveil sandbox --rw ~/.cache/pip -- claude`.
- **`git push` over SSH is blocked** because your SSH keys are hidden. Either push from a
  normal terminal, or add `--ssh-agent` for that session (it lets the agent use your SSH
  identities, so only do it when you need it).
- **Change Claude Code's settings, plugins and MCP servers in a normal session.** Inside the
  sandbox `/config`, `/model` (when it saves a default), installing or updating plugins, and
  editing `~/.claude/CLAUDE.md` can't be saved, since those files are read-only.
- **The agent can commit, but not change git's settings.** Hooks and `.git/config` are
  read-only, so `git branch -d`, `git remote add` or `git config` inside the sandbox fail
  or warn; run those in a normal terminal. Folders that contain a git repository (and the
  `.git` folders themselves) can't be renamed or deleted while the agent runs.
- **Secret-looking environment variables are removed** (`*_KEY`, `*_TOKEN`, `*_PAT`,
  `*_PASSWORD`, `DATABASE_URL`, `*_DSN`, `AWS_*`, …, in any letter case);
  the names are printed when it starts. If a tool really needs one, add `--keep-env NAME`.

### What is inside and what isn't

| Inside the sandbox | |
|---|---|
| The project directory | read-write, except what git runs later, outside: in every repository in it, the hooks, config (and files it includes or a `core.hooksPath` inside the project) are read-only, and `.git` folders can't be moved or replaced. After the agent exits, keyveil checks them again (see below) |
| Claude Code's state (`~/.claude`, `~/.claude.json`) | read-write (this includes your subscription login file unless you `--hide` it), except what makes Claude Code run something later, outside: `settings.json`, `CLAUDE.md`, `plugins`, `commands`, `agents`, `skills`, `hooks`, `output-styles`, `rules` and scripts directly in `~/.claude` are read-only. `backups`, `shell-snapshots`, `session-env` and `downloads` are private, empty copies. Security settings in `~/.claude.json` and the project's `.claude/settings*.json` and `.mcp.json` are checked after exit (see below) |
| The rest of the filesystem | read-only: your tools work, but `~/.bashrc`, PATH, keyveil's install and config can't be changed |
| `/run`, `/tmp`, `~/.cache` | private and empty: no Docker/LXD/libvirt/ssh-agent/keyring sockets |
| `~/.ssh`, `~/.gnupg`, cloud CLI credentials (`aws`, `gcloud`, `az`, `kubectl`, `gh`, `doctl`, `op`, `rclone`, …), package-registry tokens (`~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials`, Maven, Gradle), `~/.vault-token`, `~/.terraform.d`, browser and Thunderbird profiles, shell and REPL history, keyveil's config, your encrypted key file and identity | hidden. The list can't cover every tool: `--hide PATH` adds more |
| `sudo`, `su`, setuid programs | can't gain privileges (`no_new_privs`) |
| Other processes (including keyveil) | invisible (own PID namespace) |
| Environment variables that look like secrets | removed; the names are printed |
| Network | its own: the internet works (through `slirp4netns`), and keyveil is at the usual `127.0.0.1:<port>`; nothing else on your `127.0.0.1`, and no abstract Unix sockets (your X11 display, D-Bus, input methods), so `DISPLAY`, `WAYLAND_DISPLAY`, `XAUTHORITY` and `DBUS_SESSION_BUS_ADDRESS` are cleared and `~/.Xauthority` is hidden. Services on your other addresses (e.g. your LAN IP) are still reachable |

Options: `--network isolated|none|host` (or `[sandbox] network = ...`; see below),
`--project DIR`, `--rw PATH` / `--hide PATH` (or `[sandbox] rw = [...]`, `hide = [...]`
in `config.toml`), `--keep-env NAME` (keep one variable the sandbox would otherwise remove), `--ssh-agent`,
and `--dry-run` to print the exact `bwrap` command without running it. `--hide` also works on
a single file inside a writable folder, e.g. `--hide ~/.claude/.credentials.json`. It refuses
to make anything writable (the project or a `--rw` path) that is your home directory, contains
a hidden path or keyveil's own files, or contains files that run code later outside the
sandbox (`~/.bashrc`, `~/.local/bin`, `~/.config/systemd`, …): e.g. `--rw ~/.config` is
refused, `--rw ~/.config/some-tool` is fine. Shortcuts for Claude Code are in
[Claude Code: subscription or API key](#claude-code-subscription-or-api-key).

It doesn't cover:
- **Editor extensions** (Cline, Continue…): they run inside the editor's own process, so
  confining them means running the editor's agent side in a container (e.g. VS Code Dev
  Containers). Not supported by keyveil yet.
- **Using the proxy**: a confined agent can still make API calls with your keys. That is the
  point, but see path allowlists above to limit what it can call.
- **Sending your project's files somewhere**: the agent has network access.
- **Kernel exploits** that escape Linux namespaces.

**Claude Code settings check after exit.** keyveil records the security settings in
`~/.claude.json`, the project's `.claude/settings.json`, `.claude/settings.local.json` and
`.mcp.json` before the agent starts: MCP servers, hooks, permissions and allowed tools,
project trust, `env`, `apiKeyHelper`, the status line, plugins. If any of them changed when
the agent exits, it lists the changes and asks `Restore the settings from before the session?
[Y/n]`. Restoring puts back only those settings and keeps everything else Claude Code wrote.
If you approved something yourself during the session (trusting a new folder, "always allow"
for a tool), answer `n`. Without a terminal it only prints and logs the changes.

**Optional: an early warning when an agent tries.** `contrib/claude-guard-hook.py` is a
Claude Code `PreToolUse` hook that refuses Edit/Write/NotebookEdit calls on those files, and
Bash commands that name them, so the agent is told no at once (sandboxed or not). It is not
a boundary: it can't see what a script or program started by the agent does. Install it
root-owned so the agent can't change it, and register it in managed settings:

```bash
sudo install -D -m 755 -o root contrib/claude-guard-hook.py /usr/local/lib/keyveil/claude-guard-hook.py
sudo mkdir -p /etc/claude-code
sudo tee /etc/claude-code/managed-settings.json <<'EOF'
{"hooks": {"PreToolUse": [{"matcher": "Edit|Write|MultiEdit|NotebookEdit|Bash", "hooks": [
  {"type": "command", "command": "/usr/bin/python3 -I /usr/local/lib/keyveil/claude-guard-hook.py"}]}]}}
EOF
```

If that file already exists, merge the `hooks` entry into it instead. Adding
`"allowManagedHooksOnly": true` also stops hooks from user, project and plugin settings,
and makes Claude Code read the status line only from managed settings. That's stronger, but
your own hooks and status line stop working.

**Git check after exit.** When the agent exits, keyveil looks at the git repositories in
the project (and `--rw` paths) again:
- a `commondir` or `config.worktree` file that appeared in an existing `.git` folder (it
  would make git read another folder's config and hooks) is moved into
  `.git/keyveil-quarantine-<time>/`;
- new repositories, submodules and worktrees are listed, with any hooks or config settings
  in them that run a program (`core.fsmonitor`, `core.pager`, `alias.x = !…`, filters, …).

The findings are printed and added to `~/.local/state/keyveil/keyveil.log`. A new repository
isn't removed (the agent may have made it for you), so check the listed hooks and settings
before you run git in it. Folders named `node_modules`, `.venv`, `venv` and the like are
not searched.

**Network modes.** `isolated` (the default) gives the agent its own network namespace with
internet access through `slirp4netns` and a relay to the keyveil proxy. `none` keeps only the
relay: the agent can use keyveil but nothing else (no internet, so a Claude subscription login
won't work). `host` shares your network as earlier versions did. Avoid it: the agent can then
reach every service on your `127.0.0.1` and your X11 display, through which it can type into
your other windows. A `--network host` session prints a warning.

Requires `bwrap` and `slirp4netns` (Ubuntu/Debian: `sudo apt install bubblewrap slirp4netns`)
and unprivileged user namespaces (default on most distributions). `--network none` doesn't
need `slirp4netns`.

## Troubleshooting

| What you see | Why | What to do |
|---|---|---|
| Claude Code says *"claude.ai connectors are disabled because ANTHROPIC_API_KEY or another auth source is set…"* | The keyveil placeholder token (`ANTHROPIC_AUTH_TOKEN`) is set globally and outranks your subscription login | Remove the `ANTHROPIC_*` variables from `~/.claude/settings.json` and your shell profile; use them per session only ([how](#claude-code-subscription-or-api-key)) |
| `keyveil: command not found` | The terminal doesn't know where `uv` installed it, or you are inside the sandbox (where it is hidden on purpose) | Run `uv tool update-shell` and open a new terminal. In the sandbox, use a normal terminal for keyveil commands |
| A tool says "connection refused" | keyveil isn't running (it doesn't survive a reboot) | `keyveil status`, then `keyveil start` |
| `keyveil: port 8787 is already in use by another process` | Another program uses that port | Set a different `port = 8788` in `config.toml` (and in your tools' base URL), or stop the other program |
| `keyveil: decryption failed` | Wrong passphrase, wrong identity file, or the YubiKey wasn't touched in time | Run `keyveil start` again and retry |
| `keyveil: no key source configured` | `config.toml` has neither a `[decrypt]` nor an `[age]` section | Quick start step 5 |
| `keyveil: encrypted file not found` | The `[age] file` path is wrong | Fix the path in `config.toml` |
| `keyveil: failed to start: no usable keys on stdin. wanted=[…] found_names=[…]` | The names in your encrypted file don't match what the routes expect (it prints the names it found, never the values) | Use the exact names from the [table](#how-it-works), e.g. `ANTHROPIC_API_KEY`; see "Changing a key later" |
| The provider says "invalid API key" (401) | The key inside your encrypted file is wrong or expired | "Changing a key later" in the Quick start |
| `404 unknown route` | The first part of the address isn't a route, or that route's key isn't in the file | Check the spelling (`/anthropic/…`) and that its variable is in the file |
| `403 forbidden: only local, non-browser clients` | The request came from a browser, or used an address other than `127.0.0.1:<port>` / `localhost:<port>` (including from inside a container) | Point your tool at exactly `http://127.0.0.1:8787` |
| `400 ambiguous path for a route with an allow list` | The path has `;`, `//` or an encoded `/`, `\`, `.`, NUL or `%` | Send the plain path; if the API really needs one of these, remove that route's `allow` list |
| `keyveil: refusing to listen on …` | `--host` was not a loopback address | Leave it at `127.0.0.1`; the proxy is only for programs on this machine |
| `403 path not allowed for this route` | The route has an `allow` list that doesn't include this request | Adjust the route's `allow` list |
| `keyveil: bubblewrap is not installed` | `bwrap` is missing | `sudo apt install bubblewrap` |
| `keyveil: slirp4netns is not installed` | The default `isolated` network mode needs it | `sudo apt install slirp4netns`, or use `--network none` (only the keyveil proxy, no internet) |
| `keyveil: /dev/net/tun is missing` | You are inside a container or another sandbox without the tun device | Use `--network none` there, or run keyveil sandbox on the host |
| `keyveil: bubblewrap cannot create a sandbox here` | Your system restricts unprivileged user namespaces (for example Ubuntu 24.04's AppArmor setting `kernel.apparmor_restrict_unprivileged_userns`; not tested by the author) | See your distribution's documentation for allowing `bwrap` |
| `keyveil: config file … can be changed by other users` (or `routes file`, `encrypted key file`) | keyveil runs what that file says (or decrypts it) when you unlock, so it only trusts files that just you can change | Run the `chmod` (or `chown`) the message suggests. Group-writable is fine when the group is your own private group (the Ubuntu default) |
| `keyveil: refusing to make /home/you writable` | You started the sandbox from your home folder | `cd` into the project folder first |
| `keyveil: refusing to make … writable …: it contains …` | A `--rw` path (or the project) would expose a hidden or protected path inside it | Pick a narrower directory, e.g. `~/.config/some-tool` instead of `~/.config` |
| `keyveil sandbox: git repositories changed by the agent (check before using git)` | After exit, keyveil found a new repository, submodule or worktree, or moved aside a file that redirects git ([details](#what-is-inside-and-what-isnt)) | Look at the listed hooks and settings; if the agent didn't need that repository, delete it |
| `mv`/`rm` of a folder fails with "Device or resource busy" inside the sandbox | The folder contains a git repository or a hidden file, so it is pinned in place | Do it in a normal terminal |
| Copying from Claude Code (or `xclip`/`xsel`) inside the sandbox does nothing | The sandbox can't reach your display: whatever can use the clipboard can also type into your other windows | Select with the mouse while holding Shift, then Ctrl+Shift+C (your terminal copies it, outside the sandbox) |
| `keyveil: slirp4netns could not set up the sandbox network (…)` | slirp4netns couldn't join the sandbox (keyveil retries a few times first); the agent is not started | Check the message, `ls -l /dev/net/tun`, and that `slirp4netns --version` works |
| A tool inside the sandbox can't find a file | That folder is hidden or read-only | Allow it with `--rw PATH` (writable) — see [Rules of thumb](#rules-of-thumb) |

The log (`~/.local/state/keyveil/keyveil.log`) shows each request's method, path and status,
which helps tell "keyveil refused it" (403/404) from "the provider refused it" (401/429).

## Threat model

What keyveil protects, assuming an agent on your machine gets prompt-injected:

| Threat | Without keyveil | keyveil alone | keyveil + `keyveil sandbox` |
|---|---|---|---|
| Key leaked from disk (backups, sync, git, an extension's config file) | exposed | **protected** | **protected** |
| Agent reads the key from a file or the environment into its context, logs or chat | exposed (`printenv`, `cat .env`) | **protected** | **protected** |
| Agent becomes root (passwordless sudo, docker group) and reads keyveil's memory | exposed | exposed | **protected** |
| Agent edits what runs at your next unlock (config, PATH, shell rc, installed code) | n/a | exposed | **protected** |
| A web page in your browser uses the proxy | n/a | **blocked** (Host/Origin check) | **blocked** |
| Any local program spends your key while the proxy runs | exposed | limited (allowlists, idle shutdown) | limited |
| Agent reaches your desktop (X11 keystroke injection), D-Bus or other local services | n/a | exposed | **protected** (own network namespace) |
| Agent takes over the proxy's port to answer your other tools | n/a | exposed | **protected** for sandboxed agents; unsandboxed programs still can |

Also worth doing, outside keyveil:
- **Require a password for `sudo`** (remove `NOPASSWD` rules; edit with `sudo visudo`).
- **Treat `docker`, `lxd` and `libvirt` group membership as root.** The sandbox hides their
  sockets, but non-sandboxed programs can still use them.
- Don't run `sudo` scripts that live in directories you (or an agent) can write, e.g.
  `~/.local/bin`; install them root-owned in `/usr/local/sbin`.

## Limitations

- **Anyone can listen on the proxy's port when keyveil isn't running.** A program running
  as you (outside the sandbox) could bind `127.0.0.1:8787` after `keyveil stop` or an idle
  shutdown and receive what your tools send: prompts and code, but never your keys.
- **Claude Code sessions running at the same time.** A Claude Code session you start outside
  the sandbox while the agent is running reads `~/.claude.json` and the project's
  `.claude/settings.local.json` as they are, before keyveil's check after exit. Some of
  Claude Code's other writable files (session transcripts in `~/.claude/projects`, rewind
  history in `~/.claude/file-history`) can be edited by the agent and are not checked.
- **Git while the agent is still running.** The check after exit can't help if you run git
  in the project from another terminal while the agent is working: a new repository the
  agent just made could run its hooks then. Git in repositories that existed before the
  sandbox started is safe, since their hooks and config are read-only.
- **No client authentication.** Any local, non-browser program can make requests through the
  proxy while it is up — it just can't read the key. Stop it when you're not using it (or set
  `idle_timeout`), use `allow` lists for sensitive routes, and keep the default bind address of
  `127.0.0.1`.
- It does **not** protect against root (unless agents are sandboxed), a compromised kernel, or
  someone who can already use your unlocked key or know your passphrase.
- **Header credentials only.** Keys in the URL/query string, OAuth flows with token refresh,
  request signing (e.g. AWS SigV4) and mutual TLS are not supported.
- **HTTP(S) only.** No other protocols (SSH, database connections, …), and no WebSocket or
  HTTP/2 upstream features.
- **Tampering.** Outside the sandbox, a program running as you could edit what runs when you
  unlock: the config file (its `[decrypt] command` is run with `/bin/sh`), the installed
  package, or your shell aliases and PATH. Your passphrase or key touch authorizes whatever is
  there at that moment, so be suspicious of an unlock prompt you didn't trigger.
- `mlockall` needs a sufficient `ulimit -l`. If it fails, the proxy still runs and writes
  `keyveil: warning: memory not locked …` to the log; raise the limit (e.g. `memlock` in
  `/etc/security/limits.conf`) to fix it.
- Prompts and responses pass through the proxy's memory but are never logged.
- If decryption yields none of the expected variables, the proxy exits and logs the variable
  **names** it found (never values) to `~/.local/state/keyveil/keyveil.log`.

## Development

```bash
uv sync                                          # create the venv (uv fetches Python 3.11+)
uv run ruff check && uv run ruff format --check  # lint
uv run python -m unittest discover -s tests -v   # offline tests: no YubiKey, network or real keys
uv run --python 3.11 python -m unittest discover -s tests   # also try the oldest supported Python
./scripts/smoke-install.sh                       # build the wheel, install it, drive the real command
uv run keyveil --help
```

CI runs the same lint and tests on every push and pull request; merges to `main` are released
automatically from [Conventional Commit](https://www.conventionalcommits.org/) PR titles
(`feat:` → minor, `fix:` → patch). See [CONTRIBUTING.md](CONTRIBUTING.md) for how releases
work and [SECURITY.md](SECURITY.md) to report a vulnerability.

The tests run `keyveil` in a sandbox with its own `HOME`, config and port, so they never touch
your real setup or a running proxy.

Layout:

```
src/keyveil/cli.py       the `keyveil` command: init, start, stop, status, run, sandbox
src/keyveil/config.py    config file (TOML) loading and XDG paths
src/keyveil/proxy.py     the proxy (self-contained, stdlib only)
src/keyveil/sandbox.py   builds the bubblewrap command for `keyveil sandbox`
src/keyveil/bridge.py    the proxy relay inside the sandbox's own network
src/keyveil/agentstate.py  Claude Code's files: read-only list, settings check after exit
contrib/                 claude-guard-hook.py: optional Claude Code hook (early warning)
tests/                   offline tests: proxy, hardening, config, CLI, sandbox (live tests
                         skip themselves if bubblewrap can't run)
scripts/smoke-install.sh packaging smoke test (builds and installs the wheel)
scripts/check-dist.py    checks built wheel/sdist contents before publishing
.github/workflows/       CI (lint, tests), PR-title check, release pipeline
config.example.toml      the config template (same as `keyveil init` writes)
routes.example.json      template for custom routes
.env.example             template for the file you encrypt
```

## License

[MIT](LICENSE)

[age]: https://github.com/FiloSottile/age
[rage]: https://github.com/str4d/rage
