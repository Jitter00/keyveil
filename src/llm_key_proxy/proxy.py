#!/usr/bin/env python3
"""llm-key-proxy — localhost reverse proxy that injects API credentials held only in RAM.

Usage:  rage -d -i <identity> env.age | python3 -I proxy.py [--port 8787] [--routes routes.json]

Works for any HTTP API that authenticates with a key/token in a request header
(LLM providers, NetBox, GitHub, self-hosted gateways...). The decrypted
``KEY=VALUE`` env text is read from stdin (never argv, environ or disk). Clients
(editors, agents, SDKs, curl...) talk to ``http://127.0.0.1:<port>/<route>/...``
with any dummy key; the proxy strips it and adds the real one before forwarding
upstream. A route is only enabled if its key is present on stdin.

This file is self-contained (standard library only) so it can be run directly
with ``python3 -I`` as well as through the ``llm-key-proxy`` console script.
"""
import argparse
import ctypes
import http.client
import json
import re
import signal
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

# route prefix -> (upstream base URL, env var holding the key, auth style)
# auth styles:
#   "bearer"        -> Authorization: Bearer <key>
#   "token"         -> Authorization: Token <key>      (NetBox, Django REST, ...)
#   "x-api-key"     -> x-api-key: <key>
#   "header:<Name>" -> <Name>: <key>                   (any custom header)
# More routes can be added without editing this file via --routes (see load_routes_file).
ROUTES = {
    "deepseek": ("https://api.deepseek.com", "DEEPSEEK_API_KEY", "bearer"),
    "openai": ("https://api.openai.com", "OPENAI_API_KEY", "bearer"),
    "anthropic": ("https://api.anthropic.com", "ANTHROPIC_API_KEY", "x-api-key"),
}

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
    "accept-encoding",
}
STRIP_AUTH = {"authorization", "x-api-key", "api-key"}

KEYS = {}  # route prefix -> real key (filled from stdin, lives only in RAM)
SSL_CTX = ssl.create_default_context()


def auth_header(style, key):
    """Return the (header name, value) that carries ``key`` for the given auth style."""
    if style == "bearer":
        return "Authorization", "Bearer " + key
    if style == "token":
        return "Authorization", "Token " + key
    if style == "x-api-key":
        return "x-api-key", key
    if style.startswith("header:") and re.fullmatch(r"[A-Za-z0-9-]+", style[7:]):
        return style[7:], key
    raise ValueError("unknown auth style %r" % style)


def validate_route(name, spec):
    """Validate one entry of a routes file; return the ROUTES tuple."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise ValueError("route name %r: use letters, digits, '-' and '_'" % name)
    try:
        upstream, env_name, style = spec["upstream"], spec["env"], spec.get("auth", "bearer")
    except (KeyError, TypeError, AttributeError):
        raise ValueError("route %r needs 'upstream' and 'env' (optional 'auth')" % name)
    auth_header(style, "x")  # raises on unknown style
    u = urlsplit(upstream)
    if u.scheme == "https":
        pass
    elif u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1"):
        pass  # plain http is only allowed for loopback backends (keys must not cross a network in clear)
    else:
        raise ValueError("route %r: upstream must be https:// (or http:// on localhost)" % name)
    if not u.netloc:
        raise ValueError("route %r: upstream has no host" % name)
    return (upstream, env_name, style)


def load_routes_file(path):
    """Add/override routes from a JSON file (contains no secrets, only env var names).

    {"routes": {"netbox": {"upstream": "https://netbox.example.com",
                           "env": "NETBOX_TOKEN", "auth": "token"}}}
    """
    with open(path) as f:
        data = json.load(f)
    for name, spec in (data.get("routes") or {}).items():
        ROUTES[name] = validate_route(name, spec)


def harden():
    """Keep secrets out of swap and core dumps; block same-user /proc/<pid>/mem reads.

    Linux/glibc only; failures are ignored (the proxy still works, just less hardened).
    """
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.prctl(4, 0, 0, 0, 0)          # PR_SET_DUMPABLE = 0
        libc.mlockall(1 | 2)               # MCL_CURRENT | MCL_FUTURE
    except Exception:
        pass


def parse_env(text):
    """Parse ``KEY=VALUE`` lines (comments, ``export``, and simple quotes supported)."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        if k.startswith("export "):
            k = k[7:].strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k] = v
    return out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # method/path/status only — no headers/bodies
        sys.stderr.write("%s %s\n" % (self.log_date_time_string(), fmt % args))

    def _fail(self, code, msg):
        body = msg.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _proxy(self):
        parts = self.path.lstrip("/").split("/", 1)
        route = ROUTES.get(parts[0])
        if not route or parts[0] not in KEYS:
            return self._fail(404, "unknown route\n")
        base, _env_name, style = route
        up = urlsplit(base)
        path = up.path.rstrip("/") + "/" + (parts[1] if len(parts) > 1 else "")

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None

        auth_name, auth_value = auth_header(style, KEYS[parts[0]])
        drop = HOP_BY_HOP | STRIP_AUTH | {auth_name.lower()}
        headers = {k: v for k, v in self.headers.items() if k.lower() not in drop}
        headers["Host"] = up.netloc
        headers["Accept-Encoding"] = "identity"
        headers[auth_name] = auth_value

        if up.scheme == "http":  # plain http upstream: only meant for tests/local backends
            conn = http.client.HTTPConnection(up.netloc, timeout=600)
        else:
            conn = http.client.HTTPSConnection(up.netloc, context=SSL_CTX, timeout=600)
        try:
            conn.request(self.command, path, body=body, headers=headers)
            resp = conn.getresponse()
        except Exception as e:
            conn.close()
            return self._fail(502, "upstream error: %s\n" % type(e).__name__)

        try:
            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() not in HOP_BY_HOP:
                    self.send_header(k, v)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            while True:
                chunk = resp.read1(65536)
                if not chunk:
                    break
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        finally:
            conn.close()

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _proxy


def load_keys(env):
    """Select the keys needed by ROUTES from a parsed env dict into KEYS."""
    for name, (_, env_name, _) in ROUTES.items():
        if env.get(env_name):
            KEYS[name] = env[env_name]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("port_pos", nargs="?", type=int, metavar="PORT", help=argparse.SUPPRESS)
    ap.add_argument("--port", type=int, default=None, help="listen port (default 8787)")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    ap.add_argument("--routes", metavar="FILE",
                    help="JSON file with extra routes (see README); contains no secrets")
    args = ap.parse_args(argv)
    port = args.port or args.port_pos or 8787
    if args.routes:
        try:
            load_routes_file(args.routes)
        except (OSError, ValueError) as e:  # json.JSONDecodeError is a ValueError
            sys.exit("llm-key-proxy: bad routes file %s: %s" % (args.routes, e))

    harden()
    env = parse_env(sys.stdin.read())
    load_keys(env)
    names = sorted(env)
    del env
    if not KEYS:
        wanted = sorted(e for _, e, _ in ROUTES.values())
        sys.exit("llm-key-proxy: no usable keys on stdin. wanted=%s found_names=%s"
                 % (wanted, names))  # names only, never values

    srv = ThreadingHTTPServer((args.host, port), Handler)
    srv.daemon_threads = True
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    sys.stderr.write("llm-key-proxy on %s:%d routes=%s\n"
                     % (args.host, port, ",".join(sorted(KEYS))))
    sys.stderr.flush()
    try:
        srv.serve_forever()
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
