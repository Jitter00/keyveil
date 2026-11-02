#!/usr/bin/env python3
"""keyveil — localhost reverse proxy that injects API credentials held only in RAM.

Usage:  rage -d -i <identity> env.age | python3 -I proxy.py [--port 8787] [--routes routes.json]

Works for any HTTP API that authenticates with a key/token in a request header
(LLM providers, NetBox, GitHub, self-hosted gateways...). The decrypted
``KEY=VALUE`` env text is read from stdin (never argv, environ or disk). Clients
(editors, agents, SDKs, curl...) talk to ``http://127.0.0.1:<port>/<route>/...``
with any dummy key; the proxy strips it and adds the real one before forwarding
upstream. A route is only enabled if its key is present on stdin.

This file is self-contained (standard library only) so it can be run directly
with ``python3 -I`` as well as through the ``keyveil`` console script.
"""

import argparse
import ctypes
import fnmatch
import http.client
import ipaddress
import json
import os
import re
import signal
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

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
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "accept-encoding",
}
STRIP_AUTH = {"authorization", "x-api-key", "api-key"}

KEYS = {}  # route prefix -> real key (filled from stdin, lives only in RAM)
# On routes with an allow list: ";" (path parameters), "//", and percent-encoded "/", "\",
# ".", NUL or "%" (double encoding) in the path.
AMBIGUOUS_PATH = re.compile(r";|//|%(2f|5c|2e|00|25)", re.IGNORECASE)
ALLOW = {}  # route prefix -> ["METHOD /path-glob", ...]; absent means every path is allowed
SSL_CTX = ssl.create_default_context()
MAX_BODY = 64 * 1024 * 1024  # largest request body forwarded (bytes)
_ALLOW_RULE = re.compile(r"[A-Z]+ /\S*")


class RequestError(Exception):
    """A client error answered with ``code``; the connection is then closed."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


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


_PRIVATE_NETS = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _private_ip(host):
    """True if ``host`` is a literal IPv4 address in an RFC 1918 private range.

    Hostnames never qualify: DNS could point them anywhere, so plain http to one would let a
    key cross a network in clear.
    """
    try:
        ip = ipaddress.ip_address(host or "")
    except ValueError:
        return False
    return ip.version == 4 and any(ip in net for net in _PRIVATE_NETS)


def validate_route(name, spec):
    """Validate one entry of a routes file; return the ROUTES tuple."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise ValueError("route name %r: use letters, digits, '-' and '_'" % name)
    if isinstance(spec, dict):  # a typo like "alow" must not silently drop a restriction
        unknown = sorted(set(spec) - {"upstream", "env", "auth", "allow", "allow_http"})
        if unknown:
            raise ValueError("route %r: unknown key(s) %s" % (name, ", ".join(unknown)))
    try:
        upstream, env_name, style = spec["upstream"], spec["env"], spec.get("auth", "bearer")
    except (KeyError, TypeError, AttributeError):
        raise ValueError("route %r needs 'upstream' and 'env' (optional 'auth')" % name) from None
    auth_header(style, "x")  # raises on unknown style
    u = urlsplit(upstream)
    allow_http = spec.get("allow_http", False)
    if not isinstance(allow_http, bool):
        raise ValueError("route %r: 'allow_http' must be true or false" % name)
    if u.scheme == "https":
        pass
    elif u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1"):
        # plain http only for loopback backends: keys must not cross a network in clear
        pass
    elif u.scheme == "http" and allow_http and _private_ip(u.hostname):
        pass  # explicit opt-in: plain http to a literal private address (e.g. a local VM)
    elif u.scheme == "http" and allow_http:
        raise ValueError(
            "route %r: allow_http only works with a literal private IP address "
            "(10.x, 172.16-31.x, 192.168.x), not %r" % (name, u.hostname)
        )
    else:
        raise ValueError(
            "route %r: upstream must be https:// (or http:// on localhost; "
            'for a private-network IP set "allow_http": true)' % name
        )
    if not u.netloc:
        raise ValueError("route %r: upstream has no host" % name)
    return (upstream, env_name, style)


def validate_allow(name, spec):
    """Validate an optional ``allow`` list: ["METHOD /path-glob", ...]; None if absent."""
    rules = spec.get("allow") if isinstance(spec, dict) else None
    if rules is None:
        return None
    if not isinstance(rules, list) or not all(
        isinstance(r, str) and _ALLOW_RULE.fullmatch(r) for r in rules
    ):
        raise ValueError(
            "route %r: 'allow' must be a list like [\"POST /v1/messages\", "
            '"GET /v1/models*"]' % name
        )
    return list(rules)


def load_routes_file(path):
    """Add/override routes from a JSON file (contains no secrets, only env var names).

    {"routes": {"netbox": {"upstream": "https://netbox.example.com",
                           "env": "NETBOX_TOKEN", "auth": "token",
                           "allow": ["GET /api/*"]}}}
    """
    with open(path) as f:
        data = json.load(f)
    for name, spec in (data.get("routes") or {}).items():
        route, allow = validate_route(name, spec), validate_allow(name, spec)
        ROUTES[name] = route
        if allow is None:
            ALLOW.pop(name, None)
        else:
            ALLOW[name] = allow


def path_allowed(route, method, rel_path):
    """True if ``METHOD rel_path`` (query string ignored) matches the route's allowlist."""
    rules = ALLOW.get(route)
    if rules is None:
        return True
    target = "%s %s" % ("GET" if method == "HEAD" else method, rel_path.split("?", 1)[0])
    return any(fnmatch.fnmatchcase(target, rule) for rule in rules)


def harden():
    """Keep secrets out of swap and core dumps; block same-user /proc/<pid>/mem reads.

    Linux/glibc only. The proxy still works if a step fails, just less hardened: each
    failure is reported as one warning line on stderr (the log). Returns the warnings.
    """
    warnings = []
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError:
        warnings.append("not hardened: libc.so.6 not found (not Linux/glibc)")
    else:
        if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE = 0
            warnings.append(
                "core dumps and same-user memory reads not blocked (prctl: %s)"
                % os.strerror(ctypes.get_errno())
            )
        if libc.mlockall(1 | 2) != 0:  # MCL_CURRENT | MCL_FUTURE
            warnings.append(
                "memory not locked, keys could be swapped to disk (mlockall: %s); "
                "raise the limit shown by `ulimit -l`" % os.strerror(ctypes.get_errno())
            )
    for w in warnings:
        sys.stderr.write("keyveil: warning: %s\n" % w)
    sys.stderr.flush()
    return warnings


def is_loopback(host):
    """True for a loopback bind address: 127.0.0.0/8, ::1 or localhost."""
    if host.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


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

    def _fail(self, code, msg, close=False):
        body = msg.encode()
        if close:  # the request body may be unread: don't reuse this connection
            self.close_connection = True
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _local_request(self):
        """Only accept requests addressed to the loopback listener by a non-browser client.

        Blocks DNS rebinding (foreign Host) and web pages in your browser (they always send
        Origin and/or Sec-Fetch-Site on cross-site requests, and usually Referer; CLI/SDK
        clients send none of them).
        """
        hosts = self.headers.get_all("Host") or []
        port = self.server.server_address[1]
        allowed = {"127.0.0.1:%d" % port, "localhost:%d" % port, "[::1]:%d" % port}
        if len(hosts) != 1 or hosts[0].strip().lower() not in allowed:
            return False
        if self.headers.get("Origin") is not None or self.headers.get("Referer") is not None:
            return False  # browsers send these; CLI and SDK clients don't
        site = self.headers.get("Sec-Fetch-Site")
        return site is None or site.strip().lower() == "none"

    def _read_body(self):
        """Return the request body (bytes or None). Raises RequestError on bad framing/size."""
        te = self.headers.get_all("Transfer-Encoding")
        cl = self.headers.get_all("Content-Length")
        if te:
            if cl:
                raise RequestError(400, "both Content-Length and Transfer-Encoding\n")
            if len(te) != 1 or te[0].strip().lower() != "chunked":
                raise RequestError(501, "unsupported Transfer-Encoding\n")
            return self._read_chunked()
        if not cl:
            return None
        if len(cl) != 1 or not re.fullmatch(r"[0-9]+", cl[0].strip()):
            raise RequestError(400, "invalid Content-Length\n")
        length = int(cl[0])
        if length > MAX_BODY:
            raise RequestError(413, "request body too large\n")
        if not length:
            return None
        body = self.rfile.read(length)
        if len(body) != length:
            raise RequestError(400, "incomplete request body\n")
        return body

    def _read_chunked(self):
        chunks, total = [], 0
        while True:
            line = self.rfile.readline(1024)
            if not line.endswith(b"\n"):
                raise RequestError(400, "bad chunk header\n")
            size = line.split(b";", 1)[0].strip()
            if not re.fullmatch(rb"[0-9A-Fa-f]{1,8}", size):
                raise RequestError(400, "bad chunk size\n")
            size = int(size, 16)
            if size == 0:
                for _ in range(64):  # optional trailers, ignored
                    if self.rfile.readline(8192) in (b"\r\n", b"\n", b""):
                        return b"".join(chunks) or None
                raise RequestError(400, "too many trailers\n")
            total += size
            if total > MAX_BODY:
                raise RequestError(413, "request body too large\n")
            data = self.rfile.read(size)
            if len(data) != size or self.rfile.readline(3) not in (b"\r\n", b"\n"):
                raise RequestError(400, "bad chunk data\n")
            chunks.append(data)

    def _proxy(self):
        if not self._local_request():
            return self._fail(403, "forbidden: only local, non-browser clients\n", close=True)
        activity = getattr(self.server, "activity", None)
        if activity:
            activity.begin()
        try:
            self._forward()
        finally:
            if activity:
                activity.end()

    def _forward(self):
        parts = self.path.lstrip("/").split("/", 1)
        route = ROUTES.get(parts[0])
        if not route or parts[0] not in KEYS:
            return self._fail(404, "unknown route\n", close=True)
        rel = "/" + (parts[1] if len(parts) > 1 else "")
        segments = unquote(rel.split("?", 1)[0]).replace("\\", "/").split("/")
        if "." in segments or ".." in segments:  # upstream could resolve them past an allowlist
            return self._fail(400, "dot segments are not allowed in the path\n", close=True)
        if parts[0] in ALLOW and AMBIGUOUS_PATH.search(rel.split("?", 1)[0]):
            # An allowlist is checked against the path as written; the upstream may read
            # these differently (path parameters, encoded slashes or dots, empty segments).
            return self._fail(400, "ambiguous path for a route with an allow list\n", close=True)
        if not path_allowed(parts[0], self.command, rel):
            return self._fail(403, "path not allowed for this route\n", close=True)
        base, _env_name, style = route
        up = urlsplit(base)
        path = up.path.rstrip("/") + rel

        try:
            body = self._read_body()
        except RequestError as e:
            return self._fail(e.code, str(e), close=True)

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
            if self.command == "HEAD":  # headers only, never a body
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
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

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _proxy


class Activity:
    """Counts in-flight requests and the time of the last one (for idle shutdown)."""

    def __init__(self):
        self._lock = threading.Lock()
        self.active = 0
        self.last = time.monotonic()

    def begin(self):
        with self._lock:
            self.active += 1
            self.last = time.monotonic()

    def end(self):
        with self._lock:
            self.active -= 1
            self.last = time.monotonic()

    def idle_for(self):
        """Seconds since the last request finished; 0 while any request is in flight."""
        with self._lock:
            return 0.0 if self.active else time.monotonic() - self.last


def _idle_watchdog(srv, timeout):
    interval = max(0.05, min(30.0, timeout / 10))
    while True:
        time.sleep(interval)
        if srv.activity.idle_for() >= timeout:
            sys.stderr.write("keyveil: idle for %gs, shutting down\n" % timeout)
            sys.stderr.flush()
            srv.shutdown()
            return


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
    ap.add_argument(
        "--routes",
        metavar="FILE",
        help="JSON file with extra routes (see README); contains no secrets",
    )
    ap.add_argument(
        "--idle-timeout",
        type=float,
        default=0,
        metavar="SECONDS",
        help="exit after this many seconds without requests (default: never)",
    )
    args = ap.parse_args(argv)
    port = args.port or args.port_pos or 8787
    if args.routes:
        try:
            load_routes_file(args.routes)
        except (OSError, ValueError) as e:  # json.JSONDecodeError is a ValueError
            sys.exit("keyveil: bad routes file %s: %s" % (args.routes, e))
    serve(sys.stdin.read(), args.host, port, idle_timeout=args.idle_timeout)


def serve(env_text, host="127.0.0.1", port=8787, idle_timeout=0):
    """Harden the process, load keys from decrypted ``KEY=VALUE`` text, and serve.

    Serves until SIGTERM, or until ``idle_timeout`` seconds pass with no request in flight
    (0 = never). Exits (SystemExit) if none of the configured routes has a key. Routes must
    already be loaded into ROUTES. Used by ``python -m keyveil.proxy`` and ``keyveil run``.
    """
    if not is_loopback(host):
        sys.exit(
            "keyveil: refusing to listen on %s: the proxy adds your keys to every request, so "
            "anyone who can reach it can use them. Use 127.0.0.1 (the default)." % host
        )
    harden()
    env = parse_env(env_text)
    load_keys(env)
    names = sorted(env)
    del env
    if not KEYS:
        wanted = sorted(e for _, e, _ in ROUTES.values())
        sys.exit(
            "keyveil: no usable keys on stdin. wanted=%s found_names=%s" % (wanted, names)
        )  # names only, never values

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    srv.activity = Activity()
    if idle_timeout and idle_timeout > 0:
        threading.Thread(target=_idle_watchdog, args=(srv, idle_timeout), daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    sys.stderr.write("keyveil on %s:%d routes=%s\n" % (host, port, ",".join(sorted(KEYS))))
    sys.stderr.flush()
    try:
        srv.serve_forever()
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
