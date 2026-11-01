"""Hardening tests: local-only guard, HEAD, request-body framing, size cap, path allowlists,
idle shutdown. Offline: a fake upstream on loopback, no real keys."""
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from keyveil import proxy


class Upstream(BaseHTTPRequestHandler):
    """Echoes what it received as JSON; /slow waits first; HEAD gets headers only."""
    protocol_version = "HTTP/1.1"
    hits = 0

    def _reply(self):
        type(self).hits += 1
        if self.path.startswith("/slow"):
            time.sleep(1.2)
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode() if n else ""
        data = json.dumps({"method": self.command, "path": self.path,
                           "headers": dict(self.headers), "body": body}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    do_GET = do_POST = do_DELETE = do_HEAD = _reply

    def log_message(self, *a):
        pass


def start(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class QuietHandler(proxy.Handler):
    def log_message(self, *a):
        pass


class GuardedProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.up = start(Upstream)
        base = "http://127.0.0.1:%d" % cls.up.server_port
        cls._saved = dict(proxy.ROUTES), dict(proxy.KEYS), dict(proxy.ALLOW)
        proxy.ROUTES.clear()
        proxy.ROUTES.update({"echo": (base, "K", "bearer"), "rules": (base, "K", "bearer")})
        proxy.KEYS.clear()
        proxy.KEYS.update({"echo": "REAL", "rules": "REAL"})
        proxy.ALLOW.clear()
        proxy.ALLOW["rules"] = ["POST /v1/messages", "GET /v1/models*"]
        cls.px = start(QuietHandler)
        cls.port = cls.px.server_port

    @classmethod
    def tearDownClass(cls):
        for srv in (cls.px, cls.up):
            srv.shutdown()
            srv.server_close()
        for target, saved in zip((proxy.ROUTES, proxy.KEYS, proxy.ALLOW), cls._saved):
            target.clear()
            target.update(saved)

    # -- helpers
    def request(self, method, path, headers=(), body=None, host=None):
        """Send a request with full control over headers (incl. Host)."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", host or "127.0.0.1:%d" % self.port)
            for k, v in headers:
                conn.putheader(k, v)
            if body is not None and not any(k.lower() == "content-length" for k, _ in headers):
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def raw(self, data):
        """Send raw bytes; return (status, body)."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            s.sendall(data)
            resp = http.client.HTTPResponse(s)
            resp.begin()
            return resp.status, resp.read()

    def head_line(self, method, path, *extra):
        lines = ["%s %s HTTP/1.1" % (method, path), "Host: 127.0.0.1:%d" % self.port, *extra]
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    # -- local-only guard
    def test_loopback_host_forms_are_accepted(self):
        for host in ("127.0.0.1:%d", "localhost:%d", "LOCALHOST:%d", "[::1]:%d"):
            status, body = self.request("GET", "/echo/x", host=host % self.port)
            self.assertEqual(status, 200, host)
            self.assertEqual(json.loads(body)["headers"]["Authorization"], "Bearer REAL")

    def test_foreign_or_missing_host_is_rejected_before_upstream(self):
        before = Upstream.hits
        for host in ("evil.example:%d" % self.port, "127.0.0.1", "127.0.0.1:1",
                     "attacker.example"):
            self.assertEqual(self.request("GET", "/echo/x", host=host)[0], 403, host)
        self.assertEqual(self.raw(b"GET /echo/x HTTP/1.1\r\n\r\n")[0], 403)          # no Host
        dup = self.head_line("GET", "/echo/x", "Host: 127.0.0.1:%d" % self.port)
        self.assertEqual(self.raw(dup)[0], 403)                                       # two Hosts
        self.assertEqual(Upstream.hits, before, "a rejected request reached the upstream")

    def test_browser_requests_are_rejected(self):
        for header in (("Origin", "https://evil.example"), ("Origin", "null"),
                       ("Sec-Fetch-Site", "cross-site"), ("Sec-Fetch-Site", "same-site"),
                       ("Sec-Fetch-Site", "same-origin")):
            status, _ = self.request("POST", "/echo/x", [header], body=b"{}")
            self.assertEqual(status, 403, header)
        self.assertEqual(self.request("GET", "/echo/x", [("Sec-Fetch-Site", "none")])[0], 200)

    # -- HEAD
    def test_head_is_forwarded_without_a_body_and_keeps_the_connection_usable(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("HEAD", "/echo/probe")
            resp = conn.getresponse()
            self.assertEqual((resp.status, resp.read()), (200, b""))
            conn.request("GET", "/echo/after")                 # same connection: framing intact
            resp = conn.getresponse()
            self.assertEqual(json.loads(resp.read())["path"], "/after")
        finally:
            conn.close()

    # -- request bodies
    def test_chunked_body_is_reassembled_with_a_content_length(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("POST", "/echo/x", body=iter([b"hello ", b"wor", b"ld"]))
            out = json.loads(conn.getresponse().read())
        finally:
            conn.close()
        self.assertEqual(out["body"], "hello world")
        self.assertEqual(out["headers"]["Content-Length"], "11")
        self.assertNotIn("Transfer-Encoding", out["headers"])

    def test_chunk_extensions_and_trailers(self):
        req = (b"POST /echo/x HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"5;name=value\r\nhello\r\n0\r\nX-Trailer: t\r\n\r\n" % self.port)
        status, body = self.raw(req)
        self.assertEqual((status, json.loads(body)["body"]), (200, "hello"))

    def test_bad_framing_is_rejected(self):
        cases = {
            400: [("Content-Length: 2", "Transfer-Encoding: chunked"),
                  ("Content-Length: abc",), ("Content-Length: -1",),
                  ("Content-Length: 1", "Content-Length: 1")],
            501: [("Transfer-Encoding: gzip",), ("Transfer-Encoding: gzip, chunked",)],
        }
        for code, header_sets in cases.items():
            for hdrs in header_sets:
                self.assertEqual(self.raw(self.head_line("POST", "/echo/x", *hdrs))[0], code, hdrs)
        bad_chunk = self.head_line("POST", "/echo/x", "Transfer-Encoding: chunked") + b"zz\r\n"
        self.assertEqual(self.raw(bad_chunk)[0], 400)
        short = self.head_line("POST", "/echo/x", "Content-Length: 10") + b"abc"
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            s.sendall(short)
            s.shutdown(socket.SHUT_WR)                          # client gives up mid-body
            resp = http.client.HTTPResponse(s)
            resp.begin()
            self.assertEqual(resp.status, 400)

    def test_oversized_bodies_get_413(self):
        saved, proxy.MAX_BODY = proxy.MAX_BODY, 10
        try:
            self.assertEqual(self.request("POST", "/echo/x", body=b"x" * 11)[0], 413)
            self.assertEqual(self.request("POST", "/echo/x", body=b"x" * 10)[0], 200)
            chunked = self.head_line("POST", "/echo/x", "Transfer-Encoding: chunked") + \
                b"6\r\nxxxxxx\r\n6\r\nxxxxxx\r\n0\r\n\r\n"
            self.assertEqual(self.raw(chunked)[0], 413)
        finally:
            proxy.MAX_BODY = saved

    # -- path allowlists
    def test_allowlist(self):
        allowed = [("POST", "/rules/v1/messages"), ("GET", "/rules/v1/models"),
                   ("GET", "/rules/v1/models/abc"), ("GET", "/rules/v1/models?limit=5"),
                   ("HEAD", "/rules/v1/models")]
        denied = [("DELETE", "/rules/v1/messages"), ("POST", "/rules/v1/files"),
                  ("GET", "/rules/v1/messages")]
        for method, path in allowed:
            body = b"{}" if method == "POST" else None
            self.assertEqual(self.request(method, path, body=body)[0], 200, (method, path))
        for method, path in denied:
            body = b"{}" if method == "POST" else None
            self.assertEqual(self.request(method, path, body=body)[0], 403, (method, path))
        self.assertEqual(self.request("DELETE", "/echo/anything")[0], 200)  # no list: open

    def test_dot_segments_cannot_escape_an_allowlist_glob(self):
        # "GET /v1/models*" would match these, and an upstream could resolve them to /v1/files.
        for path in ("/rules/v1/models/../files", "/rules/v1/models/%2e%2e/files",
                     "/rules/v1/models/%2E%2E/files", "/rules/v1/models/./x",
                     "/rules/v1/models/..%2ffiles", "/rules/v1/models/..\\files"):
            self.assertEqual(self.request("GET", path)[0], 400, path)
        self.assertEqual(self.request("GET", "/rules/v1/models/a..b")[0], 200)  # not a segment

    def test_allow_rules_are_validated(self):
        for bad in (["post /x"], ["POST x"], ["POST /a b"], "POST /x", [1], [""]):
            with self.assertRaises(ValueError, msg=bad):
                proxy.validate_allow("r", {"allow": bad})
        self.assertIsNone(proxy.validate_allow("r", {}))
        with self.assertRaises(ValueError):           # misspelled key is an error, not ignored
            proxy.validate_route("r", {"upstream": "https://x.example.com", "env": "K",
                                       "alow": ["GET /x"]})
        self.assertEqual(proxy.validate_allow("r", {"allow": ["GET /x*"]}), ["GET /x*"])

    def test_routes_file_sets_and_clears_allowlists(self):
        saved = dict(proxy.ROUTES), dict(proxy.ALLOW)
        spec = {"upstream": "https://x.example.com", "env": "K"}
        try:
            for allow, expected in ((["GET /a"], ["GET /a"]), (None, None)):
                route = dict(spec, **({"allow": allow} if allow else {}))
                with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                    json.dump({"routes": {"z": route}}, f)
                try:
                    proxy.load_routes_file(f.name)
                finally:
                    os.unlink(f.name)
                self.assertEqual(proxy.ALLOW.get("z"), expected)
        finally:
            for target, s in zip((proxy.ROUTES, proxy.ALLOW), saved):
                target.clear()
                target.update(s)


class AllowHttpTests(unittest.TestCase):
    """Plain http upstreams: loopback always; private literal IPs only with "allow_http"."""

    def route(self, upstream, **extra):
        return proxy.validate_route("r", dict({"upstream": upstream, "env": "K"}, **extra))

    def test_private_literal_ips_need_the_opt_in(self):
        for host in ("10.1.2.3", "172.16.0.9", "172.31.255.254", "192.168.1.50:8000"):
            url = "http://%s/base" % host
            with self.assertRaises(ValueError, msg=url):          # no opt-in: still refused
                self.route(url)
            with self.assertRaises(ValueError, msg=url):
                self.route(url, allow_http=False)
            self.assertEqual(self.route(url, allow_http=True), (url, "K", "bearer"), url)

    def test_the_opt_in_never_allows_anything_that_could_leave_the_machine(self):
        refused = ["http://203.0.113.5", "http://8.8.8.8", "http://172.32.0.1", "http://172.15.0.1",
                   "http://192.169.1.1", "http://11.0.0.1", "http://169.254.1.1",
                   "http://netbox.example.com", "http://netbox.local", "http://localhost.evil.com",
                   "http://192.168.1.1.evil.com", "http://192.168.1.1@evil.example.com",
                   "http://[::ffff:192.168.1.1]", "http://[fd00::1]", "http://0xc0a80101",
                   "http://3232235777", "http://192.168.001.001"]
        for url in refused:
            with self.assertRaises(ValueError, msg=url):
                self.route(url, allow_http=True)

    def test_https_and_loopback_work_without_it_and_the_flag_must_be_a_bool(self):
        for url in ("https://nb.example.com", "http://127.0.0.1:4000", "http://localhost:4000"):
            self.assertEqual(self.route(url)[0], url)
            self.assertEqual(self.route(url, allow_http=True)[0], url)   # harmless there
        for bad in ("true", 1, None, "yes"):
            with self.assertRaises(ValueError, msg=bad):
                self.route("http://192.168.1.1", allow_http=bad)

    def test_routes_file_accepts_the_opt_in(self):
        saved = dict(proxy.ROUTES)
        spec = {"routes": {"nb": {"upstream": "http://192.168.1.50:8000", "env": "NB",
                                  "auth": "token", "allow_http": True}}}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(spec, f)
        try:
            proxy.load_routes_file(f.name)
            self.assertEqual(proxy.ROUTES["nb"], ("http://192.168.1.50:8000", "NB", "token"))
        finally:
            os.unlink(f.name)
            proxy.ROUTES.clear()
            proxy.ROUTES.update(saved)


class IdleShutdownTests(unittest.TestCase):
    def run_proxy(self, *args, env_text="DEEPSEEK_API_KEY=x\n"):
        port = free_port()
        proc = subprocess.Popen([sys.executable, "-m", "keyveil.proxy", "--port", str(port), *args],
                                stdin=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdout=subprocess.DEVNULL, text=True)
        self.addCleanup(lambda: (proc.kill(), proc.wait(), proc.stderr.close()))
        proc.stdin.write(env_text)
        proc.stdin.close()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                return proc, port
            except OSError:
                time.sleep(0.05)
        self.fail("proxy did not start: %s" % proc.stderr.read())

    def test_exits_after_the_idle_timeout(self):
        proc, _ = self.run_proxy("--idle-timeout", "0.5")
        self.assertEqual(proc.wait(timeout=5), 0)
        self.assertIn("idle", proc.stderr.read())

    def test_no_timeout_means_it_keeps_running(self):
        proc, _ = self.run_proxy()
        time.sleep(1.0)
        self.assertIsNone(proc.poll())

    def test_a_slow_request_in_flight_is_not_cut_off(self):
        up = start(Upstream)
        self.addCleanup(lambda: (up.shutdown(), up.server_close()))
        routes = {"routes": {"slow": {"upstream": "http://127.0.0.1:%d" % up.server_port,
                                      "env": "SLOW_KEY"}}}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(routes, f)
        self.addCleanup(os.unlink, f.name)
        proc, port = self.run_proxy("--idle-timeout", "0.5", "--routes", f.name,
                                    env_text="SLOW_KEY=x\n")
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", "/slow/slow")                   # upstream takes 1.2s > idle timeout
        resp = conn.getresponse()
        self.assertEqual((resp.status, json.loads(resp.read())["path"]), (200, "/slow"))
        conn.close()
        self.assertEqual(proc.wait(timeout=5), 0)          # and it still shuts down afterwards


if __name__ == "__main__":
    unittest.main()
