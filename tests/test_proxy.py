"""Offline tests: the proxy is pointed at a local fake upstream (no network, no real keys)."""

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from keyveil import proxy


class EchoUpstream(BaseHTTPRequestHandler):
    """Replies with the request headers it received, as JSON."""

    def _reply(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode() if n else ""
        data = json.dumps({"path": self.path, "headers": dict(self.headers), "body": body}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _reply

    def log_message(self, *a):
        pass


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class ParseEnvTests(unittest.TestCase):
    def test_formats(self):
        env = proxy.parse_env(
            "# comment\n\nA=1\nexport B=\"two words\"\nC='x'\r\nD = spaced \nnoequals\nE=a=b\n"
        )
        self.assertEqual(env, {"A": "1", "B": "two words", "C": "x", "D": "spaced", "E": "a=b"})

    def test_load_keys_only_enabled_routes(self):
        saved = dict(proxy.KEYS)
        proxy.KEYS.clear()
        try:
            proxy.load_keys({"DEEPSEEK_API_KEY": "k", "UNRELATED": "z"})
            self.assertEqual(proxy.KEYS, {"deepseek": "k"})
        finally:
            proxy.KEYS.clear()
            proxy.KEYS.update(saved)


class RoutesFileTests(unittest.TestCase):
    def setUp(self):
        self.saved = dict(proxy.ROUTES)

    def tearDown(self):
        proxy.ROUTES.clear()
        proxy.ROUTES.update(self.saved)

    def load(self, data):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(data, f)
        try:
            proxy.load_routes_file(f.name)
        finally:
            os.unlink(f.name)

    def test_valid_routes_are_added(self):
        self.load(
            {
                "routes": {
                    "netbox": {"upstream": "https://nb.example.com", "env": "NB", "auth": "token"},
                    "local": {"upstream": "http://localhost:4000", "env": "L"},
                }
            }
        )
        self.assertEqual(proxy.ROUTES["netbox"], ("https://nb.example.com", "NB", "token"))
        self.assertEqual(proxy.ROUTES["local"], ("http://localhost:4000", "L", "bearer"))

    def test_rejects_bad_routes(self):
        bad = [
            {"upstream": "http://api.example.com", "env": "K"},  # cleartext over network
            {"upstream": "ftp://x.example.com", "env": "K"},  # bad scheme
            {"upstream": "https://x.example.com", "env": "K", "auth": "?"},  # unknown auth style
            {"upstream": "https://x.example.com", "env": "K", "auth": "header:Bad Name"},
            {"upstream": "https://x.example.com"},  # missing env
        ]
        for spec in bad:
            with self.assertRaises(ValueError, msg=spec):
                self.load({"routes": {"r": spec}})
        with self.assertRaises(ValueError):
            self.load({"routes": {"bad/name": {"upstream": "https://x.example.com", "env": "K"}}})


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = serve(EchoUpstream)
        cls._routes, cls._keys = dict(proxy.ROUTES), dict(proxy.KEYS)
        proxy.ROUTES.clear()
        proxy.ROUTES["bear"] = (
            "http://127.0.0.1:%d/base" % cls.upstream.server_port,
            "K1",
            "bearer",
        )
        proxy.ROUTES["xkey"] = ("http://127.0.0.1:%d" % cls.upstream.server_port, "K2", "x-api-key")
        proxy.ROUTES["nokey"] = ("http://127.0.0.1:1", "K3", "bearer")
        proxy.ROUTES["tok"] = ("http://127.0.0.1:%d" % cls.upstream.server_port, "K4", "token")
        proxy.ROUTES["hdr"] = (
            "http://127.0.0.1:%d" % cls.upstream.server_port,
            "K5",
            "header:X-Auth-Token",
        )
        proxy.KEYS.clear()
        proxy.KEYS.update({"bear": "REAL-1", "xkey": "REAL-2", "tok": "REAL-4", "hdr": "REAL-5"})
        cls.proxy = serve(proxy.Handler)
        cls.url = "http://127.0.0.1:%d" % cls.proxy.server_port

    @classmethod
    def tearDownClass(cls):
        for srv in (cls.proxy, cls.upstream):
            srv.shutdown()
            srv.server_close()
        proxy.ROUTES.clear()
        proxy.ROUTES.update(cls._routes)
        proxy.KEYS.clear()
        proxy.KEYS.update(cls._keys)

    def call(self, path, data=None, headers=None):
        req = urllib.request.Request(self.url + path, data=data, headers=headers or {})
        with urllib.request.urlopen(req) as r:
            return json.load(r)

    def test_bearer_key_replaces_client_key(self):
        out = self.call("/bear/v1/models", headers={"Authorization": "Bearer dummy"})
        self.assertEqual(out["headers"]["Authorization"], "Bearer REAL-1")
        self.assertEqual(out["path"], "/base/v1/models")

    def test_x_api_key_style_and_dummy_stripped(self):
        out = self.call(
            "/xkey/v1/messages",
            data=b'{"a":1}',
            headers={
                "x-api-key": "dummy",
                "Authorization": "Bearer dummy",
                "Content-Type": "application/json",
            },
        )
        self.assertEqual(out["headers"]["x-api-key"], "REAL-2")
        self.assertNotIn("Authorization", out["headers"])
        self.assertEqual(out["body"], '{"a":1}')

    def test_token_style(self):
        out = self.call("/tok/api/", headers={"Authorization": "Bearer dummy"})
        self.assertEqual(out["headers"]["Authorization"], "Token REAL-4")

    def test_custom_header_style_replaces_client_value_any_case(self):
        out = self.call("/hdr/x", headers={"x-auth-token": "dummy"})
        self.assertEqual(out["headers"]["X-Auth-Token"], "REAL-5")
        self.assertEqual(len([k for k in out["headers"] if k.lower() == "x-auth-token"]), 1)

    def test_unknown_or_keyless_route_is_404(self):
        for path in ("/nope/x", "/nokey/x"):
            with self.assertRaises(urllib.error.HTTPError) as cm:
                self.call(path)
            self.assertEqual(cm.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
