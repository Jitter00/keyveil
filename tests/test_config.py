"""Config loading: defaults, XDG paths, precedence, and clear errors. No real files touched."""
import os
import shutil
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from keyveil import config


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        env = {"HOME": str(self.tmp), "XDG_CONFIG_HOME": str(self.tmp / "cfg"),
               "XDG_STATE_HOME": str(self.tmp / "state"), "XDG_RUNTIME_DIR": str(self.tmp / "run")}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, text, name="config.toml"):
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_defaults_without_a_file(self):
        cfg = config.load()
        self.assertEqual(cfg.port, 8787)
        self.assertIsNone(cfg.source)
        self.assertIsNone(cfg.age_identity)
        self.assertIsNone(cfg.decrypt_command)
        self.assertIsNone(cfg.routes_file)
        self.assertEqual(cfg.age_file, self.tmp / "cfg" / "keyveil" / "env.age")

    def test_xdg_directories(self):
        self.assertEqual(config.default_config_path(), self.tmp / "cfg" / "keyveil" / "config.toml")
        self.assertEqual(config.state_dir(), self.tmp / "state" / "keyveil")
        self.assertEqual(config.runtime_dir(), self.tmp / "run" / "keyveil")

    def test_runtime_dir_falls_back_to_cache_without_xdg_runtime_dir(self):
        with mock.patch.dict(os.environ):
            del os.environ["XDG_RUNTIME_DIR"]
            self.assertEqual(config.runtime_dir(), self.tmp / ".cache" / "keyveil")

    def test_full_file_with_tilde_expansion(self):
        path = self.write("""port = 9000
routes_file = "~/r.json"
[age]
identity = "~/id.txt"
file = "~/keys.age"
binary = "myage"
[decrypt]
command = "echo hi"
""")
        cfg = config.load(path)
        self.assertEqual(cfg.port, 9000)
        self.assertEqual(cfg.routes_file, self.tmp / "r.json")
        self.assertEqual(cfg.age_identity, self.tmp / "id.txt")
        self.assertEqual(cfg.age_file, self.tmp / "keys.age")
        self.assertEqual(cfg.age_binary, "myage")
        self.assertEqual(cfg.decrypt_command, "echo hi")
        self.assertEqual(cfg.source, path)

    def test_command_line_overrides_win(self):
        path = self.write('port = 9000\n[decrypt]\ncommand = "from-file"\n')
        cfg = config.load(path, port=9100, decrypt_command="from-flag")
        self.assertEqual((cfg.port, cfg.decrypt_command), (9100, "from-flag"))

    def test_default_routes_file_is_used_when_present(self):
        routes = self.tmp / "cfg" / "keyveil" / "routes.json"
        routes.parent.mkdir(parents=True)
        routes.write_text("{}")
        self.assertEqual(config.load().routes_file, routes)

    def test_invalid_toml_names_the_file_and_line(self):
        path = self.write("port = 1\nport = = 2\n")
        with self.assertRaises(config.ConfigError) as cm:
            config.load(path)
        self.assertIn(str(path), str(cm.exception))
        self.assertIn("line 2", str(cm.exception))

    def test_unknown_keys_are_rejected_so_typos_are_not_silent(self):
        for text in ('prot = 1\n', '[age]\nidentiy = "x"\n', '[decrypt]\ncmd = "x"\n'):
            with self.assertRaises(config.ConfigError, msg=text) as cm:
                config.load(self.write(text))
            self.assertIn("unknown key", str(cm.exception))

    def test_wrong_types_and_bad_ports(self):
        bad = ['port = "8787"\n', 'port = true\n', 'port = 0\n', 'port = 70000\n',
               'age = 3\n', '[age]\nidentity = ""\n', '[decrypt]\ncommand = 5\n']
        for text in bad:
            with self.assertRaises(config.ConfigError, msg=text):
                config.load(self.write(text))
        with self.assertRaises(config.ConfigError):
            config.load(port=0)

    def test_explicit_missing_file_is_an_error_default_is_not(self):
        with self.assertRaises(config.ConfigError):
            config.load(self.tmp / "nope.toml")
        config.load()  # default path absent: fine

    def test_init_template_is_valid_toml(self):
        self.assertEqual(tomllib.loads(config.TEMPLATE), {"port": 8787})

    def test_example_file_matches_the_init_template(self):
        example = Path(__file__).resolve().parent.parent / "config.example.toml"
        self.assertEqual(example.read_text(encoding="utf-8"), config.TEMPLATE)


if __name__ == "__main__":
    unittest.main()
