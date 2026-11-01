"""keyveil configuration: a TOML file in the XDG config dir. Read as data, never executed."""

import os
import shutil
import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PORT = 8787

TEMPLATE = """\
# keyveil configuration (TOML). Not secrets, just paths and settings.
# Pick ONE way of getting your keys: [age] (default) or [decrypt].

port = 8787
# routes_file = "~/.config/keyveil/routes.json"   # extra routes; used automatically if it exists
# idle_timeout = 120     # minutes without requests before the proxy exits (default 0 = never)

# 1) age / rage, e.g. an age-plugin-yubikey identity
# [age]
# identity = "~/.config/age/identity.txt"
# file = "~/.config/keyveil/env.age"      # default
# binary = "rage"                         # default: rage if installed, else age

# 2) Anything else: a command that prints KEY=VALUE lines to stdout. It is run with /bin/sh,
#    so treat it as code you trust. When set, [age] is ignored.
# [decrypt]
# command = 'gpg -d "$HOME/keys.gpg"'

# `keyveil sandbox -- <agent>`: extra paths for the sandbox (see README)
# [sandbox]
# rw = ["~/.npm"]           # also writable (default: the project, ~/.claude, ~/.claude.json)
# hide = ["~/secrets"]      # also hidden (default: ~/.ssh, ~/.gnupg, keyveil's files, ...)
"""


class ConfigError(Exception):
    """A problem with the configuration file; the message is safe to show to the user."""


def _xdg(var, fallback):
    return Path(os.environ.get(var) or Path.home() / fallback)


def config_dir():
    return _xdg("XDG_CONFIG_HOME", ".config") / "keyveil"


def state_dir():
    return _xdg("XDG_STATE_HOME", ".local/state") / "keyveil"


def runtime_dir():
    rt = os.environ.get("XDG_RUNTIME_DIR")
    return (Path(rt) if rt else Path.home() / ".cache") / "keyveil"


def default_config_path():
    return config_dir() / "config.toml"


@dataclass
class Config:
    port: int = DEFAULT_PORT
    routes_file: Path | None = None
    decrypt_command: str | None = None
    age_identity: Path | None = None
    age_file: Path | None = None
    age_binary: str = "age"
    idle_timeout: float = 0.0  # seconds; 0 = never
    sandbox_rw: tuple = ()  # extra writable paths for `keyveil sandbox`
    sandbox_hide: tuple = ()  # extra hidden paths for `keyveil sandbox`
    source: Path | None = None  # the file this was loaded from, if any


_TOP = {"port", "routes_file", "idle_timeout", "age", "decrypt", "sandbox"}
_AGE = {"identity", "file", "binary"}
_DECRYPT = {"command"}
_SANDBOX = {"rw", "hide"}


def _path_list(table, key, where):
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise ConfigError("%s: %r must be a list of non-empty strings" % (where, key))
    return tuple(_path(v) for v in value)


def _check_keys(table, allowed, where):
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ConfigError(
            "%s: unknown key(s) %s (allowed: %s)"
            % (where, ", ".join(unknown), ", ".join(sorted(allowed)))
        )


def _string(table, key, where):
    value = table.get(key)
    if value is not None and not (isinstance(value, str) and value.strip()):
        raise ConfigError("%s: %r must be a non-empty string" % (where, key))
    return value


def _table(data, key, where):
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError("%s: [%s] must be a table" % (where, key))
    return value


def _path(value):
    return Path(os.path.expanduser(value)) if value else None


def load(path=None, *, port=None, decrypt_command=None):
    """Load the config. ``path`` is explicit (must exist) or the default (may be absent).

    Keyword arguments are command-line overrides and win over the file.
    """
    explicit = path is not None
    path = Path(path) if explicit else default_config_path()
    data, source = {}, None
    if path.is_file():
        source = path
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as e:
            raise ConfigError("%s: invalid TOML: %s" % (path, e)) from None
    elif explicit:
        raise ConfigError("config file not found: %s" % path)

    where = str(path)
    _check_keys(data, _TOP, where)
    age, dec = _table(data, "age", where), _table(data, "decrypt", where)
    box = _table(data, "sandbox", where)
    _check_keys(age, _AGE, where + " [age]")
    _check_keys(dec, _DECRYPT, where + " [decrypt]")
    _check_keys(box, _SANDBOX, where + " [sandbox]")

    idle = data.get("idle_timeout", 0)
    if isinstance(idle, bool) or not isinstance(idle, (int, float)) or idle < 0:
        raise ConfigError("%s: 'idle_timeout' must be a number of minutes >= 0" % where)

    cfg_port = data.get("port", DEFAULT_PORT)
    if isinstance(cfg_port, bool) or not isinstance(cfg_port, int):
        raise ConfigError("%s: 'port' must be an integer" % where)
    final_port = port if port is not None else cfg_port
    if not 1 <= final_port <= 65535:
        raise ConfigError("port must be between 1 and 65535, got %s" % final_port)

    routes = _path(_string(data, "routes_file", where))
    if routes is None and (config_dir() / "routes.json").is_file():
        routes = config_dir() / "routes.json"

    return Config(
        port=final_port,
        routes_file=routes,
        decrypt_command=decrypt_command or _string(dec, "command", where + " [decrypt]"),
        age_identity=_path(_string(age, "identity", where + " [age]")),
        age_file=_path(_string(age, "file", where + " [age]")) or config_dir() / "env.age",
        age_binary=_string(age, "binary", where + " [age]")
        or ("rage" if shutil.which("rage") else "age"),
        idle_timeout=float(idle) * 60,
        sandbox_rw=_path_list(box, "rw", where + " [sandbox]"),
        sandbox_hide=_path_list(box, "hide", where + " [sandbox]"),
        source=source,
    )
