"""keyveil command line: unlock keys once, then run the in-memory key-injecting proxy.

keyveil init      write a starter config file
keyveil start     decrypt your keys and start the proxy in the background
keyveil status    is it running?
keyveil stop      stop it (the keys vanish with the process)
keyveil run       run in the foreground (or `--stdin` to read KEY=VALUE from a pipe)
"""

import argparse
import os
import signal
import socket
import subprocess
import sys
import time
from importlib import metadata
from pathlib import Path

from . import config as cfgmod

HOST = "127.0.0.1"
START_TIMEOUT = 5.0


class CLIError(Exception):
    """An expected failure; the message is shown to the user without a traceback."""


# ---------------------------------------------------------------- process helpers


def _pid_file(port):
    return cfgmod.runtime_dir() / ("%d.pid" % port)


def _log_file():
    return cfgmod.state_dir() / "keyveil.log"


def _port_open(port):
    try:
        with socket.create_connection((HOST, port), timeout=0.3):
            return True
    except OSError:
        return False


def _read_pid(port):
    try:
        return int(_pid_file(port).read_text().strip())
    except (OSError, ValueError):
        return None


def _alive(pid):
    """True if the process exists and is not a zombie (Linux /proc)."""
    try:
        stat = Path("/proc/%d/stat" % pid).read_bytes()
    except OSError:
        return False
    return stat.rsplit(b")", 1)[1].split()[0] != b"Z"


def _is_keyveil(pid):
    """True if ``pid`` is a keyveil proxy. Guards against signalling a recycled PID."""
    try:
        argv = Path("/proc/%d/cmdline" % pid).read_bytes().split(b"\0")
    except OSError:
        return False
    return b"keyveil.proxy" in argv


def _private_dir(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def _log_tail(path, offset):
    """Last non-empty log line written after ``offset`` (the proxy logs variable names only)."""
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return ""
    return next((ln.strip() for ln in reversed(lines) if ln.strip()), "")


# ---------------------------------------------------------------- getting the keys


def get_secrets(cfg):
    """Run the decrypt step and return the ``KEY=VALUE`` text. Never printed or logged.

    Output is captured in memory; stdin and stderr stay attached to the terminal so
    YubiKey / passphrase prompts work.
    """
    if cfg.decrypt_command:
        argv, shell = cfg.decrypt_command, True
    else:
        if cfg.age_identity is None:
            raise CLIError(
                "no key source configured. Run `keyveil init`, then set [age] "
                "identity (and file) or [decrypt] command in the config file"
            )
        if not cfg.age_file.is_file():
            raise CLIError("encrypted file not found: %s" % cfg.age_file)
        argv = [cfg.age_binary, "-d", "-i", str(cfg.age_identity), str(cfg.age_file)]
        shell = False
    print(
        "Unlocking keys (touch your YubiKey / enter your passphrase if prompted)...",
        file=sys.stderr,
    )
    try:
        # The command comes from the user's own config (documented as trusted code).
        result = subprocess.run(argv, shell=shell, stdout=subprocess.PIPE, text=True)  # noqa: S603
    except FileNotFoundError:
        raise CLIError("cannot run %r: command not found" % (argv if shell else argv[0])) from None
    if result.returncode != 0:
        raise CLIError("decryption failed (exit status %d)" % result.returncode)
    if not result.stdout.strip():
        raise CLIError("the decrypt step printed nothing")
    return result.stdout


# ---------------------------------------------------------------- commands


def _load(args):
    return cfgmod.load(
        args.config, port=args.port, decrypt_command=getattr(args, "decrypt_cmd", None)
    )


def cmd_start(args):
    cfg = _load(args)
    port = cfg.port
    if _port_open(port):
        pid = _read_pid(port)
        if pid and _is_keyveil(pid) and _alive(pid):
            print("keyveil already running on :%d (pid %d)" % (port, pid))
            return 0
        raise CLIError("port %d is already in use by another process" % port)

    secrets = get_secrets(cfg)
    log_path = _private_dir(cfgmod.state_dir()) / "keyveil.log"
    argv = [sys.executable, "-I", "-m", "keyveil.proxy"]
    if cfg.routes_file:
        argv += ["--routes", str(cfg.routes_file)]
    if cfg.idle_timeout:
        argv += ["--idle-timeout", "%g" % cfg.idle_timeout]
    argv += ["--port", str(port)]  # last: `stop` and tests match "--port N" at the end
    with open(log_path, "ab") as log:
        offset = log.tell()
        # The keys go to the child's stdin only: never argv, environment, or a file.
        proc = subprocess.Popen(  # noqa: S603 - argv is our own interpreter + module
            argv, stdin=subprocess.PIPE, stdout=log, stderr=log, start_new_session=True
        )
    try:
        proc.stdin.write(secrets.encode())
        proc.stdin.close()
    except BrokenPipeError:
        pass  # the child already exited; reported below
    del secrets

    deadline = time.monotonic() + START_TIMEOUT
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise CLIError(
                "failed to start: %s (log: %s)"
                % (_log_tail(log_path, offset) or "exited", log_path)
            )
        if _port_open(port):
            _private_dir(cfgmod.runtime_dir())
            _pid_file(port).write_text("%d\n" % proc.pid)
            print("ok — keyveil on %s:%d (pid %d)" % (HOST, port, proc.pid))
            return 0
        time.sleep(0.05)
    proc.terminate()
    raise CLIError("did not start listening within %.0fs (log: %s)" % (START_TIMEOUT, log_path))


def cmd_stop(args):
    port = cfgmod.load(args.config, port=args.port).port
    pid = _read_pid(port)
    if pid is None:
        print("not running")
        return 0
    if not (_is_keyveil(pid) and _alive(pid)):
        _pid_file(port).unlink(missing_ok=True)
        print("not running (removed stale pid file)")
        return 0
    os.kill(pid, signal.SIGTERM)
    for _ in range(60):
        if not _alive(pid):
            break
        time.sleep(0.05)
    else:
        raise CLIError("pid %d did not exit after SIGTERM" % pid)
    _pid_file(port).unlink(missing_ok=True)
    print("stopped")
    return 0


def cmd_status(args):
    port = cfgmod.load(args.config, port=args.port).port
    pid = _read_pid(port)
    if _port_open(port):
        if pid and _is_keyveil(pid) and _alive(pid):
            print("running on :%d (pid %d)" % (port, pid))
            return 0
        print("something else is listening on :%d (not started by `keyveil start`)" % port)
        return 3
    print("not running")
    return 3


def cmd_run(args):
    from . import proxy

    cfg = _load(args)
    if cfg.routes_file:
        try:
            proxy.load_routes_file(cfg.routes_file)
        except (OSError, ValueError) as e:
            raise CLIError("bad routes file %s: %s" % (cfg.routes_file, e)) from e
    text = sys.stdin.read() if args.stdin else get_secrets(cfg)
    proxy.serve(text, HOST, cfg.port, idle_timeout=cfg.idle_timeout)
    return 0


def cmd_sandbox(args):
    from . import proxy, sandbox

    cfg = cfgmod.load(args.config)
    if cfg.routes_file:  # so the sandbox strips custom routes' key variables too
        try:
            proxy.load_routes_file(cfg.routes_file)
        except (OSError, ValueError) as e:
            raise CLIError("bad routes file %s: %s" % (cfg.routes_file, e)) from e
    try:
        argv, removed, warnings = sandbox.build(
            args.command,
            project=args.project or os.getcwd(),
            cfg=cfg,
            extra_rw=args.rw,
            extra_hide=args.hide,
            keep_env=args.keep_env,
            ssh_agent=args.ssh_agent,
        )
        if args.dry_run:
            print(sandbox.describe(argv))
            return 0
        sandbox.preflight()
    except sandbox.SandboxError as e:
        raise CLIError(str(e)) from e
    for w in warnings:
        print("keyveil sandbox: %s" % w, file=sys.stderr)
    if removed:  # names only, never values
        print(
            "keyveil sandbox: removed from the environment: %s" % ", ".join(removed),
            file=sys.stderr,
        )
    sys.stdout.flush()
    sys.stderr.flush()
    os.execvp(argv[0], argv)  # noqa: S606 - replace ourselves with bwrap (argv list, no shell)


def cmd_init(args):
    path = Path(args.config) if args.config else cfgmod.default_config_path()
    if path.exists():
        raise CLIError("%s already exists; not overwriting" % path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(cfgmod.TEMPLATE, encoding="utf-8")
    os.chmod(path, 0o600)
    print("wrote %s\nedit it (set your key source), then run: keyveil start" % path)
    return 0


# ---------------------------------------------------------------- entry point


def _version():
    try:
        return metadata.version("keyveil")
    except metadata.PackageNotFoundError:
        return "unknown"


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--config", metavar="FILE", help="config file (default: ~/.config/keyveil/config.toml)"
    )
    common.add_argument(
        "--port",
        type=int,
        help="listen port (default: from the config file, else %d)" % cfgmod.DEFAULT_PORT,
    )

    parser = argparse.ArgumentParser(prog="keyveil", description=__doc__.split("\n")[0])
    parser.add_argument("--version", action="version", version="keyveil " + _version())
    sub = parser.add_subparsers(
        dest="command", required=True, metavar="{init,start,stop,status,run}"
    )

    p = sub.add_parser("init", help="write a starter config file")
    p.add_argument("--config", metavar="FILE", help="where to write it")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser(
        "start", parents=[common], help="unlock your keys and start the proxy in the background"
    )
    p.add_argument(
        "--decrypt-cmd",
        metavar="CMD",
        help="shell command printing KEY=VALUE lines (overrides the config)",
    )
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("stop", parents=[common], help="stop the background proxy")
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser(
        "status", parents=[common], help="show whether the proxy is running (exit 0 yes, 3 no)"
    )
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("run", parents=[common], help="run in the foreground")
    p.add_argument(
        "--stdin", action="store_true", help="read KEY=VALUE lines from stdin instead of decrypting"
    )
    p.add_argument(
        "--decrypt-cmd",
        metavar="CMD",
        help="shell command printing KEY=VALUE lines (overrides the config)",
    )
    p.set_defaults(func=cmd_run)

    p = sub.add_parser(
        "sandbox",
        usage="keyveil sandbox [options] -- COMMAND [ARGS...]",
        help="run an agent (e.g. claude) confined with bubblewrap",
        description="Run COMMAND so it can edit the project and use the keyveil proxy, but "
        "cannot become root, reach Docker, read common secret stores, or tamper "
        "with files outside the project. See README, 'Threat model'.",
    )
    p.add_argument(
        "--config", metavar="FILE", help="config file (default: ~/.config/keyveil/config.toml)"
    )
    p.add_argument(
        "--project",
        metavar="DIR",
        help="directory the agent may write (default: the current directory)",
    )
    p.add_argument(
        "--rw",
        action="append",
        default=[],
        metavar="PATH",
        help="also make PATH writable (repeatable)",
    )
    p.add_argument(
        "--hide", action="append", default=[], metavar="PATH", help="also hide PATH (repeatable)"
    )
    p.add_argument(
        "--keep-env",
        action="append",
        default=[],
        metavar="NAME",
        help="keep this environment variable even if it looks secret (repeatable)",
    )
    p.add_argument(
        "--ssh-agent",
        action="store_true",
        help="give the agent your ssh-agent socket (e.g. for git push over ssh)",
    )
    p.add_argument("--dry-run", action="store_true", help="print the bwrap command and exit")
    p.add_argument(
        "command",
        nargs="*",
        metavar="COMMAND",
        help="the agent to run; put it after `--` if it has its own options",
    )
    p.set_defaults(func=cmd_sandbox)
    return parser


def _split_sandbox_command(argv):
    """`keyveil sandbox [opts] -- cmd args`: everything after the first `--` is the command."""
    if "sandbox" in argv and "--" in argv[argv.index("sandbox") :]:
        cut = argv.index("--", argv.index("sandbox"))
        return argv[:cut], argv[cut + 1 :]
    return argv, None


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    argv, command = _split_sandbox_command(argv)
    args = build_parser().parse_args(argv)
    if command is not None:
        args.command = command
    try:
        return args.func(args)
    except (CLIError, cfgmod.ConfigError) as e:
        print("keyveil: %s" % e, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
