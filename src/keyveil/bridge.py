"""TCP <-> Unix socket relay used by `keyveil sandbox` when the agent has its own network.

Inside the sandbox (run as a script with any python3 >= 3.8, standard library only):

    python3 -I bridge.py PORT SOCKET -- COMMAND [ARGS...]

forks a listener on 127.0.0.1:PORT (and [::1]:PORT if possible) that relays every
connection to the Unix socket SOCKET, waits until it is listening, then execs COMMAND.
The socket is served by the `keyveil sandbox` supervisor outside, which relays on to the
real proxy on the host's 127.0.0.1:PORT. Nothing else on the host's loopback is reachable.

If the agent kills the listener it only cuts off its own access to the proxy.
"""

import os
import signal
import socket
import sys
import threading


def pump(src, dst):
    """Copy bytes from ``src`` to ``dst`` until EOF, then half-close ``dst``."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def splice(a, b):
    """Relay both directions between two connected sockets, then close both."""
    t = threading.Thread(target=pump, args=(b, a), daemon=True)
    t.start()
    pump(a, b)
    t.join()
    a.close()
    b.close()


def serve(listeners, connect):
    """Accept on every listener; relay each client to a socket made by ``connect()``."""

    def handle(client):
        try:
            upstream = connect()
        except OSError:
            client.close()
            return
        splice(client, upstream)

    def accept_loop(srv):
        while True:
            try:
                client, _ = srv.accept()
            except OSError:
                return  # listener closed
            threading.Thread(target=handle, args=(client,), daemon=True).start()

    threads = [threading.Thread(target=accept_loop, args=(s,), daemon=True) for s in listeners]
    for t in threads:
        t.start()
    return threads


def _listen(family, host, port):
    srv = socket.socket(family)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    srv.bind((host, port))
    srv.listen(64)
    return srv


def _connect_unix(path):
    s = socket.socket(socket.AF_UNIX)
    try:
        s.connect(path)
    except OSError:
        s.close()
        raise
    return s


def main(argv):
    if len(argv) < 4 or argv[2] != "--":
        sys.exit("usage: bridge.py PORT SOCKET -- COMMAND [ARGS...]")
    port, path, command = int(argv[0]), argv[1], argv[3:]
    listeners = [_listen(socket.AF_INET, "127.0.0.1", port)]
    try:
        listeners.append(_listen(socket.AF_INET6, "::1", port))
    except OSError:
        pass  # no IPv6 loopback in this namespace
    ready_r, ready_w = os.pipe()
    if os.fork() == 0:  # the listener: detached from the terminal, immune to Ctrl-C
        os.close(ready_r)
        os.setsid()
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1):
            os.dup2(devnull, fd)
        threads = serve(listeners, lambda: _connect_unix(path))
        os.write(ready_w, b"1")
        os.close(ready_w)
        for t in threads:
            t.join()
        os._exit(0)
    os.close(ready_w)
    os.read(ready_r, 1)
    os.close(ready_r)
    for s in listeners:
        s.close()  # the child owns them now
    try:
        os.execvp(command[0], command)  # noqa: S606 - the agent command (argv list, no shell)
    except OSError as e:
        sys.exit("keyveil sandbox: cannot run %s: %s" % (command[0], e.strerror))


if __name__ == "__main__":
    main(sys.argv[1:])
