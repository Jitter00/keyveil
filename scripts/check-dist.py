#!/usr/bin/env python3
"""Check built distributions before they are published.

Usage: check-dist.py DIST_DIR VERSION

Fails if the wheel or sdist is missing, has the wrong version, or contains anything that
should never ship (secrets-looking files, local config, virtualenvs, caches, test scratch).
"""

import fnmatch
import sys
import tarfile
import zipfile
from pathlib import Path

FORBIDDEN = [
    "*.age",
    "*/.env",
    ".env",
    "*/.env.*[!e]",  # .env.local etc.; .env.example is allowed
    "*routes.json",
    "*keyveil.conf",
    "*/.git/*",
    "*/.venv/*",
    "*/__pycache__/*",
    "*.pyc",
    "*/.sandbox-test-*",
    "*.swp",
]


def fail(msg):
    print("check-dist: FAIL: " + msg)
    sys.exit(1)


def forbidden(names):
    return sorted(n for n in names if any(fnmatch.fnmatchcase(n, p) for p in FORBIDDEN))


def main(dist, version):
    dist = Path(dist)
    wheels = list(dist.glob("keyveil-%s-*.whl" % version))
    sdists = list(dist.glob("keyveil-%s.tar.gz" % version))
    if len(wheels) != 1 or len(sdists) != 1:
        fail(
            "expected one wheel and one sdist for %s, found %s" % (version, sorted(dist.iterdir()))
        )

    with zipfile.ZipFile(wheels[0]) as zf:
        wheel_names = zf.namelist()
    info = "keyveil-%s.dist-info/" % version
    stray = [n for n in wheel_names if not (n.startswith("keyveil/") or n.startswith(info))]
    if stray:
        fail("wheel contains files outside the package: %s" % stray)
    for required in ("keyveil/proxy.py", "keyveil/cli.py", info + "licenses/LICENSE"):
        if required not in wheel_names:
            fail("wheel is missing %s" % required)

    with tarfile.open(sdists[0]) as tf:
        sdist_names = tf.getnames()
    root = "keyveil-%s/" % version
    for required in ("src/keyveil/proxy.py", "LICENSE", "README.md", "pyproject.toml"):
        if root + required not in sdist_names:
            fail("sdist is missing %s" % required)

    bad = forbidden(wheel_names) + forbidden(sdist_names)
    if bad:
        fail("distributions contain files that must not ship: %s" % bad)

    print(
        "check-dist: OK: %s (%d files), %s (%d files)"
        % (wheels[0].name, len(wheel_names), sdists[0].name, len(sdist_names))
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
