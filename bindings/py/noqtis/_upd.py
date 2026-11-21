# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""The notice of a newer release.

The package asks nothing of the network on its own. With the environment
variable ``NOQTIS_UPDATE_CHECK`` set to anything, ``import noqtis`` in an
interactive session (the Python prompt, IPython, a notebook) says in one
line on standard error when a newer release exists. The page of the latest
release is then asked for at most once a day, in a thread, with a limit of
two seconds, and the answer is kept in the cache directory of the user; the
notice itself reads only that file. Nothing is sent but the request. A
script never asks, and neither does a session with the environment variable
``NOQTIS_NO_UPDATE_CHECK`` set to anything.
"""

from __future__ import annotations

import os
import re
import sys
import threading
import time
from typing import Callable, Optional

HOST = "github.com"
PATH = "/rootcoder007/noqtis/releases/latest"
DAY = 86400.0
_TAG = re.compile(r"/releases/tag/v([0-9]+(?:\.[0-9]+)*)\s*$")
_VER = re.compile(r"[0-9]+(?:\.[0-9]+)*$")


def parse(location: Optional[str]) -> Optional[str]:
    """The version in the Location header of the answer, or None."""
    m = _TAG.search(location or "")
    return m.group(1) if m else None


def latest(timeout: float = 2.0) -> Optional[str]:
    """The version of the latest release, or None when it cannot be had."""
    import http.client

    try:
        c = http.client.HTTPSConnection(HOST, timeout=timeout)
        try:
            c.request("HEAD", PATH, headers={"User-Agent": "noqtis"})
            return parse(c.getresponse().getheader("Location"))
        finally:
            c.close()
    except Exception:  # no network, no TLS, another answer: no notice
        return None


def key(v: str) -> tuple[int, ...]:
    """A version as numbers, for comparison."""
    return tuple(int(x) for x in re.findall(r"[0-9]+", v))


def cache() -> str:
    """The file that keeps the last answer and its time."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "noqtis", "update-py")


def read(path: str) -> tuple[float, Optional[str]]:
    """The time and the version kept in the file; (0, None) without one."""
    try:
        with open(path, encoding="ascii") as f:
            t, _, v = f.read(64).strip().partition(" ")
        return float(t), v if _VER.match(v) else None
    except (OSError, ValueError):
        return 0.0, None


def write(path: str, now: float, v: Optional[str]) -> None:
    """Keep the answer; a place that cannot be written is left alone."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="ascii") as f:
            f.write(f"{now:.0f} {v or '-'}\n")
    except OSError:
        pass


def off(live: bool) -> bool:
    """Is the notice off: it is, unless NOQTIS_UPDATE_CHECK asks for it."""
    if not live or os.environ.get("NOQTIS_NO_UPDATE_CHECK"):
        return True
    return not os.environ.get("NOQTIS_UPDATE_CHECK")


def message(cur: str, path: str, now: float, ask: Callable[[], None]) -> Optional[str]:
    """The text of the notice from the kept answer, or None; ``ask`` is
    called when that answer is older than a day."""
    t, v = read(path)
    if now < t or now - t >= DAY:
        ask()
    if v is None or key(v) <= key(cur):
        return None
    return (
        f"noqtis {v} is available (this is {cur}): https://{HOST}{PATH}\n"
        "NOQTIS_NO_UPDATE_CHECK=1 stops this notice."
    )


def notify(cur: str) -> None:
    """Called by ``import noqtis``; never raises."""
    try:
        live = hasattr(sys, "ps1") or bool(sys.flags.interactive)
        if off(live):
            return
        path = cache()

        def ask() -> None:
            # the day is counted from the question; the thread is not a
            # daemon, so the interpreter never ends under an open connection
            write(path, time.time(), read(path)[1])
            threading.Thread(
                target=lambda: write(path, time.time(), latest()), name="noqtis-update"
            ).start()

        m = message(cur, path, time.time(), ask)
        if m:
            print(m, file=sys.stderr)
    except Exception:
        pass
