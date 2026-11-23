#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
"""Records a command's terminal output as an asciicast (version 2).

    python3 docs/demo/rec.py demo.cast sh docs/demo/demo.sh [noqtis]

The command runs under a pseudo-terminal 92 columns by 24 rows; each piece
of output is written with the time it came. One more event (" ") is added
5 s after the last, so the final frame holds before a player loops. Needs
no terminal recorder.
"""
import json
import os
import pty
import struct
import sys
import time

COLS, ROWS, HOLD = 92, 24, 5.0


def main(argv):
    if len(argv) < 3:
        sys.stderr.write("usage: rec.py <out.cast> <command> [args]\n")
        return 2
    out, cmd = argv[1], argv[2:]
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.environ["COLUMNS"], os.environ["LINES"] = str(COLS), str(ROWS)
        os.execvp(cmd[0], cmd)
    try:
        import fcntl
        import termios
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    except OSError:
        pass
    t0 = time.monotonic()
    last = 0.0
    events = []
    while True:
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        last = time.monotonic() - t0
        events.append([round(last, 3), "o", data.decode("utf-8", "replace")])
    _, status = os.waitpid(pid, 0)
    events.append([round(last + HOLD, 3), "o", " "])
    with open(out, "w", encoding="utf-8") as f:
        f.write(json.dumps({"version": 2, "width": COLS, "height": ROWS}) + "\n")
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    sys.stderr.write("%d events, %.1f seconds -> %s\n" % (len(events), last + HOLD, out))
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
