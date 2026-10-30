#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Release notes from NEWS.md: the section of one version, unwrapped.

    python3 packaging/notes.py <version> [NEWS.md]

NEWS.md is wrapped at 72 columns; GitHub shows each of those line
breaks in a release body. This prints the section headed
"# noqtis <version>" with each paragraph and each list item joined onto
one line (nested items keep their indent), and headings, blank lines and
code blocks left as they are. Exits 1 when the section is missing or
empty.
"""
import re
import sys


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: notes.py <version> [NEWS.md]")
    head = "# noqtis " + sys.argv[1]
    path = sys.argv[2] if len(sys.argv) == 3 else "NEWS.md"
    lines, keep = [], False
    for line in open(path, encoding="utf-8").read().splitlines():
        if re.match(r"^# ", line):
            keep = line.strip() == head
            continue
        if keep:
            lines.append(line)
    out, cur, fence = [], None, False
    item = re.compile(r"^(\s*)([-*+]|\d+[.)])\s+")

    def flush():
        nonlocal cur
        if cur is not None:
            out.append(cur)
            cur = None

    for line in lines:
        if line.lstrip().startswith("```"):
            flush()
            fence = not fence
            out.append(line)
            continue
        if fence:
            out.append(line)
            continue
        if not line.strip():
            flush()
            out.append("")
        elif line.startswith("#") or line.lstrip().startswith("|"):
            flush()
            out.append(line)
        elif item.match(line):
            flush()
            cur = line.rstrip()
        elif cur is not None:
            cur += " " + line.strip()
        else:
            cur = line.strip()
    flush()
    text = "\n".join(out).strip("\n")
    if not text.strip():
        sys.exit(f"notes.py: no {head!r} section in {path}")
    print(text)


main()
