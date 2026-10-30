#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Runs a guide's code and checks it prints what the page shows.

    python3 docs/examples/guide.py <lang>

<lang> is py, r, go, rust, java or js. The script takes the guide's code
blocks (docs/site/src/content/docs/guides/<lang>.md), runs them against
the binding the calling CI job has built, and fails unless every line of
the page's text blocks (the output the page shows; for R, its "> "
prompt lines left out) appears in the output, in order. For py, r and
js each program (a block that loads the package; for js, one that calls
`await init()` at its top level) runs on its own, against the text block
that follows it. The binding is found as each job leaves it:

  py    the `noqtis` package importable by $PYTHON (default python3)
  r     the `noqtis` package installed for Rscript
  go    the module in bindings/go (a replace directive)
  rust  the crate in bindings/rust (its examples/ directory)
  java  $NQJAR and $NQLIB (the jar and the shared library)
  js    the package in bindings/npm, built (it imports itself by name)
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
GUIDES = ROOT / "docs/site/src/content/docs/guides"
LANGS = {"py": ("python",), "r": ("r",), "go": ("go",), "rust": ("rust",),
         "java": ("java",), "js": ("js",)}


def blocks(md, langs):
    out, cur, lang = [], None, None
    for line in md.read_text(encoding="utf-8").splitlines(keepends=True):
        m = re.match(r"^```(\w*)", line)
        if cur is None and m:
            lang, cur = m.group(1), []
        elif cur is not None and line.startswith("```"):
            if lang in langs:
                out.append("".join(cur))
            cur = None
        elif cur is not None:
            cur.append(line)
    return out


def run(cmd, cwd, env=None):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    sys.stdout.write(p.stdout)
    sys.stderr.write(p.stderr)
    if p.returncode != 0:
        sys.exit(f"guide.py: {cmd[0]} exited {p.returncode}")
    return p.stdout


def expect(want, got, what):
    lines = [l.rstrip() for l in want.splitlines() if l.strip()]
    have = [l.rstrip() for l in got.splitlines()]
    i = 0
    for l in lines:
        while i < len(have) and have[i] != l:
            i += 1
        if i == len(have):
            sys.exit(f"guide.py: {what}: the page shows\n  {l}\nbut the "
                     "output (above) has no such line in that place")
        i += 1
    print(f"guide.py: {what}: {len(lines)} lines as the page shows them")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in LANGS:
        sys.exit("usage: guide.py py|r|go|rust|java|js")
    lang = sys.argv[1]
    md = GUIDES / f"{lang}.md"
    code = blocks(md, LANGS[lang])
    # a page may also show install lines in its language; the program is
    # the block that loads the package
    use = {"py": "import noqtis", "r": "library(noqtis)",
           "js": "\nawait init("}
    if lang in use:
        code = [c for c in code if use[lang] in "\n" + c]
    texts = blocks(md, ("text",))
    if not code or not texts:
        sys.exit(f"guide.py: {md} has no code or no output block")
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="nqguide"))
    if lang in use and len(texts) < len(code):
        sys.exit(f"guide.py: {md} has {len(code)} programs but "
                 f"{len(texts)} output blocks")
    if lang == "py":
        for i, c in enumerate(code):
            f = tmp / f"g{i}.py"
            f.write_text(c)
            got = run([os.environ.get("PYTHON", "python3"), str(f)], tmp)
            expect(texts[i], got, f"py program {i + 1}")
    elif lang == "r":
        for i, c in enumerate(code):
            f = tmp / f"g{i}.R"
            f.write_text(c)
            got = run(["Rscript", "-e",
                       f'source("{f.as_posix()}", print.eval = TRUE)'], tmp)
            want = "\n".join(l for l in texts[i].splitlines()
                             if not l.startswith("> "))
            expect(want, got, f"r program {i + 1}")
    elif lang == "go":
        # each block is a fragment of main; give each its own scope
        body = "".join("\tfunc() {\n" + c + "\t}()\n" for c in code[1:])
        (tmp / "main.go").write_text(
            "package main\n\nimport (\n\t\"bytes\"\n\t\"errors\"\n"
            "\t\"fmt\"\n\t\"os\"\n\t\"path/filepath\"\n\t\"time\"\n\n"
            "\t\"github.com/rootcoder007/noqtis/bindings/go\"\n)\n\n"
            "var _ = bytes.Equal\nvar _ = errors.Is\nvar _ = fmt.Sprint\n"
            "var _ = os.Exit\nvar _ = filepath.Join\nvar _ = time.Now\n\n"
            "func main() {\n" + body + "}\n")
        (tmp / "go.mod").write_text(
            "module nqguide\n\ngo 1.22\n\n"
            "require github.com/rootcoder007/noqtis/bindings/go v0.0.0\n\n"
            "replace github.com/rootcoder007/noqtis/bindings/go => "
            f"{(ROOT / 'bindings/go').as_posix()}\n")
        env = dict(os.environ, GOFLAGS="-mod=mod")
        got = run(["go", "run", "."], tmp, env)
        expect("\n".join(texts[:len(code) - 1]), got, "go")
    elif lang == "rust":
        ex = ROOT / "bindings/rust/examples"
        try:
            for i, c in enumerate(code):
                (ex / f"zguide{i}.rs").write_text(c)
            for i in range(len(code)):
                got = run(["cargo", "run", "-q", "--example", f"zguide{i}"],
                          ROOT / "bindings/rust")
                expect(texts[i], got, f"rust block {i + 1}")
        finally:
            for i in range(len(code)):
                (ex / f"zguide{i}.rs").unlink(missing_ok=True)
    elif lang == "java":
        jar, lib = os.environ["NQJAR"], os.environ["NQLIB"]
        names = []
        for c in code:
            n = re.search(r"public class (\w+)", c).group(1)
            (tmp / f"{n}.java").write_text(c)
            names.append(n)
        run(["javac", "--release", "22", "-cp", jar, "-d", "c"] +
            [f"{n}.java" for n in names], tmp)
        for i, n in enumerate(names):
            got = run(["java", "--enable-native-access=ALL-UNNAMED",
                       f"-Dnoqtis.library={lib}", "-cp",
                       jar + os.pathsep + "c", n], tmp)
            expect(texts[i], got, f"java {n}")
    elif lang == "js":
        # inside the package, so that 'noqtis' and 'noqtis/node' resolve
        # to it by its own name, as they do for a user who installed it
        f = ROOT / "bindings/npm/test" / "zguide.mjs"
        for i, c in enumerate(code):
            try:
                f.write_text(c)
                got = run(["node", str(f)], ROOT / "bindings/npm")
            finally:
                f.unlink(missing_ok=True)
            expect(texts[i], got, f"js program {i + 1}")
    shutil.rmtree(tmp, ignore_errors=True)


main()
