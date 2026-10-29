# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Renders each binding's API reference into the site from its sources,
so the pages cannot drift from the code: the Python package's docstrings
and signatures (read with ast, nothing imported), the npm package's type
declarations and their doc comments, and the R package's Rd files.

Writes src/content/docs/reference/api/{python,javascript,r}.md. Run from
docs/site (npm runs it before dev and build); standard library only.
"""
import ast
import os
import re
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
OUT = os.path.join("src", "content", "docs", "reference", "api")
NOTE = ("Generated from {src} by docs/site/scripts/api.py when the site is "
        "built; edit the source, not this page.")


def page(title, desc, src, body):
    return ("---\ntitle: %s\ndescription: %s\n---\n\n:::note\n%s\n:::\n\n%s"
            % (title, desc, NOTE.format(src=src), body.rstrip() + "\n"))


def fence(lang, code):
    return "```%s\n%s\n```\n" % (lang, code.rstrip())


# ---- Python ------------------------------------------------------------

PYMODS = [("noqtis", "__init__.py"), ("noqtis.sign", "sign.py"),
          ("noqtis.kem", "kem.py"), ("noqtis.keyfile", "keyfile.py"),
          ("Errors", "_err.py")]


def pysig(name, fn):
    a = ast.unparse(fn.args)
    r = " -> " + ast.unparse(fn.returns) if fn.returns is not None else ""
    return "%s(%s)%s" % (name, a, r)


def pydoc(d):
    """A docstring as Markdown: doctest blocks fenced, the rest as text."""
    out, code = [], []
    for line in (d or "").strip().splitlines():
        if line.strip().startswith(">>>"):
            code.append(line.strip())
            continue
        if code:
            out.append(fence("python", "\n".join(code)))
            code = []
        out.append(line)
    if code:
        out.append(fence("python", "\n".join(code)))
    return "\n".join(out).strip()


def python():
    base = os.path.join(ROOT, "bindings", "py", "noqtis")
    parts = []
    for mod, f in PYMODS:
        tree = ast.parse(open(os.path.join(base, f), encoding="utf-8").read())
        parts.append("## %s\n" % ("`%s`" % mod if mod != "Errors" else mod))
        d = ast.get_docstring(tree)
        if d and mod != "Errors":
            parts.append(pydoc(d) + "\n")
        for n in tree.body:
            if isinstance(n, ast.FunctionDef) and not n.name.startswith("_"):
                q = n.name if mod == "noqtis" else "%s.%s" % (mod, n.name)
                parts.append("### `%s`\n" % q)
                parts.append(fence("python", pysig(q, n)))
                parts.append(pydoc(ast.get_docstring(n)) + "\n")
            elif isinstance(n, ast.ClassDef) and not n.name.startswith("_"):
                q = "noqtis." + n.name
                bases = ", ".join(ast.unparse(b) for b in n.bases)
                parts.append("### `%s`\n" % q)
                parts.append(fence("python", "class %s(%s)" % (n.name, bases)))
                parts.append(pydoc(ast.get_docstring(n)) + "\n")
                for m in n.body:
                    if isinstance(m, ast.FunctionDef) and \
                            not m.name.startswith("_") and ast.get_docstring(m):
                        parts.append("- `%s`: %s" % (
                            m.name, pydoc(ast.get_docstring(m))))
                parts.append("")
    return page("Python API", "Every public function and class of the noqtis "
                "Python package, from its docstrings.",
                "bindings/py/noqtis/*.py", "\n".join(parts))


# ---- JavaScript ---------------------------------------------------------

def jsdecls(text):
    """(doc, declaration) for each top-level declaration, in order; doc is
    the /** */ comment right above it, or ""."""
    out, doc, i = [], "", 0
    lines = text.splitlines()
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("/**"):
            j = i
            while "*/" not in lines[j]:
                j += 1
            doc = " ".join(re.sub(r"^\s*(/\*\*|\*/|\*)\s?", "", x).replace(
                "*/", "").strip() for x in lines[i:j + 1]).strip()
            i = j + 1
            continue
        if ln.startswith("export ") or ln.startswith("declare "):
            j, depth = i, 0
            while j < len(lines):
                depth += lines[j].count("{") - lines[j].count("}")
                if depth <= 0 and lines[j].rstrip().endswith((";", "}")):
                    break
                j += 1
            out.append((doc, "\n".join(lines[i:j + 1])))
            doc = ""
            i = j + 1
            continue
        doc = ""
        i += 1
    return out


def javascript():
    lib = os.path.join(ROOT, "bindings", "npm", "lib")
    parts = []
    for f, title in (("index.d.ts", "`noqtis`"), ("node.d.ts", "`noqtis/node`")):
        parts.append("## %s\n" % title)
        text = open(os.path.join(lib, f), encoding="utf-8").read()
        for doc, d in jsdecls(text):
            if d.startswith("export default") or d.startswith("declare const _default"):
                continue
            m = re.match(r"export (?:declare )?(?:const|function|class|interface|type) (\w+)", d)
            if m:
                parts.append("### `%s`\n" % m.group(1))
            if doc:
                parts.append(doc + "\n")
            parts.append(fence("ts", d))
    return page("JavaScript API", "Every export of the noqtis npm package, "
                "from its type declarations.",
                "bindings/npm/lib/*.d.ts", "\n".join(parts))


# ---- R -------------------------------------------------------------------

def rdgroup(s, i):
    """The text of the brace group opening at s[i] == '{', and the index
    after its closing brace."""
    depth, j = 0, i
    while j < len(s):
        c = s[j]
        if c == "\\" and j + 1 < len(s) and s[j + 1] in "{}%\\":
            j += 2
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return s[i + 1:j], j + 1
        j += 1
    raise ValueError("unbalanced Rd braces")


def rdargs(s, i, n):
    """n brace groups starting at s[i] (whitespace between allowed)."""
    out = []
    for _ in range(n):
        while i < len(s) and s[i] in " \t\n":
            i += 1
        if i >= len(s) or s[i] != "{":
            break
        g, i = rdgroup(s, i)
        out.append(g)
    return out, i


SIMPLE = {"code": "`%s`", "emph": "*%s*", "strong": "**%s**",
          "bold": "**%s**", "sQuote": "'%s'", "dQuote": '"%s"',
          "pkg": "%s", "var": "*%s*", "file": "`%s`", "env": "`%s`",
          "samp": "`%s`", "option": "`%s`", "verb": "`%s`", "eqn": "%s",
          "acronym": "%s", "dfn": "*%s*", "cite": "%s", "kbd": "`%s`",
          "email": "%s", "url": "<%s>", "method": "%s"}


def rdtext(s):
    """Rd text as Markdown."""
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "%":  # an Rd comment
            j = s.find("\n", i)
            i = len(s) if j < 0 else j
            continue
        if c == "\\" and i + 1 < len(s) and s[i + 1] in "{}%\\":
            out.append(s[i + 1])
            i += 2
            continue
        if c != "\\":
            out.append(c)
            i += 1
            continue
        m = re.match(r"\\([A-Za-z]+)(\[[^\]]*\])?", s[i:])
        if not m:
            out.append(c)
            i += 1
            continue
        name, opt = m.group(1), m.group(2)
        i += m.end()
        if name in ("R",):
            out.append("R")
            if s[i:i + 2] == "{}":
                i += 2
        elif name in ("dots", "ldots"):
            out.append("...")
            if s[i:i + 2] == "{}":
                i += 2
        elif name == "cr":
            out.append("  \n")
        elif name == "tab":
            out.append(" ")
        elif name in SIMPLE:
            (g,), i = rdargs(s, i, 1)
            inner = rdtext(g)
            if SIMPLE[name].startswith("`"):
                inner = inner.replace("`", "")
            out.append(SIMPLE[name] % inner)
        elif name == "link":
            (g,), i = rdargs(s, i, 1)
            out.append(rdtext(g))
        elif name == "href":
            (u, t), i = rdargs(s, i, 2)
            out.append("[%s](%s)" % (rdtext(t), u.strip()))
        elif name in ("itemize", "enumerate"):
            (g,), i = rdargs(s, i, 1)
            items = [x.strip() for x in g.split("\\item")[1:]]
            mark = "-" if name == "itemize" else "1."
            out.append("\n" + "\n".join("%s %s" % (mark, rdtext(x)) for x in items)
                       + "\n")
        elif name == "describe":
            (g,), i = rdargs(s, i, 1)
            out.append("\n" + rditems(g) + "\n")
        elif name in ("preformatted", "deqn"):
            (g,), i = rdargs(s, i, 1)
            out.append("\n" + fence("", g.strip("\n")))
        elif name == "if":
            (fmt, g), i = rdargs(s, i, 2)
            if fmt.strip() in ("html", "text"):
                out.append(rdtext(g))
        elif name == "ifelse":
            (fmt, a, b), i = rdargs(s, i, 3)
            out.append(rdtext(a if fmt.strip() in ("html", "text") else b))
        elif name in ("out", "figure", "enc"):
            g, i = rdargs(s, i, 1)
            out.append(rdtext(g[0]) if g and name == "enc" else "")
        else:  # unknown macro: keep its text
            g, i = rdargs(s, i, 1)
            out.append(rdtext(g[0]) if g else "")
    t = "".join(out)
    t = re.sub(r"[ \t]+\n", "\n", t)
    return re.sub(r"\n{3,}", "\n\n", t).strip()


def rditems(g):
    rows, i = [], 0
    while True:
        k = g.find("\\item", i)
        if k < 0:
            break
        (a, b), i = rdargs(g, k + 5, 2)
        rows.append("- `%s`: %s" % (rdtext(a).replace("`", ""), rdtext(b)))
    return "\n".join(rows)


def rdsections(s):
    """{section: [raw text, ...]} of an Rd file."""
    secs, i = {}, 0
    while i < len(s):
        m = re.compile(r"\\([A-Za-z]+)\s*\{").search(s, i)
        if not m:
            break
        name = m.group(1)
        if name == "section":
            (t, b), i = rdargs(s, m.end() - 1, 2)
            secs.setdefault("section", []).append((t, b))
            continue
        g, i = rdgroup(s, m.end() - 1)
        secs.setdefault(name, []).append(g)
    return secs


def r():
    man = os.path.join(ROOT, "bindings", "r", "man")
    files = sorted(f for f in os.listdir(man) if f.endswith(".Rd"))
    files = [f for f in files if f == "noqtis-package.Rd"] + \
        [f for f in files if f != "noqtis-package.Rd"]
    parts = []
    for f in files:
        sec = rdsections(open(os.path.join(man, f), encoding="utf-8").read())
        if sec.get("keyword") == ["internal"]:
            continue
        title = rdtext(sec.get("title", [""])[0])
        names = [rdtext(a) for a in sec.get("alias", [])] or \
            [rdtext(sec["name"][0])]
        parts.append("## %s\n" % ", ".join("`%s`" % n for n in names
                                           if "-package" not in n) if
                     f != "noqtis-package.Rd" else "## The package\n")
        parts.append("*%s*\n" % title)
        if "usage" in sec:
            parts.append(fence("r", rdtext(sec["usage"][0]).replace("`", "")))
        for k in ("description",):
            for b in sec.get(k, []):
                parts.append(rdtext(b) + "\n")
        if "arguments" in sec:
            parts.append("**Arguments**\n\n" + rditems(sec["arguments"][0]) + "\n")
        if "value" in sec:
            parts.append("**Value**\n\n" + rdtext(sec["value"][0]) + "\n")
        for b in sec.get("details", []):
            parts.append("**Details**\n\n" + rdtext(b) + "\n")
        for t, b in sec.get("section", []):
            parts.append("**%s**\n\n%s\n" % (rdtext(t), rdtext(b)))
        if "examples" in sec:
            ex = re.sub(r"\\dontrun\{|\\donttest\{|\\dontshow\{", "{",
                        sec["examples"][0])
            parts.append("**Examples**\n\n" + fence("r", ex.strip("\n").replace(
                "\\%", "%")))
    return page("R API", "Every exported function of the noqtis R package, "
                "from its help pages.", "bindings/r/man/*.Rd",
                "\n".join(parts))


def main():
    os.makedirs(OUT, exist_ok=True)
    for name, fn in (("python", python), ("javascript", javascript), ("r", r)):
        p = os.path.join(OUT, name + ".md")
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(fn())
        print("api.py: %s" % p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
