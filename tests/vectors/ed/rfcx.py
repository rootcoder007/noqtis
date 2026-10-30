# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# extract RFC 8032 sections 7.1-7.3 test vectors into JSON
import json, re, sys
t = open(sys.argv[1]).read().split("\n")
s = next(i for i, l in enumerate(t) if l.startswith("7.1.  Test Vectors for Ed25519"))
e = next(i for i, l in enumerate(t) if l.startswith("7.4."))
lines = t[s:e]
hexre = re.compile(r"^\s+([0-9a-f]{2,})\s*$")
out, cur, key = [], None, None
for l in lines:
    st = l.strip()
    if st == "ALGORITHM:":
        cur = {"alg": None, "sk": "", "pk": "", "msg": "", "ctx": "", "sig": ""}
        out.append(cur); key = "alg"; continue
    if cur is None: continue
    m = re.match(r"^(SECRET KEY|PUBLIC KEY|MESSAGE|CONTEXT|SIGNATURE)", st)
    if m:
        key = {"SECRET KEY": "sk", "PUBLIC KEY": "pk", "MESSAGE": "msg",
               "CONTEXT": "ctx", "SIGNATURE": "sig"}[m.group(1)]
        continue
    if key == "alg" and st:
        cur["alg"] = st; key = None; continue
    h = hexre.match(l)
    if h and key in ("sk", "pk", "msg", "ctx", "sig"):
        cur[key] += h.group(1)
for v in out:
    assert len(v["sk"]) == 64 and len(v["pk"]) == 64 and len(v["sig"]) == 128, v
json.dump({"source": "RFC 8032 sections 7.1-7.3", "tests": out}, sys.stdout, indent=1)
print(file=sys.stderr, end=f"{len(out)} vectors: " + ", ".join(sorted(set(v['alg'] for v in out))) + "\n")
