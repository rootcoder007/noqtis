# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Writes mu.txt, a few records of the ACVP ML-DSA external-mu groups
(sigGen: the first test of each deterministic and each randomised group,
sigVer: the first passing and the first failing test of each group), as
key=value text the bindings' tests read without a JSON parser:
    python3 -I mu.py > mu.txt
"""
import json
import os

H = os.path.dirname(os.path.abspath(__file__))


def load(d, f):
    with open(os.path.join(H, d, f), encoding="utf-8") as fh:
        return json.load(fh)


def groups(d):
    p, e = load(d, "prompt.json"), load(d, "expectedResults.json")
    ex = {g["tgId"]: {t["tcId"]: t for t in g["tests"]}
          for g in e["testGroups"]}
    for g in p["testGroups"]:
        if g.get("externalMu") is True:
            yield g, ex[g["tgId"]]


print("# ML-DSA with an external mu: records of the ACVP sets in")
print("# ML-DSA-sigGen-FIPS204 and ML-DSA-sigVer-FIPS204, written by mu.py.")
print("# kind gen: the signature of mu under the secret key key with rnd")
print("# (32 zero bytes for a deterministic group); kind ver: whether sig")
print("# verifies for mu under the public key key (ok 1 or 0).")
for g, ex in groups("ML-DSA-sigGen-FIPS204"):
    t = g["tests"][0]
    print()
    print("alg=%s" % g["parameterSet"])
    print("kind=gen")
    print("key=%s" % t["sk"].lower())
    print("mu=%s" % t["mu"].lower())
    print("rnd=%s" % ("00" * 32 if g["deterministic"] else t["rnd"].lower()))
    print("sig=%s" % ex[t["tcId"]]["signature"].lower())
    print("ok=1")
for g, ex in groups("ML-DSA-sigVer-FIPS204"):
    for want in (True, False):
        t = next(t for t in g["tests"] if ex[t["tcId"]]["testPassed"] is want)
        print()
        print("alg=%s" % g["parameterSet"])
        print("kind=ver")
        print("key=%s" % t["pk"].lower())
        print("mu=%s" % t["mu"].lower())
        print("rnd=")
        print("sig=%s" % t["signature"].lower())
        print("ok=%d" % want)
