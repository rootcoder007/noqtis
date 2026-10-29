#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Writes the SPDX 2.3 SBOM (JSON) of a release.

noqtis has no dependencies: the library and the command are built from
this repository's sources alone, with the platform's C library and, on
Windows, bcrypt. So the SBOM names the source package (the tagged
commit) and one package per release archive, with its SHA-256, each
GENERATED_FROM the source. The output is a function of its inputs only
(the creation time is SOURCE_DATE_EPOCH), so it is reproducible too.

  sbom.py <dist dir> <version> <commit sha>    > noqtis-<version>.spdx.json
"""
import hashlib
import json
import os
import re
import sys
import time

REPO = "rootcoder007/noqtis"
LICENSE = "Apache-2.0 WITH LLVM-exception"
COPYRIGHT = "Copyright 2026 Vansh Singh Ruhela (rootcoder007)"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 16), b""):
            h.update(block)
    return h.hexdigest()


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: sbom.py <dist dir> <version> <commit sha>")
    dist, ver, sha = sys.argv[1:]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?", ver):
        sys.exit("sbom.py: bad version " + ver)
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        sys.exit("sbom.py: the commit must be a full SHA-1")
    sde = os.environ.get("SOURCE_DATE_EPOCH", "")
    if not sde.isdigit():
        sys.exit("sbom.py: set SOURCE_DATE_EPOCH (the commit time)")
    when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(sde)))
    pat = re.compile(r"noqtis-" + re.escape(ver) +
                     r"-([a-z0-9_]+-[a-z0-9_]+(?:-shared)?)\.(?:tar\.gz|zip)")
    names = sorted(n for n in os.listdir(dist) if pat.fullmatch(n))
    if not names:
        sys.exit("sbom.py: no noqtis-%s-* archives in %s" % (ver, dist))

    tag = "v" + ver
    src = {
        "SPDXID": "SPDXRef-Package-source",
        "name": "noqtis",
        "versionInfo": ver,
        "supplier": "Person: rootcoder007",
        "originator": "Person: rootcoder007",
        "downloadLocation": "git+https://github.com/%s@%s" % (REPO, sha),
        "homepage": "https://github.com/" + REPO,
        "filesAnalyzed": False,
        "licenseConcluded": LICENSE,
        "licenseDeclared": LICENSE,
        "copyrightText": COPYRIGHT,
        "primaryPackagePurpose": "SOURCE",
        "externalRefs": [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": "pkg:github/%s@%s" % (REPO, tag),
        }],
        "comment": "No third-party code: built from this repository alone "
                   "with the platform's C library (and bcrypt on Windows).",
    }
    pkgs = [src]
    rels = [{
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": src["SPDXID"],
    }]
    for n in names:
        target = pat.fullmatch(n).group(1)
        pid = "SPDXRef-Package-" + target.replace("_", "-")
        pkgs.append({
            "SPDXID": pid,
            "name": "noqtis-" + target,
            "versionInfo": ver,
            "packageFileName": n,
            "supplier": "Person: rootcoder007",
            "downloadLocation": "https://github.com/%s/releases/download/%s/%s"
                                % (REPO, tag, n),
            "filesAnalyzed": False,
            "checksums": [{"algorithm": "SHA256",
                           "checksumValue": sha256(os.path.join(dist, n))}],
            "licenseConcluded": LICENSE,
            "licenseDeclared": LICENSE,
            "copyrightText": COPYRIGHT,
            "primaryPackagePurpose": "ARCHIVE",
        })
        rels.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": pid,
        })
        rels.append({
            "spdxElementId": pid,
            "relationshipType": "GENERATED_FROM",
            "relatedSpdxElement": src["SPDXID"],
        })
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "noqtis-" + ver,
        "documentNamespace": "https://github.com/%s/releases/%s/sbom/%s"
                             % (REPO, tag, sha),
        "creationInfo": {
            "created": when,
            "creators": ["Tool: noqtis-packaging-sbom.py",
                         "Person: rootcoder007"],
        },
        "packages": pkgs,
        "relationships": rels,
    }
    json.dump(doc, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
