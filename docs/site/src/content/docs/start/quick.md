---
title: Your first capsule
description: Make a key, seal a folder, check it, and watch a change fail the check.
---

A **capsule** is an ordinary folder with two extra files: `noqtis.json`
lists every file with its size and digests, and `noqtis.sig` signs that
list. Anyone with the public key can later check that the folder holds
exactly the files that were sealed.

## 1. Make a key pair

```sh
$ noqtis keygen -a ML-DSA-65 -o me
ML-DSA-65 key pair: me (secret), me.pub (public)
```

`me` is the secret key (created readable by you only); `me.pub` is the
public key you give to others. ML-DSA-65 is a good default; see
[keys](/noqtis/guides/keys/) for the others.

## 2. Seal a folder

```sh
$ mkdir -p results/data
$ printf 'a,b\n' > results/data/in.csv
$ printf 'r\n' > results/report.txt
$ noqtis seal -k me results
sealed results with ML-DSA-65
```

## 3. Check it

```sh
$ noqtis check -p me.pub results
      check               detail
ok    seal.read           noqtis.sig
...
ok    signature           ML-DSA-65 signature over noqtis.json is valid
ok    folder              listed
ok    file                data/in.csv
ok    file                report.txt
...
results: OK (22 checks passed)
```

The exit status is 0.

## 4. Change something

```sh
$ echo extra >> results/report.txt
$ touch results/new.txt
$ noqtis check -p me.pub results; echo $?
...
FAIL  file                report.txt: size differs
...
FAIL  extra               new.txt: not in the manifest
results: FAILED (2 of 23 checks failed)
1
```

Every change shows: a changed byte (through the size or either digest), a
removed file, an added file, a renamed file, an edited manifest or seal, a
seal by another key.

## Next

- [Seal and check a capsule](/noqtis/guides/seal/): metadata, reproducible
  capsules, what can and cannot be sealed.
- [Check someone else's capsule](/noqtis/guides/others/): what a passing
  check proves.
- [The capsule format](/noqtis/spec/capsule/).
