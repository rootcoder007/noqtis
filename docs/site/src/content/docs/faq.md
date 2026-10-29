---
title: FAQ
description: Common questions about NOQTIS, capsules and post-quantum signatures.
---

## What is NOQTIS for?

Making results traceable: a paper's figures, a dataset release, a build
output or a model can be sealed together with the exact inputs, so that
anyone can check later, offline, that they have the very same files and
who sealed them. The name stands for **N**otary **O**f **Q**uantum-safe
**T**raceable **I**nputs and **S**eals.

## Why post-quantum now?

Records like these must stay checkable for decades, longer than RSA and
elliptic-curve signatures are expected to remain safe once large quantum
computers exist. ML-DSA and SLH-DSA are the NIST standards (FIPS 204 and
205, 2024) designed to resist them. Sealing with them today means the
seals do not need redoing later.

## How is this different from `sha256sum` plus GPG, or from Sigstore?

`sha256sum` lists digests but does not notice added files, links or case
collisions, and GPG signatures are not post-quantum. Sigstore signs
artifacts with short-lived certificates and a transparency log, which needs
the network and trusts its services. NOQTIS is one offline file format and
library: the manifest records every file with two digests, the check also
fails on anything extra, and the signature is post-quantum. They can be
combined: sign a capsule's `noqtis.json` with another tool as well, if you
like.

## Is it audited?

Not yet. See the [security page](/noqtis/security/).

## Which algorithm should I use?

ML-DSA-65 by default. SLH-DSA (for example `SLH-DSA-SHAKE-128s`) if you
want security that rests on hash functions alone and can accept larger
signatures. See [keys](/noqtis/guides/keys/).

## Does a check need the network?

No. Checking reads only the folder and the public key. Timestamps need a
TSA once, when sealing (not yet in the command-line tool), never when
checking.

## Can I put the capsule in Git, a ZIP or a tarball?

Yes, as long as the transport keeps bytes exactly: turn off line-ending
conversion in Git (`* -text` in `.gitattributes` for the capsule) and keep
names' case. `tar` keeps everything NOQTIS checks.

## Why does `noqtis check` pass without `-p`?

Because a capsule carries its own public key, it can always be checked for
integrity. That shows the files are unchanged since *someone* sealed them.
To know who, pin their key with `-p`. The report and a note on standard
error say when the key was not pinned.

## Why was my folder refused by `seal`?

It holds a symbolic link, a special file, a name that is not portable
(control characters, `\`, `:`, invalid UTF-8), two names that differ only
in case, or exceeds a limit. See
[what cannot be sealed](/noqtis/guides/seal/#what-cannot-be-sealed).

## Can I change a capsule and keep the seal?

No: any change fails the check. Seal again (with the same key), which
replaces `noqtis.json` and `noqtis.sig`.

## Is `dec` returning a wrong secret a bug?

No. ML-KEM and HQC use implicit rejection: a tampered ciphertext gives an
unrelated secret rather than an error, so an attacker learns nothing from
failures. Use the secret with an authenticated cipher, which will then
fail.

## Can I use NOQTIS from Python, JavaScript or R?

Bindings for npm (WebAssembly), PyPI and CRAN are being prepared for the
first release; see [install](/noqtis/start/install/). Anything that can call
C can use `libnoqtis` directly.

## How do I cite NOQTIS?

A `CITATION.cff` and a Zenodo DOI will come with the first release.

## What is the licence?

Apache-2.0 WITH LLVM-exception.
