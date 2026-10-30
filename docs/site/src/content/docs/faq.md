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
See [why post-quantum provenance now](/noqtis/explain/why/).

## How is this different from `sha256sum` plus GPG, or from Sigstore?

`sha256sum` lists digests but does not notice added files, links or case
collisions, and GPG signatures are not post-quantum. Sigstore signs
artifacts with short-lived certificates and a transparency log, which needs
the network and trusts its services. NOQTIS is one offline file format and
library: the manifest records every file with two digests, the check also
fails on anything extra, and the signature is post-quantum. They can be
combined: sign a capsule's `noqtis.json` with another tool as well, if you
like. [How NOQTIS compares](/noqtis/explain/compare/) and the
coming-from pages ([sha256sum and GPG](/noqtis/from/sha256sum-gpg/),
[minisign](/noqtis/from/minisign/), [Sigstore](/noqtis/from/sigstore/),
[BagIt](/noqtis/from/bagit/)) go into detail.

## Is it audited?

Not yet. An independent audit through OSTIF has been applied for and is
open for [funding](https://app.lfx.dev/crowdfunding/initiatives/noqtis-security-audit-of-a-post-quantum-signing-and-provenance-library-in-c11). See the [security page](/noqtis/security/)
for how NOQTIS is tested meanwhile.

## Which algorithm should I use?

ML-DSA-65 by default. SLH-DSA (for example `SLH-DSA-SHAKE-128s`) if you
want security that rests on hash functions alone and can accept larger
signatures. See [keys](/noqtis/guides/keys/).

## Does a check need the network?

No. Checking reads only the folder, the public key and, for a timestamp,
the TSA's certificate (`--anchor`). Timestamps need a TSA once, when
sealing (`noqtis seal --tsa <url>`), never when checking. The network is
used only when you ask for it: `noqtis check <url>` fetches a published
capsule's files and checks them as it would a folder.

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

It holds a symbolic link, a special file, a NOQTIS secret key, a name
that is not portable (control characters, `\`, `:`, invalid UTF-8), two
names that differ only in case, or exceeds a limit. See
[what cannot be sealed](/noqtis/guides/seal/#what-cannot-be-sealed).

## Can I change a capsule and keep the seal?

No: any change fails the check. Seal again (with the same key), which
replaces `noqtis.json` and `noqtis.sig`.

## Is `dec` returning a wrong secret a bug?

No. ML-KEM and HQC use implicit rejection: a tampered ciphertext gives an
unrelated secret rather than an error, so an attacker learns nothing from
failures. Use the secret with an authenticated cipher, which will then
fail.

## Can I use NOQTIS from Python, JavaScript, R, Rust, Go or Java?

Yes: npm (WebAssembly), PyPI, r-universe (and CRAN after its review),
crates.io, a Go module and Maven Central (Java 22 or later, with the
library inside the jar), published with the first release and
installable from the repository until then. See the tutorials for [Python](/noqtis/guides/py/),
[JavaScript](/noqtis/guides/js/), [R](/noqtis/guides/r/),
[Rust](/noqtis/guides/rust/), [Go](/noqtis/guides/go/) and
[Java](/noqtis/guides/java/). Anything that
can call C can use `libnoqtis` directly ([C tutorial](/noqtis/guides/c/)).

## How do I cite NOQTIS?

With the metadata in
[`CITATION.cff`](https://github.com/rootcoder007/noqtis/blob/main/CITATION.cff)
(GitHub's "Cite this repository" button reads it).

## What is the licence?

Apache-2.0 WITH LLVM-exception.
