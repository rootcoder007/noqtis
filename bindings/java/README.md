# noqtis for Java <img src="https://raw.githubusercontent.com/rootcoder007/noqtis/main/docs/logo/noqtis-hex-512.png" align="right" height="139" alt="NOQTIS hex logo" />

[![Website](https://img.shields.io/badge/website-noqtis.dev-12706b)](https://noqtis.dev/)
[![ci](https://github.com/rootcoder007/noqtis/actions/workflows/ci.yml/badge.svg)](https://github.com/rootcoder007/noqtis/actions/workflows/ci.yml)
[![coverage](https://github.com/rootcoder007/noqtis/actions/workflows/cov.yml/badge.svg)](https://github.com/rootcoder007/noqtis/actions/workflows/cov.yml)
[![R-CMD-check](https://github.com/rootcoder007/noqtis/actions/workflows/r.yml/badge.svg)](https://github.com/rootcoder007/noqtis/actions/workflows/r.yml)
[![fuzz](https://github.com/rootcoder007/noqtis/actions/workflows/fuzz.yml/badge.svg)](https://github.com/rootcoder007/noqtis/actions/workflows/fuzz.yml)
[![docs](https://github.com/rootcoder007/noqtis/actions/workflows/docs.yml/badge.svg)](https://github.com/rootcoder007/noqtis/actions/workflows/docs.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16049/badge)](https://www.bestpractices.dev/projects/16049)
[![Release](https://img.shields.io/github/v/release/rootcoder007/noqtis?label=release&color=2ea44f)](https://github.com/rootcoder007/noqtis/releases/latest)
[![PyPI](https://img.shields.io/pypi/v/noqtis?label=PyPI&color=3775a9)](https://pypi.org/project/noqtis/)
[![npm](https://img.shields.io/npm/v/noqtis?label=npm&color=cb3837)](https://www.npmjs.com/package/noqtis)
[![crates.io](https://img.shields.io/crates/v/noqtis?label=crates.io&color=f0b400)](https://crates.io/crates/noqtis)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.rootcoder007/noqtis?label=Maven%20Central&color=6f42c1)](https://central.sonatype.com/artifact/io.github.rootcoder007/noqtis)
[![Go Reference](https://pkg.go.dev/badge/github.com/rootcoder007/noqtis/bindings/go.svg)](https://pkg.go.dev/github.com/rootcoder007/noqtis/bindings/go)
[![r-universe](https://rootcoder007.r-universe.dev/badges/noqtis)](https://rootcoder007.r-universe.dev/noqtis)
[![COPR](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fcopr.fedorainfracloud.org%2Fapi_3%2Fpackage%2F%3Fownername%3Drootcoder007%26projectname%3Dnoqtis%26packagename%3Dnoqtis%26with_latest_build%3Dtrue&query=%24.builds.latest.state&label=COPR%20build&color=2ea44f)](https://copr.fedorainfracloud.org/coprs/rootcoder007/noqtis/)
[![OBS](https://build.opensuse.org/projects/home:rootcoder007/packages/noqtis/badge.svg?type=default)](https://build.opensuse.org/package/show/home:rootcoder007/noqtis)

Documentation and guides: <https://noqtis.dev/>.

Post-quantum signatures, key encapsulation, hashes and sealed file
capsules, from the [noqtis](https://github.com/rootcoder007/noqtis) C
library, through the Foreign Function and Memory API (JDK 22 or later):
the jar calls the shared library `libnoqtis` directly, with no JNI code
to compile and no dependencies.
Use a JDK release that carries the November 2026 security update
(25.0.5.1 or later; CVE-2026-114938 is a flaw of the JDK's own Base64
decoder, which this binding does not call). JDK 22 to 24 no longer
receive fixes.

| Family | Algorithms | Standard |
|---|---|---|
| Signatures | ML-DSA-44/65/87 | FIPS 204 |
| | SLH-DSA-SHA2 and SLH-DSA-SHAKE, 128/192/256, s and f | FIPS 205 |
| | Ed25519, and the hybrids ML-DSA-44/65/87+Ed25519 | RFC 8032 |
| KEMs | ML-KEM-512/768/1024 | FIPS 203 |
| | HQC-128/192/256 | HQC specification 5.1 (keys made by 0.2.x are not read) |
| Hashes | SHA-224 ... SHA-512/256, SHA3-224 ... SHA3-512, SHAKE128/256, HMAC | FIPS 180-4, FIPS 202 |

## Build

```sh
sh bindings/java/build.sh test examples
```

builds the shared library with CMake (`-DNQSHARED=ON`) and
`build/noqtis.jar` with `javac` and `jar` alone (no Maven or Gradle,
nothing downloaded), then runs the tests and the examples in examples/. It
needs CMake, a C compiler and a JDK 22 or later.

Run your program with the jar on the class path, the library where Java
finds it, and native access enabled:

```sh
java --enable-native-access=ALL-UNNAMED \
  -Dnoqtis.library=build/lib/libnoqtis.so -cp build/noqtis.jar:. MyApp
```

The library is the file named by `-Dnoqtis.library` or the environment
variable `NOQTIS_LIBRARY`; else the copy in the jar for this operating
system and CPU (the jar on Maven Central carries one for Linux, macOS and
Windows on x86-64 and arm64), unpacked to a private temporary folder;
else `libnoqtis` (`noqtis-0.dll` on Windows) on the system's library
path, as `make install` or a release archive puts it.

From Maven Central:

```xml
<dependency>
  <groupId>io.github.rootcoder007</groupId>
  <artifactId>noqtis</artifactId>
  <version>LATEST_RELEASE</version>
</dependency>
```

with the latest release's version in place of `LATEST_RELEASE`
(Gradle: `implementation("io.github.rootcoder007:noqtis:<version>")`).

## Signatures

`examples/SignExample.java`:

```java
import io.github.rootcoder007.noqtis.Sign;
import java.nio.charset.StandardCharsets;

public class SignExample {
  public static void main(String[] args) {
    Sign.KeyPair k = Sign.keygen("ML-DSA-65");
    Sign.Opts o = Sign.Opts.none().withCtx("app-v1".getBytes(StandardCharsets.UTF_8));
    byte[] msg = "the results in table 2".getBytes(StandardCharsets.UTF_8);
    byte[] sig = Sign.sign("ML-DSA-65", k.sk(), msg, o);
    System.out.println("signature: " + sig.length + " bytes");
    System.out.println("verify: " + Sign.verify("ML-DSA-65", k.pk(), msg, sig, o));
    byte[] other = "other".getBytes(StandardCharsets.UTF_8);
    System.out.println("other message: " + Sign.verify("ML-DSA-65", k.pk(), other, sig, o));
  }
}
```

```text
signature: 3309 bytes
verify: true
other message: false
```

- `Sign.keygen(alg)` and `Sign.keygen(alg, seed)` return a `KeyPair`
  (`pk()`, `sk()`); a seed gives the standard's deterministic pair.
- `Sign.Opts.none()` and its `withCtx` (at most 255 bytes),
  `withDeterministic`, `withRnd` and `withPrehash` (`"SHA-512"` or any
  name from `Noqtis.hashes()`: HashML-DSA / HashSLH-DSA / Ed25519ph; the
  message is still the message).
- `verify` returns `false` for a bad or malformed signature; only a bad
  argument throws.

## Key encapsulation, hashes, random bytes

```java
Sign.KeyPair k = Kem.keygen("ML-KEM-768");
Kem.Encap e = Kem.encap("ML-KEM-768", k.pk());
byte[] ss = Kem.decap("ML-KEM-768", k.sk(), e.ct());   // equal to e.ss()

Noqtis.hash("SHA3-256", data);
Noqtis.hash("SHAKE256", data, 100);                     // 100 bytes of output
Noqtis.hmac("SHA-256", key, data);
Noqtis.random(32);                                      // the OS CSPRNG
```

A tampered ciphertext decapsulates to an unrelated secret rather than an
error (implicit rejection, as FIPS 203 requires).

## Capsules

A capsule is a folder sealed with a manifest of every file in it
(`noqtis.json`) and a post-quantum signature over it (`noqtis.sig`), the
same files the `noqtis` command writes and checks.
`examples/SealExample.java`:

```java
import io.github.rootcoder007.noqtis.Capsule;
import io.github.rootcoder007.noqtis.Sign;
import java.nio.file.Files;
import java.nio.file.Path;

public class SealExample {
  public static void main(String[] args) throws Exception {
    // a folder with some results
    Path d = Files.createTempDirectory("noqtis-java-demo");
    Files.createDirectories(d.resolve("data"));
    Files.writeString(d.resolve("data/in.csv"), "a,b\n1,2\n");
    Files.writeString(d.resolve("report.txt"), "r\n");

    // seal it, then check it with the public key pinned
    Sign.KeyPair k = Sign.keygen("ML-DSA-65");
    Capsule.seal(d, "ML-DSA-65", k.sk(), k.pk(), "{\"project\":\"tutorial\"}");
    Capsule.Opts o = Capsule.Opts.none().withTrust(k.pk());
    Capsule.Report r = Capsule.check(d, o);
    System.out.println("check: " + r.ok() + " (" + r.rows().size() + " checks)");

    // change a file: the check fails and says why
    Files.writeString(d.resolve("report.txt"), "r\nedited\n");
    r = Capsule.check(d, o);
    System.out.println("after edit: " + r.ok());
    for (Capsule.Row row : r.failed()) {
      System.out.println("FAIL " + row.check() + " " + row.detail());
    }
    try (var w = Files.walk(d)) {
      for (Path p : w.sorted(java.util.Comparator.reverseOrder()).toList()) {
        Files.delete(p);
      }
    }
  }
}
```

```text
check: true (23 checks)
after edit: false
FAIL file report.txt: size differs
```

- `check` returns a `Report` (`code()`, `rows()` of `check`, `ok`,
  `detail`) also when the capsule fails; `ok()` is true only when every
  check passed. `Capsule.check(dir)` (or no `withTrust`) accepts the key
  in the seal, and the `key` row says so. `Capsule.Opts` also takes TSA
  anchors (`withAnchors`, DER), a partial check (`withOnly`; `partial()` then says only some files were checked), folders to
  find a format 2 capsule's inputs in (`withLineage`) and key statements
  (`withStmts`).
- `seal` seals in format 3 with fresh salts and no inputs; `seal1`
  writes format 1, as `seal` did before 0.3.0, for older readers.
- `seal3(dir, alg, sk, pk, meta, inputs, saltKey)` seals in format 3 (a
  Merkle tree over the files, a secret salt in each leaf; `saltKey` null
  for fresh salts, or 32 secret bytes for a reproducible capsule),
  recording the capsules it was made from (`new Capsule.Input(id,
  name)`, the id from `capid`); `seal2` seals in format 2, the same tree
  unsalted, for readers older than 0.3.0.
- `prove(dir, List.of("data/in.csv"))` writes a proof that shows those
  files and none of the others' names, sizes or digests; of a format 3
  capsule (noqtis-proof-2) nothing in it confirms a guess of another
  file, of a format 2 one (noqtis-proof-1) its hashes do (see
  `noqtis-prove(1)`); `checkProof(proof, opts, dir)` checks one.
- `inspect(dir)` says what a capsule says without checking anything (the
  `info.*` rows, `report.get("info.alg")`); `files(dir)` adds one
  `info.file` row per listed file.

## Identity cards

```java
byte[] card = IdCard.make("ML-DSA-65", p.sk(), p.pk(),
    IdCard.Fields.of("Ada Lovelace").withOrcid("0000-0002-1825-0097"), null);
IdCard.Card c = IdCard.verify(card, p.pk());   // null when it does not verify
```

A card (noqtis-idcard-1, JSON) binds the key to its holder's name and,
when given, ORCID iD (check digit verified), e-mail address, `https://`
page and affiliation, signed by the key under its own context, so it is
never a seal or a key statement. It is self-signed: compare
`keySha256()` with the one its holder published, or pass the key
(`examples/CardExample.java`).

## Key files

`KeyFile` reads and writes the text key files `noqtis keygen` makes
(`noqtis-key-1 <alg> <pub|sec>`, then base64), as strictly as the
command-line tool reads them. A signature secret key is written as `noqtis-key-2 <alg> sec`, the
version 2 container (`Sign.sxmake`: the key with an integrity value), and read
back as that container, which every signing function takes in place of
the key and checks again after signing, so that a change to any stored
byte of the key is refused rather than signed with; a version 1 file
still reads, as the key.

```java
KeyFile.Key k = KeyFile.read(Path.of("me"), "sec");          // alg(), kind(), key()
byte[] sig = Sign.sign(k.alg(), k.key(), msg);

Sign.KeyPair p = Sign.keygen("ML-DSA-65");
KeyFile.write(Path.of("you"), "ML-DSA-65", "sec", p.sk(), false);   // owner-only, no overwrite
KeyFile.write(Path.of("you.pub"), "ML-DSA-65", "pub", p.pk(), false);
```

## Data records

`Data` reads and writes a capsule's data record (`noqtis.data.json`,
`noqtis-data(5)`): where each file came from, the schemas of its CSV
files and summaries for drift checks. Elements go in and come out as
JSON text, and the record is written in canonical form, the same bytes
the command line writes; seal the folder afterwards. The data layer is a
library of its own beside libnoqtis (`libnqd`, in `nqd/` of the CMake
build): `-Dnoqtis.nqd=<path>` or `NOQTIS_NQD`, else the one beside
`noqtis.library`, else `libnqd` on the library path. The Maven Central
jar does not carry it yet.

```java
Path d = Path.of("results");
Data.add(d, List.of("data/a.csv"),
    new Data.Src("https://example.org/a.csv", null, null, null, "now", false));
Data.put(d, "schemas", Data.schema(d, "data/a.csv", null));
Data.pin(d, List.of("data/a.csv"), null);
Data.check(d).ok();
// later: has new.csv drifted from the pinned summaries?
Data.Report r = Data.drift(d, List.of("data/a.csv"), List.of(Path.of("new.csv")), null, null);
r.level(); // ok, warn or fail
Data.diff(Path.of("results-v1"), d).same();
```

Also `Data.text`, `Data.canon`, `Data.key`, `Data.del` and
`Data.schemaCheck`.

## Passphrase keys, streams and sealed files

```java
KeyFile.write(Path.of("me"), "ML-DSA-65", "sec", sk, false, pass); // char[] pass
try (Signer s = new Signer("ML-DSA-65", sk, Sign.Opts.none());
     InputStream in = Files.newInputStream(Path.of("big.csv"))) {
  s.update(in);
  byte[] sig = s.sign(Sign.Opts.none());       // Sign.sign's bytes
}
try (InputStream in = Files.newInputStream(Path.of("big.csv"));
     OutputStream out = Files.newOutputStream(Path.of("big.csv.nqk"))) {
  Box.box("ML-KEM-768", kemPk, in, out, null, 0);
}
```

`KeyFile.pwenc2(KeyFile.KDF_PBKDF2, pw, sk, ad, 0, 0, 0)` gives the protected key (noqtis-pwkey-1, the body of such a key file) under
PBKDF2-HMAC-SHA-256 (600000 iterations) instead of Argon2id;
`KeyFile.pwdec` reads both.

`Verifier`, `Hasher`, `Box.Sealer` and `Box.Opener` are the other
streams; `Kem.seal` and `Kem.open` a message; `Sign.mu`, `signmu` and
`verifymu` ML-DSA with an external mu; `Noqtis.blake2b`, `argon2id`,
`pbkdf2`, `cteq` and `wipe` the primitives. `Capsule.sealWhy`, `tsreq`,
`tsput`, `ersreq`, `ersput`, `rotate`, `revoke` and the `Dsse` class
reach the rest of the capsule functions; `Data.checkSchema`, `synth`,
`calibrate`, `chunks`, `piece`, `commit`, `reveal`, `commitment`,
`cite`, `report`, `pack`, `unpack`, `checkPack`, `chain` and `env` the
rest of the data layer (`env` lists the boot layer's modules and the
class path's jars).

`Noqtis.kt128` and `kt256` are KangarooTwelve (RFC 9861); `sivenc` /
`sivdec` AES-SIV (RFC 5297) and `gsivenc` / `gsivdec` AES-GCM-SIV (RFC
8452), authenticated encryption; `chacha20` the ChaCha20 stream of RFC
8439, which is not authenticated.

## Mail, OpenPGP, a key store and tokens

`Mail` writes text armor (RFC 7468), X.509 certificates for noqtis keys,
and CMS and S/MIME messages, signed or encrypted. `Pgp` makes version 6
OpenPGP keys (RFC 9580) and signs, verifies, encrypts and decrypts with
them. `KeyStore` keeps other people's public keys in a folder, certifies
them and carries them from one store to another. `Token` signs and
decapsulates with keys that stay on a PKCS #11 token.

```java
byte[] msg = "a message".getBytes(StandardCharsets.UTF_8);
Pgp.KeyPair k = Pgp.generate(Pgp.MLDSA65, Pgp.MLKEM768,
    "Ada Example <ada@example.org>", Instant.now(), null);
byte[] sig = Pgp.sign(k.secret(), null, msg, Pgp.DETACHED, Instant.now());
Pgp.verify(k.cert(), sig, msg);   // throws when it does not verify
```

## Errors

Every failure is a `NoqtisException` (unchecked): `code()` is the
library's `NQE*` value (-1 for NQEARG, ...), `kind()` the same as a
`NoqtisException.Code` (`ARG`, `BUF`, `VERIFY`, `DECODE`, `RAND`, `MEM`,
`IO`, `UNSUPPORTED`, `LIMIT`, `STATE`), `nqerr()` the library's message,
and `getMessage()` adds what was wrong.

## Notes

- 64-bit platforms only (`size_t` is passed as a Java `long`).
- Secret keys and shared secrets are plain `byte[]`: overwrite them with
  `Arrays.fill` when that matters.
- Without `--enable-native-access=ALL-UNNAMED` the JDK prints a warning
  the first time the binding calls the library (and a later JDK may
  refuse); an executable jar can say `Enable-Native-Access: ALL-UNNAMED`
  in its manifest instead.

LGPL-3.0-or-later; versions up to 0.2.2 were released under Apache-2.0.
See LICENSE (the GNU Lesser General Public License version 3), COPYING
(the GNU General Public License version 3, which it adds to) and NOTICE.

## Citation

> Ruhela, V. S. (2026). *NOQTIS: Notary of Quantum-Safe Traceable Inputs
> and Seals.* <https://github.com/rootcoder007/noqtis>

[CITATION.cff](https://github.com/rootcoder007/noqtis/blob/main/CITATION.cff)
in the repository holds the same reference, with the version, for
reference managers.
