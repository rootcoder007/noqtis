# noqtis for Java <img src="https://raw.githubusercontent.com/rootcoder007/noqtis/main/docs/logo/noqtis-hex-512.png" align="right" height="139" alt="NOQTIS hex logo" />

Post-quantum signatures, key encapsulation, hashes and sealed file
capsules, from the [noqtis](https://github.com/rootcoder007/noqtis) C
library, through the Foreign Function and Memory API (JDK 22 or later):
the jar calls the shared library `libnoqtis` directly, with no JNI code
to compile and no dependencies.

| Family | Algorithms | Standard |
|---|---|---|
| Signatures | ML-DSA-44/65/87 | FIPS 204 |
| | SLH-DSA-SHA2 and SLH-DSA-SHAKE, 128/192/256, s and f | FIPS 205 |
| | Ed25519, and the hybrids ML-DSA-44/65/87+Ed25519 | RFC 8032 |
| KEMs | ML-KEM-512/768/1024 | FIPS 203 |
| | HQC-128/192/256 | HQC round 4 |
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
check: true (22 checks)
after edit: false
FAIL file report.txt: size differs
```

- `check` returns a `Report` (`code()`, `rows()` of `check`, `ok`,
  `detail`) also when the capsule fails; `ok()` is true only when every
  check passed. `Capsule.check(dir)` (or no `withTrust`) accepts the key
  in the seal, and the `key` row says so. `Capsule.Opts` also takes TSA
  anchors (`withAnchors`, DER), a partial check (`withOnly`), folders to
  find a format 2 capsule's inputs in (`withLineage`) and key statements
  (`withStmts`).
- `seal2(dir, alg, sk, pk, meta, inputs)` seals in format 2 (a Merkle
  tree over the files), recording the capsules it was made from
  (`new Capsule.Input(id, name)`, the id from `capid`).
- `prove(dir, List.of("data/in.csv"))` writes a proof (noqtis-proof-1)
  that shows those files of a format 2 capsule and nothing of the
  others; `checkProof(proof, opts, dir)` checks one.
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
command-line tool reads them:

```java
KeyFile.Key k = KeyFile.read(Path.of("me"), "sec");          // alg(), kind(), key()
byte[] sig = Sign.sign(k.alg(), k.key(), msg);

Sign.KeyPair p = Sign.keygen("ML-DSA-65");
KeyFile.write(Path.of("you"), "ML-DSA-65", "sec", p.sk(), false);   // owner-only, no overwrite
KeyFile.write(Path.of("you.pub"), "ML-DSA-65", "pub", p.pk(), false);
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

Licensed under Apache-2.0 WITH LLVM-exception.
