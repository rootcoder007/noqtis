---
title: Use from Java
description: The noqtis Java binding - seal and check a folder, sign and verify, encapsulate and hash, over the shared library with the FFM API.
---

The Java binding calls the shared library `libnoqtis` through the
Foreign Function and Memory API of JDK 22 and later: no JNI code to
compile and no dependencies. It runs on Linux, macOS and Windows
(64-bit).

## Build it

From the repository:

```sh
sh bindings/java/build.sh test examples
```

This builds the shared library with CMake and `bindings/java/build/noqtis.jar`
with `javac` and `jar` alone (no Maven or Gradle, nothing downloaded),
then runs the tests and the three examples on this page. Run a program
with the jar on the class path, the library where Java finds it, and
native access enabled:

```sh
java --enable-native-access=ALL-UNNAMED \
  -Dnoqtis.library=build/lib/libnoqtis.so -cp build/noqtis.jar:. MyApp
```

Without `-Dnoqtis.library` (or `NOQTIS_LIBRARY`) it loads `libnoqtis`
from the system's library path, where an installed noqtis puts it.

## Seal and check a folder

This is `examples/SealExample.java`, less the lines at its end that
remove the folder:

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
  }
}
```

It prints:

```text
check: true (22 checks)
after edit: false
FAIL file report.txt: size differs
```

- `Capsule.seal` writes `noqtis.json` and `noqtis.sig` into the folder;
  `meta` is JSON text (an object), signed with the manifest and never
  interpreted. `Capsule.seal2` seals in format 2, with the capsules it
  was made from.
- `Capsule.check` returns a `Report` also when the capsule fails: `ok()`
  is true only when every check passed, and `rows()` lists every check.
  Without `withTrust` it accepts the key in the seal, and the `key` row
  says so.
- `Capsule.inspect`, `capid`, `prove` and `checkProof` do what `noqtis
  inspect`, the capsule id, `noqtis prove` and `noqtis check --proof` do.

## Sign and verify

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

`verify` returns `false` for a bad signature; only a bad argument
throws. Every error is a `NoqtisException` with the library's code
(`code()`, `kind()`) and message (`nqerr()`).

## Identity cards

An identity card ties your signing key to who you are, signed by the
key itself; `noqtis check --card` reads it too.
`examples/CardExample.java`:

```java
import io.github.rootcoder007.noqtis.IdCard;
import io.github.rootcoder007.noqtis.NoqtisException;
import io.github.rootcoder007.noqtis.Sign;
import java.nio.charset.StandardCharsets;

public class CardExample {
  public static void main(String[] args) {
    Sign.KeyPair k = Sign.keygen("ML-DSA-65");
    IdCard.Fields f =
        IdCard.Fields.of("Ada Lovelace")
            .withOrcid("https://orcid.org/0000-0002-1825-0097")
            .withUrl("https://example.org/ada");
    byte[] card = IdCard.make("ML-DSA-65", k.sk(), k.pk(), f, null);

    IdCard.Card c = IdCard.verify(card, k.pk()); // null unless it verifies and is k's
    System.out.println("name: " + c.name());
    System.out.println("orcid: " + c.orcid());

    // a changed card does not verify; a wrong check digit is refused
    String t = new String(card, StandardCharsets.UTF_8).replace("Ada", "Eve");
    System.out.println("changed: " + IdCard.verify(t.getBytes(StandardCharsets.UTF_8), null));
    try {
      IdCard.make("ML-DSA-65", k.sk(), k.pk(), f.withOrcid("0000-0002-1825-0098"), null);
    } catch (NoqtisException e) {
      System.out.println("refused: " + e.kind());
    }
  }
}
```

```text
name: Ada Lovelace
orcid: 0000-0002-1825-0097
changed: null
refused: ARG
```

The card holds the bare ORCID iD. It is self-signed: it shows that the
holder of the key wrote it, not that the name is true, so give the key's
SHA-256 (`keySha256()`) where people already know you, or let readers
pin your public key. `IdCard.verify` returns `null` for a card that
does not verify or is for another key, and throws `DECODE` for input
that is not a card.

## Notes

- `Kem` has `keygen`, `encap` and `decap`; `Noqtis` has `hash`, `hmac`,
  `random`, `version` and `algs`; `KeyFile` reads and writes the CLI's
  key files.
- Secret keys are plain `byte[]`: overwrite them when that matters.

The full API is in the binding's
[README](https://github.com/rootcoder007/noqtis/tree/main/bindings/java#readme).
