// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
package io.github.rootcoder007.noqtis;

import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * noqtis: post-quantum signatures, KEMs, hashes and sealed file capsules,
 * the Java binding of the noqtis C library. This class has the version,
 * the algorithm table, hashes and random bytes; {@link Sign}, {@link Kem},
 * {@link Capsule} and {@link KeyFile} the rest. Algorithms are named as
 * {@code noqtis algs} lists them ("ML-DSA-65", "ML-KEM-768", ...), in any
 * case. Every failure is a {@link NoqtisException}.
 */
public final class Noqtis {
  private Noqtis() {}

  /**
   * One algorithm and its sizes in bytes: {@code sig} is 0 for a KEM,
   * {@code ct} and {@code ss} are 0 for a signature algorithm.
   *
   * @param name "ML-DSA-65", "ML-KEM-768", ...
   * @param kind "sign" or "kem"
   * @param id the library's nqsalg or nqkalg value
   * @param pk public key size
   * @param sk secret key size
   * @param sig signature size
   * @param ct ciphertext size
   * @param ss shared secret size
   */
  public record Alg(String name, String kind, int id, int pk, int sk, int sig, int ct, int ss) {}

  private static final List<Alg> TABLE = table();

  private static List<Alg> table() {
    List<Alg> out = new ArrayList<>();
    try (Arena a = Arena.ofConfined()) {
      MemorySegment z = a.allocate(JAVA_LONG, 4);
      for (int i = 1; i < 64; i++) {
        if ((int) Native.NQSSIZE.invoke(i, z) == 0) {
          String n = Native.str((MemorySegment) Native.NQSNAME.invoke(i));
          out.add(new Alg(n, "sign", i, sz(z, 0), sz(z, 1), sz(z, 2), 0, 0));
        }
      }
      for (int i = 1; i < 64; i++) {
        if ((int) Native.NQKSIZE.invoke(i, z) == 0) {
          String n = Native.str((MemorySegment) Native.NQKNAME.invoke(i));
          out.add(new Alg(n, "kem", i, sz(z, 0), sz(z, 1), 0, sz(z, 2), sz(z, 3)));
        }
      }
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
    return Collections.unmodifiableList(out);
  }

  private static int sz(MemorySegment z, int i) {
    return (int) z.getAtIndex(JAVA_LONG, i);
  }

  /**
   * The library's version.
   *
   * @return "0.1.3"
   */
  public static String version() {
    try {
      return Native.str((MemorySegment) Native.NQVER.invoke());
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Every algorithm with its sizes, the signature algorithms first.
   *
   * @return the table, unmodifiable
   */
  public static List<Alg> algs() {
    return TABLE;
  }

  /**
   * The algorithm of a name, in any case.
   *
   * @param name "ML-DSA-65", ...
   * @return its sizes
   */
  public static Alg alg(String name) {
    for (Alg a : TABLE) {
      if (a.name().equalsIgnoreCase(name)) {
        return a;
      }
    }
    throw new NoqtisException(-8, "unknown algorithm \"" + name + "\"");
  }

  static Alg find(String name, String kind) {
    Alg a = alg(name);
    if (!a.kind().equals(kind)) {
      String w = kind.equals("sign") ? "signature" : "KEM";
      throw new NoqtisException(-8, a.name() + " is not a " + w + " algorithm");
    }
    return a;
  }

  private static final List<String> HASHES =
      List.of(
          "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256", "SHA3-224",
          "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256");

  /**
   * The hash names {@link #hash}, {@link #hmac} and the pre-hash option take.
   *
   * @return the names
   */
  public static List<String> hashes() {
    return HASHES;
  }

  private static String hkey(String s) {
    return s.replace("-", "").replace("/", "").replace("_", "").toLowerCase(Locale.ROOT);
  }

  /** The nqhalg of a hash name: "SHA-256", "sha256", "sha3_256", ... */
  static int hid(String name) {
    String k = hkey(name);
    for (int i = 0; i < HASHES.size(); i++) {
      if (hkey(HASHES.get(i)).equals(k)) {
        return i + 1;
      }
    }
    throw new NoqtisException(-8, "unknown hash \"" + name + "\"");
  }

  private static byte[] digest(String alg, byte[] data, long n) {
    int i = hid(alg);
    try (Arena a = Arena.ofConfined()) {
      long d = (long) Native.NQHLEN.invoke(i);
      if (n >= 0) {
        if (i < 11) {
          throw new NoqtisException(-1, alg + " has a fixed length; n is for SHAKE");
        }
        d = n;
      }
      MemorySegment o = Native.out(a, d);
      Native.rc((int) Native.NQHASH.invoke(i, Native.in(a, data), (long) data.length, o, d));
      return Native.bytes(o, d);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The digest of data; for SHAKE128 and SHAKE256, 32 and 64 bytes.
   *
   * @param alg "SHA-256", "SHA3-512", "SHAKE128", ...
   * @param data the input
   * @return the digest
   */
  public static byte[] hash(String alg, byte[] data) {
    return digest(alg, data, -1);
  }

  /**
   * n bytes of SHAKE128 or SHAKE256 output.
   *
   * @param alg "SHAKE128" or "SHAKE256"
   * @param data the input
   * @param n the output length
   * @return the output
   */
  public static byte[] hash(String alg, byte[] data, int n) {
    if (n < 0) {
      throw new NoqtisException(-1, "n: a length in bytes");
    }
    return digest(alg, data, n);
  }

  /**
   * HMAC of data under key with a SHA-2 or SHA-3 hash.
   *
   * @param alg "SHA-256", ...
   * @param key the key
   * @param data the input
   * @return the MAC
   */
  public static byte[] hmac(String alg, byte[] key, byte[] data) {
    int i = hid(alg);
    try (Arena a = Arena.ofConfined()) {
      long d = (long) Native.NQHLEN.invoke(i);
      MemorySegment o = Native.out(a, d);
      Native.rc(
          (int)
              Native.NQHMAC.invoke(
                  i,
                  Native.in(a, key),
                  (long) key.length,
                  Native.in(a, data),
                  (long) data.length,
                  o,
                  d));
      return Native.bytes(o, d);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Bytes from the operating system's CSPRNG.
   *
   * @param n how many
   * @return n random bytes
   */
  public static byte[] random(int n) {
    if (n < 0) {
      throw new NoqtisException(-1, "n: a length in bytes");
    }
    if (n == 0) {
      return new byte[0];
    }
    try (Arena a = Arena.ofConfined()) {
      MemorySegment o = Native.out(a, n);
      Native.rc((int) Native.NQRAND.invoke(o, (long) n));
      return Native.bytes(o, n);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }
}
