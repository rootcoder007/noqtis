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
   * @return "0.3.0"
   */
  public static String version() {
    try {
      return Native.str((MemorySegment) Native.NQVER.invoke());
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Runs the library's known-answer self-test (every family, about a
   * tenth of a second).
   *
   * @throws NoqtisException with {@code SELFTEST} when an answer differs
   */
  public static void selfTest() {
    int rc;
    try {
      rc = (int) Native.NQSELF.invoke();
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
    Native.rc(rc);
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

  /**
   * Wipes b (with nqwipe on a native copy, and zeros here); Java cannot
   * promise that no other copy of b exists.
   *
   * @param b the bytes to zero
   */
  public static void wipe(byte[] b) {
    if (b != null) {
      java.util.Arrays.fill(b, (byte) 0);
    }
  }

  /**
   * Whether a and b are equal, in time that depends only on their length
   * (nqcteq): compare MACs and tags with it.
   *
   * @param a one
   * @param b the other
   * @return true when equal
   */
  public static boolean cteq(byte[] a, byte[] b) {
    if (a.length != b.length) {
      return false;
    }
    try (Arena m = Arena.ofConfined()) {
      return (int)
              Native.NQCTEQ.invoke(Native.out(m, a.length).copyFrom(MemorySegment.ofArray(a)),
                  Native.out(m, b.length).copyFrom(MemorySegment.ofArray(b)), (long) a.length)
          == 1;
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * BLAKE2b (RFC 7693): an n-byte digest (1 to 64) of data, keyed (a MAC)
   * with up to 64 bytes of key.
   *
   * @param data the message
   * @param key the key, or null (or empty) for the plain hash
   * @param n the digest size
   * @return the digest
   */
  public static byte[] blake2b(byte[] data, byte[] key, int n) {
    if (n < 1 || n > 64) {
      throw new NoqtisException(-1, "n: 1 to 64 bytes");
    }
    byte[] k = key == null ? new byte[0] : key;
    try (Arena m = Arena.ofConfined()) {
      MemorySegment o = Native.out(m, n);
      Native.rc(
          (int)
              Native.NQB2B.invoke(
                  Native.in(m, k), (long) k.length, Native.in(m, data), (long) data.length, o,
                  (long) n));
      return Native.bytes(o, n);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  private static byte[] kt(int bits, byte[] data, byte[] custom, int n) {
    if (n < 1) {
      throw new NoqtisException(-1, "n: 1 byte or more");
    }
    byte[] c = custom == null ? new byte[0] : custom;
    try (Arena m = Arena.ofConfined()) {
      MemorySegment o = Native.out(m, n);
      Native.rc(
          (int)
              Native.NQKT.invoke(
                  bits, Native.in(m, data), (long) data.length, Native.in(m, c), (long) c.length,
                  o, (long) n));
      return Native.bytes(o, n);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * KangarooTwelve KT128 (RFC 9861): n bytes of the tree hash and
   * extendable-output function, with a customization string (a secret
   * key there makes it a MAC). 32 bytes give its full strength against
   * collisions.
   *
   * @param data the message
   * @param custom the customization string, or null (or empty) for none
   * @param n the output length, 1 or more
   * @return the output
   */
  public static byte[] kt128(byte[] data, byte[] custom, int n) {
    return kt(128, data, custom, n);
  }

  /**
   * KangarooTwelve KT256 (RFC 9861): as kt128, at 256 bits; 64 bytes give
   * its full strength against collisions.
   *
   * @param data the message
   * @param custom the customization string, or null (or empty) for none
   * @param n the output length, 1 or more
   * @return the output
   */
  public static byte[] kt256(byte[] data, byte[] custom, int n) {
    return kt(256, data, custom, n);
  }

  /**
   * The ChaCha20 stream cipher (RFC 8439): data XORed with the key stream
   * of the 32-byte key and the 12-byte nonce, from a block counter. The
   * same call decrypts.
   *
   * <p>NOT AUTHENTICATED: a changed ciphertext decrypts to a changed
   * plaintext with no error, and a key and nonce used for two messages
   * give away their XOR. To encrypt, use sivenc or gsivenc.
   *
   * @param key the key, 32 bytes
   * @param nonce the nonce, 12 bytes
   * @param counter the block counter the stream starts at, 0 to 2^32 - 1
   * @param data the bytes to XOR
   * @return data XORed with the key stream
   */
  public static byte[] chacha20(byte[] key, byte[] nonce, long counter, byte[] data) {
    if (counter < 0 || counter > 0xffffffffL) {
      throw new NoqtisException(-1, "counter: 0 to 2^32 - 1");
    }
    try (Arena m = Arena.ofConfined()) {
      MemorySegment o = Native.out(m, data.length);
      Native.rc(
          (int)
              Native.NQCHA20.invoke(
                  Native.in(m, key), (long) key.length, Native.in(m, nonce), (long) nonce.length,
                  (int) counter, Native.in(m, data), (long) data.length, o));
      return Native.bytes(o, data.length);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  private static byte[] siv(boolean dec, byte[] key, byte[][] ad, byte[] data) {
    byte[][] a = ad == null ? new byte[0][] : ad;
    if (a.length > 126) {
      throw new NoqtisException(-1, "ad: at most 126 strings");
    }
    if (dec && data.length < 16) {
      throw new NoqtisException(-1, "data: at least the 16 bytes of the IV");
    }
    long n = dec ? data.length - 16 : data.length + 16;
    try (Arena m = Arena.ofConfined()) {
      MemorySegment p = m.allocate(java.lang.foreign.ValueLayout.ADDRESS, Math.max(a.length, 1));
      MemorySegment l = m.allocate(java.lang.foreign.ValueLayout.JAVA_LONG, Math.max(a.length, 1));
      for (int i = 0; i < a.length; i++) {
        byte[] s = a[i] == null ? new byte[0] : a[i];
        p.setAtIndex(java.lang.foreign.ValueLayout.ADDRESS, i, Native.in(m, s));
        l.setAtIndex(java.lang.foreign.ValueLayout.JAVA_LONG, i, (long) s.length);
      }
      MemorySegment o = Native.out(m, n);
      Native.rc(
          (int)
              (dec ? Native.NQSIVDEC : Native.NQSIVENC)
                  .invoke(
                      Native.in(m, key), (long) key.length, p, l, (long) a.length,
                      Native.in(m, data), (long) data.length, o, n));
      return Native.bytes(o, n);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * AES-SIV (RFC 5297), deterministic authenticated encryption. The same
   * input always gives the same output, and no nonce is needed.
   *
   * @param key two AES keys: 32, 48 or 64 bytes
   * @param ad up to 126 associated strings, authenticated and not
   *     encrypted (a nonce, where there is one, is by convention the
   *     last), or null for none
   * @param data the message
   * @return the 16-byte synthetic IV, then the ciphertext
   */
  public static byte[] sivenc(byte[] key, byte[][] ad, byte[] data) {
    return siv(false, key, ad, data);
  }

  /**
   * The message of sivenc.
   *
   * @param key the key given to sivenc
   * @param ad the associated strings given to sivenc
   * @param data the output of sivenc
   * @return the message
   * @throws NoqtisException with code VERIFY when the key, the strings or
   *     the data are not the ones encrypted
   */
  public static byte[] sivdec(byte[] key, byte[][] ad, byte[] data) {
    return siv(true, key, ad, data);
  }

  private static byte[] gsiv(boolean dec, byte[] key, byte[] nonce, byte[] ad, byte[] data) {
    byte[] a = ad == null ? new byte[0] : ad;
    if (dec && data.length < 16) {
      throw new NoqtisException(-1, "data: at least the 16 bytes of the tag");
    }
    long n = dec ? data.length - 16 : data.length + 16;
    try (Arena m = Arena.ofConfined()) {
      MemorySegment o = Native.out(m, n);
      Native.rc(
          (int)
              (dec ? Native.NQGSIVDEC : Native.NQGSIVENC)
                  .invoke(
                      Native.in(m, key), (long) key.length, Native.in(m, nonce),
                      (long) nonce.length, Native.in(m, a), (long) a.length, Native.in(m, data),
                      (long) data.length, o, n));
      return Native.bytes(o, n);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * AES-GCM-SIV (RFC 8452), authenticated encryption that resists a nonce
   * used twice.
   *
   * @param key the key: 16 or 32 bytes
   * @param nonce the nonce, 12 bytes
   * @param ad the associated data, or null for none
   * @param data the message
   * @return the ciphertext, then the 16-byte tag
   */
  public static byte[] gsivenc(byte[] key, byte[] nonce, byte[] ad, byte[] data) {
    return gsiv(false, key, nonce, ad, data);
  }

  /**
   * The message of gsivenc.
   *
   * @param key the key given to gsivenc
   * @param nonce the nonce given to gsivenc
   * @param ad the associated data given to gsivenc
   * @param data the output of gsivenc
   * @return the message
   * @throws NoqtisException with code VERIFY when it does not verify
   */
  public static byte[] gsivdec(byte[] key, byte[] nonce, byte[] ad, byte[] data) {
    return gsiv(true, key, nonce, ad, data);
  }

  /**
   * Argon2id (RFC 9106, version 0x13): n bytes (4 to 1024) from the
   * password and the salt (8 bytes or more), t passes over m KiB in p
   * lanes, with an optional secret key and associated data.
   *
   * @param pw the password
   * @param salt the salt
   * @param t passes, 1 to 1024
   * @param mem memory in KiB, 8p to 4 GiB
   * @param p lanes, 1 to 255
   * @param n the output size
   * @param key the secret key, or null
   * @param ad the associated data, or null
   * @return the tag
   */
  public static byte[] argon2id(
      byte[] pw, byte[] salt, int t, int mem, int p, int n, byte[] key, byte[] ad) {
    if (n < 4 || n > 1024) {
      throw new NoqtisException(-1, "n: 4 to 1024 bytes");
    }
    byte[] k = key == null ? new byte[0] : key, a = ad == null ? new byte[0] : ad;
    try (Arena m = Arena.ofConfined()) {
      MemorySegment o = Native.out(m, n), ps = Native.in(m, pw);
      try {
        Native.rc(
            (int)
                Native.NQA2ID.invoke(
                    ps, (long) pw.length, Native.in(m, salt), (long) salt.length,
                    Native.in(m, k), (long) k.length, Native.in(m, a), (long) a.length, t, mem,
                    p, o, (long) n));
        return Native.bytes(o, n);
      } finally {
        Native.wipe(ps, pw.length);
        Native.wipe(o, n);
      }
    } catch (Throwable x) {
      throw Native.wrap(x);
    }
  }
}
