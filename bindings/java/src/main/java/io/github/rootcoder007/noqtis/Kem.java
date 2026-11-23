// SPDX-License-Identifier: LGPL-3.0-or-later
package io.github.rootcoder007.noqtis;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * Key encapsulation: ML-KEM (FIPS 203) and HQC.
 *
 * <pre>{@code
 * Sign.KeyPair k = Kem.keygen("ML-KEM-768");
 * Kem.Encap e = Kem.encap("ML-KEM-768", k.pk());
 * byte[] ss = Kem.decap("ML-KEM-768", k.sk(), e.ct()); // equal to e.ss()
 * }</pre>
 */
public final class Kem {
  private Kem() {}

  /**
   * A ciphertext and the shared secret it carries.
   *
   * @param ct the ciphertext
   * @param ss the shared secret
   */
  public record Encap(byte[] ct, byte[] ss) {}

  /**
   * A new key pair from the OS CSPRNG.
   *
   * @param alg the algorithm
   * @return the pair
   */
  public static Sign.KeyPair keygen(String alg) {
    return keygen(alg, null);
  }

  /**
   * A key pair; with a seed (d || z for ML-KEM) the standard's
   * deterministic one.
   *
   * @param alg the algorithm
   * @param seed the seed, or null for a random pair
   * @return the pair
   */
  public static Sign.KeyPair keygen(String alg, byte[] seed) {
    Noqtis.Alg a = Noqtis.find(alg, "kem");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment pk = Native.out(m, a.pk()), sk = Native.out(m, a.sk());
      int c;
      if (seed == null) {
        c = (int) Native.NQKKG.invoke(a.id(), pk, (long) a.pk(), sk, (long) a.sk());
      } else {
        c =
            (int)
                Native.NQKKGD.invoke(
                    a.id(),
                    Native.in(m, seed),
                    (long) seed.length,
                    pk,
                    (long) a.pk(),
                    sk,
                    (long) a.sk());
      }
      Native.rc(c);
      return new Sign.KeyPair(Native.bytes(pk, a.pk()), Native.bytes(sk, a.sk()));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * A ciphertext and shared secret for pk.
   *
   * @param alg the algorithm
   * @param pk the public key
   * @return both
   */
  public static Encap encap(String alg, byte[] pk) {
    return encap(alg, pk, null);
  }

  /**
   * A ciphertext and shared secret for pk; a seed (m for ML-KEM) makes it
   * deterministic, for test vectors.
   *
   * @param alg the algorithm
   * @param pk the public key
   * @param seed the seed, or null
   * @return both
   */
  public static Encap encap(String alg, byte[] pk, byte[] seed) {
    Noqtis.Alg a = Noqtis.find(alg, "kem");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment ct = Native.out(m, a.ct()), ss = Native.out(m, a.ss());
      MemorySegment p = Native.in(m, pk);
      int c;
      if (seed == null) {
        c =
            (int)
                Native.NQENC.invoke(
                    a.id(), p, (long) pk.length, ct, (long) a.ct(), ss, (long) a.ss());
      } else {
        c =
            (int)
                Native.NQENCD.invoke(
                    a.id(), p, (long) pk.length, Native.in(m, seed), (long) seed.length, ct,
                    (long) a.ct(), ss, (long) a.ss());
      }
      Native.rc(c);
      return new Encap(Native.bytes(ct, a.ct()), Native.bytes(ss, a.ss()));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The shared secret in ct. A tampered ciphertext gives an unrelated
   * pseudorandom secret, not an error (implicit rejection); only a key or
   * ciphertext of the wrong size, or a damaged secret key, throws.
   *
   * @param alg the algorithm
   * @param sk the secret key
   * @param ct the ciphertext
   * @return the shared secret
   */
  public static byte[] decap(String alg, byte[] sk, byte[] ct) {
    Noqtis.Alg a = Noqtis.find(alg, "kem");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment ss = Native.out(m, a.ss());
      Native.rc(
          (int)
              Native.NQDEC.invoke(
                  a.id(),
                  Native.in(m, sk),
                  (long) sk.length,
                  Native.in(m, ct),
                  (long) ct.length,
                  ss,
                  (long) a.ss()));
      return Native.bytes(ss, a.ss());
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * msg sealed to the ML-KEM public key pk (noqtis-kseal-1): only the
   * holder of the secret key opens it, with the same ctx.
   *
   * @param alg ML-KEM-512, -768 or -1024
   * @param pk the public key
   * @param msg the message
   * @param ctx the context, at most 255 bytes (null for none)
   * @return the sealed message
   */
  public static byte[] seal(String alg, byte[] pk, byte[] msg, byte[] ctx) {
    Noqtis.Alg a = Noqtis.find(alg, "kem");
    byte[] c = ctx == null ? new byte[0] : ctx;
    try (Arena m = Arena.ofConfined()) {
      return Native.sized(
          m,
          22L + a.ct() + msg.length,
          (o, cap, n) ->
              (int)
                  Native.NQKSEAL.invoke(
                      a.id(), Native.in(m, pk), (long) pk.length, Native.in(m, c), (long) c.length,
                      Native.in(m, msg), (long) msg.length, o, cap, n));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The message {@link #seal} sealed: {@link NoqtisException.Code#VERIFY}
   * for a changed byte, another key or another ctx,
   * {@link NoqtisException.Code#DECODE} for bytes that are not a sealed
   * message of this algorithm.
   *
   * @param alg ML-KEM-512, -768 or -1024
   * @param sk the secret key
   * @param data the sealed message
   * @param ctx the context it was sealed with (null for none)
   * @return the message
   */
  public static byte[] open(String alg, byte[] sk, byte[] data, byte[] ctx) {
    Noqtis.Alg a = Noqtis.find(alg, "kem");
    byte[] c = ctx == null ? new byte[0] : ctx;
    try (Arena m = Arena.ofConfined()) {
      MemorySegment k = Native.in(m, sk);
      try {
        return Native.sized(
            m,
            Math.max(data.length, 1),
            (o, cap, n) ->
                (int)
                    Native.NQKOPEN.invoke(
                        a.id(), k, (long) sk.length, Native.in(m, c), (long) c.length,
                        Native.in(m, data), (long) data.length, o, cap, n));
      } finally {
        Native.wipe(k, sk.length);
      }
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }
}
