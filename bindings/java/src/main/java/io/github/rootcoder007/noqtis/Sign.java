// SPDX-License-Identifier: LGPL-3.0-or-later
package io.github.rootcoder007.noqtis;

import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * Signatures: ML-DSA (FIPS 204), SLH-DSA (FIPS 205), Ed25519 (RFC 8032)
 * and the ML-DSA + Ed25519 hybrids.
 *
 * <pre>{@code
 * Sign.KeyPair k = Sign.keygen("ML-DSA-65");
 * Sign.Opts o = Sign.Opts.none().withCtx("app-v1".getBytes());
 * byte[] sig = Sign.sign("ML-DSA-65", k.sk(), msg, o);
 * boolean ok = Sign.verify("ML-DSA-65", k.pk(), msg, sig, o);
 * }</pre>
 */
public final class Sign {
  private Sign() {}

  /**
   * A key pair.
   *
   * @param pk the public key
   * @param sk the secret key
   */
  public record KeyPair(byte[] pk, byte[] sk) {}

  /**
   * The options of {@link #sign} and {@link #verify}; {@link #none()} is
   * all defaults, and each {@code with} method returns a changed copy.
   *
   * @param ctx the context string, at most 255 bytes (empty for none)
   * @param deterministic all-zero per-signature randomness: the
   *     standard's deterministic variant (sign only)
   * @param prehash a hash name ("SHA-512", "SHAKE256", ...) for HashML-DSA
   *     / HashSLH-DSA (Ed25519ph for Ed25519), or null; the message is
   *     still the message, hashed inside
   * @param rnd the per-signature randomness, explicitly (sign only), or
   *     null
   */
  public record Opts(byte[] ctx, boolean deterministic, String prehash, byte[] rnd) {
    /**
     * No context, fresh randomness, no pre-hash.
     *
     * @return the defaults
     */
    public static Opts none() {
      return new Opts(new byte[0], false, null, null);
    }

    /**
     * @param c the context string
     * @return a copy with that context
     */
    public Opts withCtx(byte[] c) {
      return new Opts(c, deterministic, prehash, rnd);
    }

    /**
     * @return a copy that signs deterministically
     */
    public Opts withDeterministic() {
      return new Opts(ctx, true, prehash, rnd);
    }

    /**
     * @param h a hash name
     * @return a copy with that pre-hash
     */
    public Opts withPrehash(String h) {
      return new Opts(ctx, deterministic, h, rnd);
    }

    /**
     * @param r the per-signature randomness
     * @return a copy with that randomness
     */
    public Opts withRnd(byte[] r) {
      return new Opts(ctx, deterministic, prehash, r);
    }

    int ph() {
      return prehash == null ? 0 : Noqtis.hid(prehash);
    }

    byte[] c() {
      return ctx == null ? new byte[0] : ctx;
    }
  }

  /**
   * Bytes of per-signature randomness.
   *
   * @param alg the algorithm
   * @return 32 for ML-DSA and the hybrids, n for SLH-DSA, 0 for Ed25519
   */
  public static int rndlen(String alg) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    if (a.name().equals("Ed25519")) {
      return 0;
    }
    return a.name().startsWith("ML-DSA") ? 32 : a.pk() / 2;
  }

  /**
   * A new key pair from the OS CSPRNG.
   *
   * @param alg the algorithm
   * @return the pair
   */
  public static KeyPair keygen(String alg) {
    return keygen(alg, null);
  }

  /**
   * A key pair; with a seed (xi for ML-DSA, 32 bytes; SK.seed || SK.prf ||
   * PK.seed for SLH-DSA, 3n bytes; the private key for Ed25519; xi || the
   * Ed25519 key for a hybrid) the standard's deterministic one.
   *
   * @param alg the algorithm
   * @param seed the seed, or null for a random pair
   * @return the pair
   */
  public static KeyPair keygen(String alg, byte[] seed) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment pk = Native.out(m, a.pk()), sk = Native.out(m, a.sk());
      int c;
      if (seed == null) {
        c = (int) Native.NQSKG.invoke(a.id(), pk, (long) a.pk(), sk, (long) a.sk());
      } else {
        c =
            (int)
                Native.NQSKGD.invoke(
                    a.id(),
                    Native.in(m, seed),
                    (long) seed.length,
                    pk,
                    (long) a.pk(),
                    sk,
                    (long) a.sk());
      }
      Native.rc(c);
      return new KeyPair(Native.bytes(pk, a.pk()), Native.bytes(sk, a.sk()));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The signature of msg under sk, with no context.
   *
   * @param alg the algorithm
   * @param sk the secret key
   * @param msg the message
   * @return the signature
   */
  public static byte[] sign(String alg, byte[] sk, byte[] msg) {
    return sign(alg, sk, msg, Opts.none());
  }

  /**
   * The signature of msg under sk.
   *
   * @param alg the algorithm
   * @param sk the secret key
   * @param msg the message
   * @param o the options
   * @return the signature
   */
  public static byte[] sign(String alg, byte[] sk, byte[] msg, Opts o) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    if (o.deterministic() && o.rnd() != null) {
      throw new NoqtisException(-1, "deterministic and rnd exclude each other");
    }
    int ph = o.ph();
    byte[] r = o.deterministic() ? new byte[rndlen(alg)] : o.rnd();
    byte[] c = o.c();
    try (Arena m = Arena.ofConfined()) {
      MemorySegment sig = Native.out(m, a.sig()), n = m.allocate(JAVA_LONG);
      MemorySegment ks = Native.in(m, sk), ms = Native.in(m, msg), cs = Native.in(m, c);
      int rc;
      if (r == null) {
        rc =
            (int)
                Native.NQSIGN.invoke(
                    a.id(), ks, (long) sk.length, ms, (long) msg.length, cs, (long) c.length, ph,
                    sig, (long) a.sig(), n);
      } else {
        rc =
            (int)
                Native.NQSIGND.invoke(
                    a.id(), ks, (long) sk.length, ms, (long) msg.length, cs, (long) c.length, ph,
                    Native.in(m, r), (long) r.length, sig, (long) a.sig(), n);
      }
      Native.rc(rc);
      return Native.bytes(sig, n.get(JAVA_LONG, 0));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Whether sig is a valid signature of msg under pk, with no context.
   *
   * @param alg the algorithm
   * @param pk the public key
   * @param msg the message
   * @param sig the signature
   * @return true when it verifies
   */
  public static boolean verify(String alg, byte[] pk, byte[] msg, byte[] sig) {
    return verify(alg, pk, msg, sig, Opts.none());
  }

  /**
   * Whether sig is a valid signature of msg under pk (with the same
   * context and pre-hash): false when it does not verify or is not a
   * well-formed signature. Bad arguments (a context over 255 bytes, a
   * public key of the wrong size) throw.
   *
   * @param alg the algorithm
   * @param pk the public key
   * @param msg the message
   * @param sig the signature
   * @param o the options
   * @return true when it verifies
   */
  public static boolean verify(String alg, byte[] pk, byte[] msg, byte[] sig, Opts o) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    if (pk.length != a.pk()) {
      throw new NoqtisException(
          -4, a.name() + " public keys are " + a.pk() + " bytes, not " + pk.length);
    }
    int ph = o.ph();
    byte[] c = o.c();
    try (Arena m = Arena.ofConfined()) {
      int rc =
          (int)
              Native.NQVRFY.invoke(
                  a.id(),
                  Native.in(m, pk),
                  (long) pk.length,
                  Native.in(m, msg),
                  (long) msg.length,
                  Native.in(m, c),
                  (long) c.length,
                  ph,
                  Native.in(m, sig),
                  (long) sig.length);
      if (rc == 0) {
        return true;
      }
      if (rc == -3 || rc == -4) {
        return false;
      }
      throw new NoqtisException(rc);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /** The randomness of o for alg: null for the hedged signature. */
  static byte[] rnd(String alg, Opts o) {
    if (o.deterministic() && o.rnd() != null) {
      throw new NoqtisException(-1, "deterministic and rnd exclude each other");
    }
    return o.deterministic() ? new byte[rndlen(alg)] : o.rnd();
  }

  /**
   * The 64-byte message representative mu of FIPS 204 for msg under pk,
   * as {@link #sign} computes it (ML-DSA only; o's ctx and prehash are
   * used), so that the message can be hashed away from the key.
   *
   * @param alg ML-DSA-44, -65 or -87
   * @param pk the public key
   * @param msg the message
   * @param o the context and pre-hash
   * @return mu
   */
  public static byte[] mu(String alg, byte[] pk, byte[] msg, Opts o) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    Opts x = o == null ? Opts.none() : o;
    try (Arena m = Arena.ofConfined()) {
      MemorySegment mu = Native.out(m, 64);
      byte[] c = x.c();
      Native.rc(
          (int)
              Native.NQSMU.invoke(
                  a.id(), Native.in(m, pk), (long) pk.length, Native.in(m, msg),
                  (long) msg.length, Native.in(m, c), (long) c.length, x.ph(), mu, 64L));
      return Native.bytes(mu, 64);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The signature of the message whose mu is mu ({@link #mu}): the bytes
   * {@link #sign} gives for that message with the same randomness.
   *
   * @param alg ML-DSA-44, -65 or -87
   * @param sk the secret key
   * @param mu the message's mu
   * @param o its randomness (rnd or deterministic; the rest is not used)
   * @return the signature
   */
  public static byte[] signmu(String alg, byte[] sk, byte[] mu, Opts o) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    byte[] r = rnd(alg, o == null ? Opts.none() : o);
    try (Arena m = Arena.ofConfined()) {
      MemorySegment s = Native.out(m, a.sig()), n = m.allocate(JAVA_LONG), k = Native.in(m, sk);
      int c =
          (int)
              Native.NQSIGNMU.invoke(
                  a.id(), k, (long) sk.length, Native.in(m, mu), (long) mu.length,
                  Native.in(m, r), r == null ? 0L : (long) r.length, s, (long) a.sig(), n);
      Native.wipe(k, sk.length);
      Native.rc(c);
      return Native.bytes(s, n.get(JAVA_LONG, 0));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Whether sig verifies for the message whose mu is mu.
   *
   * @param alg ML-DSA-44, -65 or -87
   * @param pk the public key
   * @param mu the message's mu
   * @param sig the signature
   * @return true when it verifies
   */
  public static boolean verifymu(String alg, byte[] pk, byte[] mu, byte[] sig) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    try (Arena m = Arena.ofConfined()) {
      int c =
          (int)
              Native.NQVRFYMU.invoke(
                  a.id(), Native.in(m, pk), (long) pk.length, Native.in(m, mu), (long) mu.length,
                  Native.in(m, sig), (long) sig.length);
      if (c == -3 || c == -4) {
        return false;
      }
      Native.rc(c);
      return true;
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The length of alg's version 2 secret-key container: the key S, for
   * Ed25519 and the hybrids the Ed25519 public key P, and the integrity
   * value T, SHA3-256 of a domain string, the name, S and P
   * (docs/spec/keyfile.md).
   *
   * @param alg the algorithm
   * @return the length in bytes
   */
  public static int sxsize(String alg) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment n = m.allocate(JAVA_LONG);
      Native.rc((int) Native.NQSXSZ.invoke(a.id(), n));
      return (int) n.get(JAVA_LONG, 0);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The version 2 container of the secret key sk. Every signing function
   * takes it in place of sk: after signing it checks the integrity value
   * (and for Ed25519 and the hybrids the public key) again, so that a
   * change to any stored byte of the key ends in a NoqtisException of code
   * -11 (a fault) before a signature leaves.
   *
   * @param alg the algorithm
   * @param sk the secret key
   * @return the container
   */
  public static byte[] sxmake(String alg, byte[] sk) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    int n = sxsize(alg);
    try (Arena m = Arena.ofConfined()) {
      MemorySegment k = Native.in(m, sk), x = Native.out(m, n);
      try {
        Native.rc((int) Native.NQSXMK.invoke(a.id(), k, (long) sk.length, x, (long) n));
        return Native.bytes(x, n);
      } finally {
        Native.wipe(k, sk.length);
        Native.wipe(x, n);
      }
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Whether x is a sound container: false when it is damaged; a key with
   * no container (version 1) throws a NoqtisException of code -8.
   *
   * @param alg the algorithm
   * @param x the container
   * @return true when it checks
   */
  public static boolean sxcheck(String alg, byte[] x) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment k = Native.in(m, x);
      int c;
      try {
        c = (int) Native.NQSXCHK.invoke(a.id(), k, (long) x.length);
      } finally {
        Native.wipe(k, x.length);
      }
      if (c == -4) {
        return false;
      }
      Native.rc(c);
      return true;
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }
}
