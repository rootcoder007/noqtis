// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
package io.github.rootcoder007.noqtis;

import java.io.IOException;
import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * A signature over a message given in pieces: {@link #update} any number
 * of times (or {@link #update(InputStream)}), then {@link #sign}, which
 * gives the bytes {@link Sign#sign} gives for the whole message with the
 * same randomness. Only the piece at hand is held; the secret key is the
 * caller's array, not a copy. ML-DSA (pure and pre-hash), and HashSLH-DSA,
 * Ed25519ph and the hybrids with prehash "SHA-512"; the others are
 * {@link NoqtisException.Code#UNSUPPORTED}. One use: then
 * {@link NoqtisException.Code#STATE}.
 *
 * <pre>{@code
 * try (Signer s = new Signer("ML-DSA-65", sk, Sign.Opts.none())) {
 *   s.update(in);
 *   byte[] sig = s.sign(Sign.Opts.none());
 * }
 * }</pre>
 */
public final class Signer implements AutoCloseable {
  final Arena m = Arena.ofShared();
  final MemorySegment c = m.allocate(160 * 8, 8);
  private final Noqtis.Alg a;
  private final byte[] key;

  Signer(String alg, byte[] key, Sign.Opts o, boolean verify) {
    a = Noqtis.find(alg, "sign");
    this.key = key;
    Sign.Opts x = o == null ? Sign.Opts.none() : o;
    try (Arena t = Arena.ofConfined()) {
      byte[] cx = x.c();
      MemorySegment k = Native.in(t, key);
      int r =
          (int)
              (verify ? Native.NQVINI : Native.NQSINI)
                  .invoke(c, a.id(), k, (long) key.length, Native.in(t, cx), (long) cx.length, x.ph());
      Native.wipe(k, key.length);
      Native.rc(r);
    } catch (Throwable e) {
      close();
      throw Native.wrap(e);
    }
  }

  /**
   * Starts a signature with sk.
   *
   * @param alg the algorithm
   * @param sk the secret key
   * @param o its context and pre-hash, as for {@link Sign#sign}
   */
  public Signer(String alg, byte[] sk, Sign.Opts o) {
    this(alg, sk, o, false);
  }

  /**
   * Adds len bytes of data from off.
   *
   * @param data the next piece
   * @param off where it starts
   * @param len its length
   */
  public void update(byte[] data, int off, int len) {
    if (!m.scope().isAlive()) {
      throw new NoqtisException(-10);
    }
    try (Arena t = Arena.ofConfined()) {
      MemorySegment s = Native.out(t, len).copyFrom(MemorySegment.ofArray(data).asSlice(off, len));
      Native.rc((int) Native.NQSUPD.invoke(c, s, (long) len));
    } catch (Throwable e) {
      throw Native.wrap(e);
    }
  }

  /**
   * Adds data.
   *
   * @param data the next piece
   */
  public void update(byte[] data) {
    update(data, 0, data.length);
  }

  /**
   * Adds the rest of in, 64 KiB at a time.
   *
   * @param in the stream
   * @throws IOException when it cannot be read
   */
  public void update(InputStream in) throws IOException {
    byte[] b = new byte[65536];
    for (int n; (n = in.read(b)) > 0; ) {
      update(b, 0, n);
    }
  }

  byte[] key() {
    return key;
  }

  /**
   * The signature; ends the signer.
   *
   * @param o its randomness, as for {@link Sign#sign} (rnd or deterministic)
   * @return the signature
   */
  public byte[] sign(Sign.Opts o) {
    if (!m.scope().isAlive()) {
      throw new NoqtisException(-10);
    }
    Sign.Opts x = o == null ? Sign.Opts.none() : o;
    byte[] r = Sign.rnd(a.name(), x);
    try (Arena t = Arena.ofConfined()) {
      MemorySegment k = Native.in(t, key), s = Native.out(t, a.sig()), n = t.allocate(8);
      MemorySegment rp = r == null ? MemorySegment.NULL : Native.out(t, r.length);
      if (r != null && r.length > 0) {
        rp.copyFrom(MemorySegment.ofArray(r));
      }
      int c2 =
          (int)
              Native.NQSFIN.invoke(
                  c, k, (long) key.length, rp, r == null ? 0L : (long) r.length, s, (long) a.sig(), n);
      Native.wipe(k, key.length);
      Native.rc(c2);
      return Native.bytes(s, n.get(java.lang.foreign.ValueLayout.JAVA_LONG, 0));
    } catch (Throwable e) {
      throw Native.wrap(e);
    } finally {
      close();
    }
  }

  /** Wipes and frees the context. */
  @Override
  public void close() {
    if (m.scope().isAlive()) {
      Native.wipe(c, c.byteSize());
      m.close();
    }
  }
}
