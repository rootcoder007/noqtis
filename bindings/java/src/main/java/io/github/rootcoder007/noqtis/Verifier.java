// SPDX-License-Identifier: LGPL-3.0-or-later
package io.github.rootcoder007.noqtis;

import java.io.IOException;
import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * {@link Sign#verify} over a message given in pieces: {@link #update} any
 * number of times, then {@link #verify}, as {@link Signer}.
 */
public final class Verifier implements AutoCloseable {
  private final Signer s;

  /**
   * Starts checking a signature under pk.
   *
   * @param alg the algorithm
   * @param pk the public key
   * @param o its context and pre-hash, as for {@link Sign#verify}
   */
  public Verifier(String alg, byte[] pk, Sign.Opts o) {
    s = new Signer(alg, pk, o, true);
  }

  /**
   * Adds len bytes of data from off.
   *
   * @param data the next piece
   * @param off where it starts
   * @param len its length
   */
  public void update(byte[] data, int off, int len) {
    s.update(data, off, len);
  }

  /**
   * Adds data.
   *
   * @param data the next piece
   */
  public void update(byte[] data) {
    s.update(data);
  }

  /**
   * Adds the rest of in, 64 KiB at a time.
   *
   * @param in the stream
   * @throws IOException when it cannot be read
   */
  public void update(InputStream in) throws IOException {
    s.update(in);
  }

  /**
   * Whether sig is a valid signature of the whole message; ends the
   * verifier.
   *
   * @param sig the signature
   * @return true when it verifies
   */
  public boolean verify(byte[] sig) {
    if (!s.m.scope().isAlive()) {
      throw new NoqtisException(-10);
    }
    byte[] pk = s.key();
    try (Arena t = Arena.ofConfined()) {
      int c =
          (int)
              Native.NQVFIN.invoke(
                  s.c, Native.in(t, pk), (long) pk.length, Native.in(t, sig), (long) sig.length);
      if (c == 0) {
        return true;
      }
      if (c == -3 || c == -4) {
        return false;
      }
      throw new NoqtisException(c);
    } catch (Throwable e) {
      throw Native.wrap(e);
    } finally {
      s.close();
    }
  }

  /** Wipes and frees the context. */
  @Override
  public void close() {
    s.close();
  }
}
