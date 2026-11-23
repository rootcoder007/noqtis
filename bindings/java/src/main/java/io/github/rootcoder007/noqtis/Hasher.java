// SPDX-License-Identifier: LGPL-3.0-or-later
package io.github.rootcoder007.noqtis;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * A digest of data given in pieces, as {@link Noqtis#hash} gives it for
 * the whole: {@link #update} any number of times, then {@link #digest};
 * for SHAKE, {@link #digest(int)} may be called again to squeeze more
 * output. {@link #close} frees it; not for use from two threads at once.
 *
 * <pre>{@code
 * try (Hasher h = new Hasher("SHA-256")) {
 *   h.update(part1);
 *   h.update(part2);
 *   byte[] d = h.digest();
 * }
 * }</pre>
 */
public final class Hasher implements AutoCloseable {
  private final Arena m = Arena.ofShared();
  private final MemorySegment c = m.allocate(52 * 8, 8);
  private final int n;
  private final boolean shake;

  /**
   * Starts a hash.
   *
   * @param alg "SHA-256", "SHA3-512", "SHAKE128", ...
   */
  public Hasher(String alg) {
    int i = Noqtis.hid(alg);
    try {
      Native.rc((int) Native.NQHINI.invoke(c, i));
      n = (int) (long) Native.NQHLEN.invoke(i);
    } catch (Throwable t) {
      m.close();
      throw Native.wrap(t);
    }
    shake = i >= 11;
  }

  /**
   * Adds data.
   *
   * @param data the next piece
   * @param off where it starts in data
   * @param len its length
   */
  public void update(byte[] data, int off, int len) {
    try (Arena a = Arena.ofConfined()) {
      MemorySegment s = Native.out(a, len).copyFrom(MemorySegment.ofArray(data).asSlice(off, len));
      Native.rc((int) Native.NQHUPD.invoke(c, s, (long) len));
    } catch (Throwable t) {
      throw Native.wrap(t);
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
   * The digest (for SHAKE, its default length).
   *
   * @return the digest
   */
  public byte[] digest() {
    return out(n);
  }

  /**
   * The next len bytes of a SHAKE output.
   *
   * @param len the bytes wanted
   * @return them
   */
  public byte[] digest(int len) {
    if (!shake) {
      throw new NoqtisException(-1, "a length is for SHAKE");
    }
    return out(len);
  }

  private byte[] out(int len) {
    try (Arena a = Arena.ofConfined()) {
      MemorySegment o = Native.out(a, len);
      Native.rc((int) Native.NQHFIN.invoke(c, o, (long) len));
      return Native.bytes(o, len);
    } catch (Throwable t) {
      throw Native.wrap(t);
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
