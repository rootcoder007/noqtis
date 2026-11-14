// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
package io.github.rootcoder007.noqtis;

import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;

/**
 * Streams sealed to an ML-KEM public key (noqtis-kstream-1), the format
 * of {@code noqtis box}, in memory of one chunk: {@link #box} and
 * {@link #unbox} between streams, or {@link Sealer} and {@link Opener}
 * chunk by chunk.
 *
 * <pre>{@code
 * Box.box("ML-KEM-768", pk, in, out, null, 0);
 * Box.unbox("ML-KEM-768", sk, sealed, plain, null);
 * }</pre>
 */
public final class Box {
  private Box() {}

  /** The default chunk size (NQKFCHUNK). */
  public static final int CHUNK = 65536;

  private abstract static class Ctx implements AutoCloseable {
    final Arena m = Arena.ofShared();
    final MemorySegment c = m.allocate(16 * 8, 8);
    int chunk;

    byte[] step(MethodHandle f, byte[] in, int len, long cap, boolean last) {
      if (!m.scope().isAlive()) {
        throw new NoqtisException(-10);
      }
      try (Arena t = Arena.ofConfined()) {
        MemorySegment i = Native.out(t, len).copyFrom(MemorySegment.ofArray(in).asSlice(0, len));
        MemorySegment o = Native.out(t, cap), n = t.allocate(JAVA_LONG);
        int r = (int) f.invoke(c, i, (long) len, o, cap, n);
        if (last || (r != 0 && r != -2)) {
          close();
        }
        Native.rc(r);
        byte[] b = Native.bytes(o, n.get(JAVA_LONG, 0));
        Native.wipe(o, cap);
        Native.wipe(i, len);
        return b;
      } catch (Throwable e) {
        throw Native.wrap(e);
      }
    }

    /**
     * The chunk size.
     *
     * @return its bytes
     */
    public int chunk() {
      return chunk;
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

  /**
   * Seals a stream: write {@link #header} first, then {@link #update}
   * each full chunk and {@link #last} the last (0 to chunk bytes; a stream
   * that ends on a full chunk ends with it).
   */
  public static final class Sealer extends Ctx {
    private final byte[] hdr;

    /**
     * Starts a stream to pk.
     *
     * @param alg ML-KEM-512, -768 or -1024
     * @param pk the public key
     * @param ctx the context, at most 255 bytes (null for none)
     * @param chunk 1024 to 16777216 bytes, 0 for {@link #CHUNK}
     */
    public Sealer(String alg, byte[] pk, byte[] ctx, int chunk) {
      Noqtis.Alg a = Noqtis.find(alg, "kem");
      byte[] cx = ctx == null ? new byte[0] : ctx;
      this.chunk = chunk == 0 ? CHUNK : chunk;
      try (Arena t = Arena.ofConfined()) {
        MemorySegment h = Native.out(t, 17L + a.ct()), n = t.allocate(JAVA_LONG);
        Native.rc(
            (int)
                Native.NQKFEINI.invoke(
                    c, a.id(), Native.in(t, pk), (long) pk.length, Native.in(t, cx),
                    (long) cx.length, this.chunk, h, 17L + a.ct(), n));
        hdr = Native.bytes(h, n.get(JAVA_LONG, 0));
      } catch (Throwable e) {
        close();
        throw Native.wrap(e);
      }
    }

    /**
     * The stream's header.
     *
     * @return its bytes
     */
    public byte[] header() {
      return hdr.clone();
    }

    /**
     * One full chunk, sealed.
     *
     * @param in chunk bytes
     * @return the sealed chunk
     */
    public byte[] update(byte[] in) {
      return step(Native.NQKFEUPD, in, in.length, chunk + 16L, false);
    }

    /**
     * The last chunk, sealed; the stream ends.
     *
     * @param in 0 to chunk bytes
     * @return the sealed chunk
     */
    public byte[] last(byte[] in) {
      return step(Native.NQKFEFIN, in, in.length, chunk + 16L, true);
    }
  }

  /**
   * Opens what {@link Sealer} wrote: give it the header, then each sealed
   * chunk (chunk + 16 bytes) to {@link #update} and the last to
   * {@link #last}. A chunk's plaintext comes back only when its tag
   * verifies ({@link NoqtisException.Code#VERIFY} otherwise: a changed,
   * moved, dropped or cut chunk).
   */
  public static final class Opener extends Ctx {
    /**
     * Reads the header.
     *
     * @param alg ML-KEM-512, -768 or -1024
     * @param sk the secret key
     * @param hdr 17 bytes and the KEM ciphertext
     * @param ctx the context it was sealed with (null for none)
     */
    public Opener(String alg, byte[] sk, byte[] hdr, byte[] ctx) {
      Noqtis.Alg a = Noqtis.find(alg, "kem");
      byte[] cx = ctx == null ? new byte[0] : ctx;
      try (Arena t = Arena.ofConfined()) {
        MemorySegment ch = t.allocate(JAVA_INT), k = Native.in(t, sk);
        int r =
            (int)
                Native.NQKFDINI.invoke(
                    c, a.id(), k, (long) sk.length, Native.in(t, cx), (long) cx.length,
                    Native.in(t, hdr), (long) hdr.length, ch);
        Native.wipe(k, sk.length);
        Native.rc(r);
        chunk = ch.get(JAVA_INT, 0);
      } catch (Throwable e) {
        close();
        throw Native.wrap(e);
      }
    }

    /**
     * One sealed chunk, opened.
     *
     * @param in chunk + 16 bytes
     * @return the plaintext
     */
    public byte[] update(byte[] in) {
      return step(Native.NQKFDUPD, in, in.length, chunk, false);
    }

    /**
     * The last sealed chunk, opened; the stream ends.
     *
     * @param in 16 to chunk + 16 bytes
     * @return the plaintext
     */
    public byte[] last(byte[] in) {
      return step(Native.NQKFDFIN, in, in.length, chunk, true);
    }
  }

  @FunctionalInterface
  private interface Step {
    byte[] call(byte[] b, boolean last);
  }

  /** Moves in to out in pieces of n bytes; the last is the one no byte follows. */
  private static void pump(InputStream in, OutputStream out, int n, Step f) throws IOException {
    byte[] b = new byte[n];
    int pre = 0;
    try {
      for (; ; ) {
        int got = pre + in.readNBytes(b, pre, n - pre);
        int nx = got == n ? in.read() : -1;
        byte[] p = got == n ? b : java.util.Arrays.copyOf(b, got);
        byte[] o = f.call(p, nx < 0);
        if (p != b) {
          java.util.Arrays.fill(p, (byte) 0);
        }
        out.write(o);
        if (nx < 0) {
          return;
        }
        b[0] = (byte) nx;
        pre = 1;
      }
    } finally {
      java.util.Arrays.fill(b, (byte) 0);
    }
  }

  /**
   * Seals all of in to out as {@code noqtis box} does, one chunk in memory.
   *
   * @param alg ML-KEM-512, -768 or -1024
   * @param pk the public key
   * @param in the plaintext
   * @param out the sealed stream
   * @param ctx the context (null for none)
   * @param chunk the chunk size, 0 for {@link #CHUNK}
   * @throws IOException when a stream fails
   */
  public static void box(
      String alg, byte[] pk, InputStream in, OutputStream out, byte[] ctx, int chunk)
      throws IOException {
    try (Sealer s = new Sealer(alg, pk, ctx, chunk)) {
      out.write(s.header());
      pump(in, out, s.chunk(), (b, last) -> last ? s.last(b) : s.update(b));
    }
  }

  /**
   * Opens a sealed stream from in to out, chunk by chunk. On an error what
   * was written before the bad chunk had verified, but the stream is
   * incomplete: discard out.
   *
   * @param alg ML-KEM-512, -768 or -1024
   * @param sk the secret key
   * @param in the sealed stream
   * @param out the plaintext
   * @param ctx the context (null for none)
   * @throws IOException when a stream fails
   */
  public static void unbox(String alg, byte[] sk, InputStream in, OutputStream out, byte[] ctx)
      throws IOException {
    Noqtis.Alg a = Noqtis.find(alg, "kem");
    byte[] h = in.readNBytes(17 + a.ct());
    try (Opener u = new Opener(alg, sk, h, ctx)) {
      pump(in, out, u.chunk() + 16, (b, last) -> last ? u.last(b) : u.update(b));
    }
  }
}
