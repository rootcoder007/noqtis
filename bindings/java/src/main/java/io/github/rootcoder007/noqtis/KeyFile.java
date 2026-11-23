// SPDX-License-Identifier: LGPL-3.0-or-later
package io.github.rootcoder007.noqtis;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/**
 * The CLI's key files (docs/guides/keys.md, docs/spec/keyfile.md): a header
 * line {@code noqtis-key-1 <algorithm> <pub|sec>} and the key bytes as
 * padded base64 in lines of 64 characters, as {@code noqtis keygen} writes
 * them. A signature secret key is written as {@code noqtis-key-2
 * <algorithm> sec} holding its version 2 container ({@link Sign#sxmake}),
 * which {@link #decode} returns; a version 1 file still decodes, to the
 * key. {@link
 * #decode} is as strict as the CLI's reader: the exact header, {@code \n}
 * or {@code \r\n} line ends and nothing else outside the base64 alphabet,
 * canonical padding, and the algorithm's exact key size. The base64 coder
 * has no table lookups or branches on the key bytes; the JVM promises
 * nothing about timing, so that is best effort.
 */
public final class KeyFile {
  private KeyFile() {}

  /**
   * The first word of a key file of version 1: a public key, a KEM secret
   * key, or a signature secret key written before 0.3.0.
   */
  public static final String MAGIC = "noqtis-key-1";

  /** The first word of a signature secret key in the version 2 container. */
  public static final String MAGIC2 = "noqtis-key-2";

  /**
   * A decoded key file.
   *
   * @param alg the algorithm's name, as noqtis spells it
   * @param kind "pub" or "sec"
   * @param key the key bytes
   */
  public record Key(String alg, String kind, byte[] key) {}

  private static Noqtis.Alg kalg(String name) {
    try {
      return Noqtis.alg(name);
    } catch (NoqtisException e) {
      throw new NoqtisException(
          -8, "unknown algorithm \"" + name + "\" (the names `noqtis algs` lists)");
    }
  }

  private static int size(Noqtis.Alg a, String kind) {
    return kind.equals("pub") ? a.pk() : a.sk();
  }

  // 0-25 'A'.., 26-51 'a'.., 52-61 '0'.., 62 '+', 63 '/', without branches
  private static byte ench(int x) {
    int c = x + 65;
    c += ((25 - x) >> 8) & 6;
    c -= ((51 - x) >> 8) & 75;
    c -= ((61 - x) >> 8) & 15;
    c += ((62 - x) >> 8) & 3;
    return (byte) c;
  }

  private static int rng(int c, int lo, int hi, int off) {
    int m = ((lo - 1 - c) & (c - hi - 1)) >> 8; // -1 when lo <= c <= hi
    return m & (c - lo + off + 1);
  }

  // the value of a base64 character, or -1, without branches
  private static int dech(int c) {
    int v = -1 + rng(c, 65, 90, 0) + rng(c, 97, 122, 26) + rng(c, 48, 57, 52);
    v += (((42 - c) & (c - 44)) >> 8) & 63; // '+': 62
    v += (((46 - c) & (c - 48)) >> 8) & 64; // '/': 63
    return v;
  }

  private static byte[] b64e(byte[] k) {
    ByteArrayOutputStream o = new ByteArrayOutputStream();
    for (int i = 0; i < k.length; i += 3) {
      int n = k.length - i;
      int v = (k[i] & 255) << 16;
      if (n > 1) {
        v |= (k[i + 1] & 255) << 8;
      }
      if (n > 2) {
        v |= k[i + 2] & 255;
      }
      o.write(ench(v >> 18));
      o.write(ench((v >> 12) & 63));
      o.write(n > 1 ? ench((v >> 6) & 63) : '=');
      o.write(n > 2 ? ench(v & 63) : '=');
    }
    return o.toByteArray();
  }

  // strict, padded, canonical base64, or null
  private static byte[] b64d(byte[] s, int len) {
    if (len % 4 != 0) {
      return null;
    }
    ByteArrayOutputStream o = new ByteArrayOutputStream();
    int bad = 0;
    for (int i = 0; i < len; i += 4) {
      int pad = 0;
      if (i + 4 == len) {
        if (s[i + 3] == '=') {
          pad++;
        }
        if (s[i + 2] == '=') {
          pad++;
        }
        if (pad == 1 && s[i + 2] == '=') {
          return null;
        }
      }
      int v = 0;
      for (int j = 0; j < 4; j++) {
        int d = j < 4 - pad ? dech(s[i + j] & 255) : 0;
        bad |= d;
        v = v << 6 | (d & 63);
      }
      o.write(v >> 16);
      if (pad < 2) {
        o.write(v >> 8);
      } else if ((v & 0xffff) != 0) {
        return null;
      }
      if (pad < 1) {
        o.write(v);
      } else if ((v & 0xff) != 0) {
        return null;
      }
    }
    return bad < 0 ? null : o.toByteArray();
  }

  /**
   * The key file text for key.
   *
   * @param alg the algorithm, in any case
   * @param kind "pub" or "sec"
   * @param key the key bytes
   * @return the text
   */
  public static String encode(String alg, String kind, byte[] key) {
    return encode(alg, kind, key, null);
  }

  /** The passphrase as UTF-8; the caller wipes it. */
  private static byte[] utf8(char[] pw) {
    java.nio.ByteBuffer b = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(pw));
    byte[] out = new byte[b.remaining()];
    b.get(out);
    if (b.hasArray()) {
      java.util.Arrays.fill(b.array(), (byte) 0);
    }
    if (out.length < 1 || out.length > 4096) {
      Noqtis.wipe(out);
      throw new NoqtisException(-1, "a passphrase is 1 to 4096 bytes");
    }
    return out;
  }

  private static byte[] ad(Noqtis.Alg a, String magic) {
    return (magic + " " + a.name() + " sec").getBytes(StandardCharsets.US_ASCII);
  }

  /**
   * sk under the passphrase pw (noqtis-pwkey-1): Argon2id with m KiB, t
   * passes and p lanes (0 for each: 64 MiB, 3, 4) gives the key of
   * ChaCha20-Poly1305, whose associated data includes ad.
   *
   * @param pw the passphrase, 1 to 4096 bytes
   * @param sk the secret key
   * @param ad the associated data (null for none)
   * @param m memory in KiB, or 0
   * @param t passes, or 0
   * @param p lanes, or 0
   * @return the protected key
   */
  public static byte[] pwenc(byte[] pw, byte[] sk, byte[] ad, int m, int t, int p) {
    byte[] x = ad == null ? new byte[0] : ad;
    try (Arena a = Arena.ofConfined()) {
      MemorySegment ps = Native.in(a, pw), ks = Native.in(a, sk);
      try {
        return Native.sized(
            a,
            sk.length + 51L,
            (o, cap, n) ->
                (int)
                    Native.NQPWENC.invoke(
                        ps, (long) pw.length, Native.in(a, x), (long) x.length, m, t, p, ks,
                        (long) sk.length, o, cap, n));
      } finally {
        Native.wipe(ps, pw.length);
        Native.wipe(ks, sk.length);
      }
    } catch (Throwable e) {
      throw Native.wrap(e);
    }
  }

  /** The derivation of {@link #pwenc}: Argon2id. */
  public static final int KDF_ARGON2ID = 1;

  /** PBKDF2 with HMAC-SHA-256, for places whose rules ask for it. */
  public static final int KDF_PBKDF2 = 2;

  /**
   * {@link #pwenc} under the derivation kdf: {@link #KDF_ARGON2ID} with m, t
   * and p as there, or {@link #KDF_PBKDF2} with t the iteration count (0:
   * 600000; 100000 to 10000000) and m and p 0. {@link #pwdec} reads both.
   *
   * @param kdf {@link #KDF_ARGON2ID} or {@link #KDF_PBKDF2}
   * @param pw the passphrase, 1 to 4096 bytes
   * @param sk the secret key
   * @param ad the associated data (null for none)
   * @param m memory in KiB, or 0
   * @param t passes or iterations, or 0
   * @param p lanes, or 0
   * @return the protected key
   */
  public static byte[] pwenc2(int kdf, byte[] pw, byte[] sk, byte[] ad, int m, int t, int p) {
    byte[] x = ad == null ? new byte[0] : ad;
    try (Arena a = Arena.ofConfined()) {
      MemorySegment ps = Native.in(a, pw), ks = Native.in(a, sk);
      try {
        return Native.sized(
            a,
            sk.length + 51L,
            (o, cap, n) ->
                (int)
                    Native.NQPWENC2.invoke(
                        kdf, ps, (long) pw.length, Native.in(a, x), (long) x.length, m, t, p,
                        ks, (long) sk.length, o, cap, n));
      } finally {
        Native.wipe(ps, pw.length);
        Native.wipe(ks, sk.length);
      }
    } catch (Throwable e) {
      throw Native.wrap(e);
    }
  }

  /**
   * The key {@link #pwenc} protected: {@link NoqtisException.Code#VERIFY}
   * for a wrong passphrase or ad, or any changed byte;
   * {@link NoqtisException.Code#LIMIT} for parameters over the limits (a
   * file cannot ask for more memory or time). Wipe it after use.
   *
   * @param pw the passphrase
   * @param data the protected key
   * @param ad the associated data (null for none)
   * @return the secret key
   */
  public static byte[] pwdec(byte[] pw, byte[] data, byte[] ad) {
    byte[] x = ad == null ? new byte[0] : ad;
    try (Arena a = Arena.ofConfined()) {
      MemorySegment ps = Native.in(a, pw);
      try {
        return Native.sized(
            a,
            Math.max(data.length - 51L, 1),
            (o, cap, n) ->
                (int)
                    Native.NQPWDEC.invoke(
                        ps, (long) pw.length, Native.in(a, x), (long) x.length,
                        Native.in(a, data), (long) data.length, o, cap, n));
      } finally {
        Native.wipe(ps, pw.length);
      }
    } catch (Throwable e) {
      throw Native.wrap(e);
    }
  }

  /**
   * The key file text for key, a secret key kept under passphrase when it
   * is not null (the format {@code noqtis keygen --pass-fd} writes).
   *
   * @param alg the algorithm, in any case
   * @param kind "pub" or "sec"
   * @param key the key bytes
   * @param passphrase the passphrase, or null
   * @return the text
   */
  public static String encode(String alg, String kind, byte[] key, char[] passphrase) {
    Noqtis.Alg a = kalg(alg);
    if (!kind.equals("pub") && !kind.equals("sec")) {
      throw new NoqtisException(-1, "kind: \"pub\" or \"sec\"");
    }
    String magic = MAGIC;
    if (kind.equals("sec") && a.kind().equals("sign")) {
      // a signature secret key is written in the version 2 container: the
      // key becomes one, a container is taken once it checks
      magic = MAGIC2;
      if (key.length == a.sk()) {
        key = Sign.sxmake(a.name(), key);
      } else if (key.length != Sign.sxsize(a.name()) || !Sign.sxcheck(a.name(), key)) {
        throw new NoqtisException(
            -1,
            a.name()
                + " secret key: "
                + key.length
                + " bytes, neither the key ("
                + a.sk()
                + ") nor a sound container");
      }
    } else {
      int want = size(a, kind);
      if (key.length != want) {
        throw new NoqtisException(
            -1, a.name() + " " + kind + " key: " + want + " bytes, not " + key.length);
      }
    }
    if (passphrase != null) {
      if (!kind.equals("sec")) {
        throw new NoqtisException(-1, "a passphrase protects a secret key only");
      }
      byte[] pw = utf8(passphrase);
      try {
        key = pwenc(pw, key, ad(a, magic), 0, 0, 0);
      } finally {
        Noqtis.wipe(pw);
      }
    }
    String b = new String(b64e(key), StandardCharsets.US_ASCII);
    StringBuilder s = new StringBuilder(magic + " " + a.name() + " " + kind + "\n");
    for (int i = 0; i < b.length(); i += 64) {
      s.append(b, i, Math.min(i + 64, b.length())).append('\n');
    }
    return s.toString();
  }

  private static NoqtisException notkey() {
    return new NoqtisException(
        -4,
        "not a noqtis key file (want a first line \""
            + MAGIC
            + " <alg> <pub|sec>\" or \""
            + MAGIC2
            + " <alg> sec\")");
  }

  /**
   * The algorithm, kind and key of key file text.
   *
   * @param text the file's bytes
   * @return the key
   */
  public static Key decode(byte[] text) {
    return decode(text, null);
  }

  /**
   * The algorithm, kind and key of key file text, opening a secret key
   * kept under passphrase.
   *
   * @param text the file's bytes
   * @param passphrase the passphrase, or null
   * @return the key
   */
  public static Key decode(byte[] text, char[] passphrase) {
    int nl = -1;
    for (int i = 0; i < text.length; i++) {
      if (text[i] == '\n') {
        nl = i;
        break;
      }
    }
    if (nl < 0 || nl >= 96) {
      throw notkey();
    }
    int hl = nl > 0 && text[nl - 1] == '\r' ? nl - 1 : nl;
    String h = new String(text, 0, hl, StandardCharsets.UTF_8);
    String[] f = h.split(" ", -1);
    boolean v2 = f.length == 3 && f[0].equals(MAGIC2) && f[2].equals("sec");
    if (f.length != 3
        || !(f[0].equals(MAGIC) || v2)
        || !(f[2].equals("pub") || f[2].equals("sec"))) {
      throw notkey();
    }
    Noqtis.Alg a = kalg(f[1]);
    if (v2 && !a.kind().equals("sign")) {
      throw new NoqtisException(
          -4, "a " + a.name() + " key has no version 2 container (only signature keys do)");
    }
    int want = v2 ? Sign.sxsize(a.name()) : size(a, f[2]);
    Key r = open(a, f, want, text, nl, passphrase);
    if (v2 && !Sign.sxcheck(a.name(), r.key())) {
      throw new NoqtisException(
          -4,
          "the secret key is damaged: its integrity value does not match (restore the file from"
              + " a copy)");
    }
    return r;
  }

  private static Key open(
      Noqtis.Alg a, String[] f, int want, byte[] text, int nl, char[] passphrase) {
    byte[] body = new byte[text.length];
    int n = 0;
    for (int i = nl + 1; i < text.length; i++) {
      if (text[i] != '\r' && text[i] != '\n') {
        body[n++] = text[i];
      }
    }
    byte[] k = b64d(body, n);
    if (k != null && f[2].equals("sec") && k.length == want + 51 && k[0] == 'N' && k[1] == 'Q'
        && k[2] == 'P' && k[3] == 'W') {
      if (passphrase == null) {
        throw new NoqtisException(
            -1, "the key is protected by a passphrase: give it to decode or read");
      }
      byte[] pw = utf8(passphrase);
      try {
        return new Key(a.name(), f[2], pwdec(pw, k, ad(a, f[0])));
      } finally {
        Noqtis.wipe(pw);
      }
    }
    if (k != null && k.length == want && passphrase != null && f[2].equals("sec")) {
      throw new NoqtisException(-1, "the key is not protected by a passphrase");
    }
    if (k == null || k.length != want) {
      throw new NoqtisException(
          -4,
          "the key is not "
              + want
              + " bytes of base64 for "
              + a.name()
              + " (the file is damaged or cut short)");
    }
    return new Key(a.name(), f[2], k);
  }

  /**
   * Reads a key file.
   *
   * @param file the file
   * @param kind "pub" or "sec" to require that kind, or null for either
   * @return the key
   */
  public static Key read(Path file, String kind) {
    return read(file, kind, null);
  }

  /**
   * Reads a key file, opening a secret key kept under passphrase.
   *
   * @param file the file
   * @param kind "pub" or "sec" to require that kind, or null for either
   * @param passphrase the passphrase, or null
   * @return the key
   */
  public static Key read(Path file, String kind, char[] passphrase) {
    if (kind != null && !kind.equals("pub") && !kind.equals("sec")) {
      throw new NoqtisException(-1, "kind: null, \"pub\" or \"sec\"");
    }
    byte[] t;
    try (InputStream in = Files.newInputStream(file)) {
      t = in.readNBytes(1 << 20);
    } catch (IOException e) {
      throw new NoqtisException(-7, "cannot read key file " + file + ": " + e.getMessage());
    }
    Key k = decode(t, passphrase);
    if (kind != null && !k.kind().equals(kind)) {
      throw new NoqtisException(
          -1,
          file
              + " is a "
              + (k.kind().equals("sec") ? "secret" : "public")
              + " key; give the "
              + (kind.equals("sec") ? "secret" : "public")
              + " key");
    }
    return k;
  }

  /**
   * Writes a key file. A secret key file is created owner-only (where the
   * file system has POSIX permissions), never through a link; an existing
   * file is kept unless force, which removes it first so the new one never
   * inherits its permissions.
   *
   * @param file the file
   * @param alg the algorithm
   * @param kind "pub" or "sec"
   * @param key the key bytes
   * @param force replace an existing file
   */
  public static void write(Path file, String alg, String kind, byte[] key, boolean force) {
    write(file, alg, kind, key, force, null);
  }

  /**
   * Writes a key file, a secret key kept under passphrase when it is not
   * null; as {@link #write(Path, String, String, byte[], boolean)}.
   *
   * @param file the file
   * @param alg the algorithm
   * @param kind "pub" or "sec"
   * @param key the key bytes
   * @param force replace an existing file
   * @param passphrase the passphrase, or null
   */
  public static void write(
      Path file, String alg, String kind, byte[] key, boolean force, char[] passphrase) {
    byte[] t = encode(alg, kind, key, passphrase).getBytes(StandardCharsets.US_ASCII);
    try {
      if (force) {
        Files.deleteIfExists(file);
      }
      boolean posix =
          file.toAbsolutePath().getFileSystem().supportedFileAttributeViews().contains("posix");
      FileAttribute<?>[] at = new FileAttribute<?>[0];
      if (posix) {
        at =
            new FileAttribute<?>[] {
              PosixFilePermissions.asFileAttribute(
                  PosixFilePermissions.fromString(kind.equals("sec") ? "rw-------" : "rw-r--r--"))
            };
      }
      Set<OpenOption> op = Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
      try (SeekableByteChannel ch = Files.newByteChannel(file, op, at)) {
        ByteBuffer b = ByteBuffer.wrap(t);
        while (b.hasRemaining()) {
          ch.write(b);
        }
      }
    } catch (FileAlreadyExistsException e) {
      throw new NoqtisException(-7, file + " exists (pass force to replace it)");
    } catch (IOException e) {
      throw new NoqtisException(-7, "cannot write " + file + ": " + e.getMessage());
    }
  }
}
