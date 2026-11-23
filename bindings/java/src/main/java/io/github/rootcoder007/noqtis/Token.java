// SPDX-License-Identifier: LGPL-3.0-or-later
package io.github.rootcoder007.noqtis;

import static io.github.rootcoder007.noqtis.Native.I;
import static io.github.rootcoder007.noqtis.Native.P;
import static io.github.rootcoder007.noqtis.Native.Z;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Keys on a token, through PKCS #11: a smart card, a hardware security
 * module, or a software token. The private key stays there; the token
 * signs and decapsulates. The post-quantum key types are those of PKCS
 * #11 version 3.2. A Token is for one thread at a time; close it when
 * done.
 *
 * <pre>{@code
 * try (Token t = Token.open(Path.of("/usr/lib/softhsm/libsofthsm2.so"))) {
 *   t.login(t.tokens().get(0).slot(), "1234");
 *   Token.Key k = t.generate("ML-DSA-65", "release");
 *   byte[] sig = t.sign(k, msg, null);
 * }
 * }</pre>
 */
public final class Token implements AutoCloseable {
  // C's unsigned long: 8 bytes, or 4 on Windows
  private static final MemoryLayout UL = Native.L.canonicalLayouts().get("long");
  private static final boolean W = UL.byteSize() == 4;
  private static final long ULS = UL.byteSize();

  private static final MethodHandle OPEN = Native.fn("nqp11open", I, P, P);
  private static final MethodHandle CLOSE = Native.fn("nqp11close", null, P);
  private static final MethodHandle WHY = Native.fn("nqp11why", UL, P);
  private static final MethodHandle TOKS = Native.fn("nqp11toks", I, P, P, Z, P);
  private static final MethodHandle LOGIN = Native.fn("nqp11login", I, P, UL, P, Z);
  private static final MethodHandle KEYS = Native.fn("nqp11keys", I, P, P, Z, P);
  private static final MethodHandle PUB = Native.fn("nqp11pub", I, P, P, P, Z, P);
  private static final MethodHandle SIGN = Native.fn("nqp11sign", I, P, P, P, Z, P, Z, P, Z, P);
  private static final MethodHandle DEC = Native.fn("nqp11dec", I, P, P, P, Z, P, Z);
  private static final MethodHandle GEN = Native.fn("nqp11gen", I, P, I, I, P, P);

  // nqp11t and nqp11k of noqtis.h: sizes and offsets, by the size of long
  private static final long TSIZE = align(ULS + 33 + 33 + 17 + 17 + 4, ULS);
  private static final long TLOGIN = align(ULS + 100, 4);
  private static final long KLABEL = 8 + ULS, KID = KLABEL + 65, KIDLEN = align(KID + 32, 8);
  private static final long KSIZE = KIDLEN + 8;

  private MemorySegment p;

  private Token(MemorySegment p) {
    this.p = p;
  }

  private static long align(long n, long a) {
    return (n + a - 1) / a * a;
  }

  /**
   * One token present.
   *
   * @param slot its slot, for {@link #login}
   * @param label its label
   * @param maker its maker
   * @param model its model
   * @param serial its serial number
   * @param login whether its keys need the PIN
   */
  public record Info(
      long slot, String label, String maker, String model, String serial, boolean login) {}

  /**
   * A private key on a token that noqtis can use.
   *
   * @param alg its algorithm
   * @param kem whether it is a KEM key
   * @param label its label
   * @param id its ID
   * @param handle the object, in the session that listed it
   */
  public record Key(String alg, boolean kem, String label, byte[] id, long handle) {}

  /**
   * Loads the PKCS #11 module at the path and starts it. The path must
   * have a folder in it: a bare name, which the system would search for,
   * throws ARG.
   *
   * @param module the module, a shared library
   * @return the token
   */
  public static Token open(Path module) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment h = m.allocate(ADDRESS);
      Native.rc((int) OPEN.invoke(m.allocateFrom(module.toString()), h));
      return new Token(h.get(ADDRESS, 0));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /** Ends the session and unloads the module. */
  @Override
  public void close() {
    if (p != null) {
      try {
        CLOSE.invoke(p);
      } catch (Throwable t) {
        throw Native.wrap(t);
      } finally {
        p = null;
      }
    }
  }

  private MemorySegment live() {
    if (p == null) {
      throw new NoqtisException(-10, "the token is closed");
    }
    return p;
  }

  private static long ul(MemorySegment s, long off) {
    return W ? Integer.toUnsignedLong(s.get(JAVA_INT, off)) : s.get(JAVA_LONG, off);
  }

  /**
   * The module's own return value for the last call it refused: a CKR
   * number of the standard.
   *
   * @return the number
   */
  public long why() {
    try {
      return W ? Integer.toUnsignedLong((int) WHY.invoke(live())) : (long) WHY.invoke(live());
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The tokens present.
   *
   * @return the tokens
   */
  public List<Info> tokens() {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment ts = m.allocate(TSIZE * 64, 8), n = m.allocate(JAVA_LONG);
      Native.rc((int) TOKS.invoke(live(), ts, 64L, n));
      List<Info> out = new ArrayList<>();
      long got = Math.min(64, n.get(JAVA_LONG, 0));
      for (long i = 0; i < got; i++) {
        MemorySegment e = ts.asSlice(i * TSIZE, TSIZE);
        out.add(
            new Info(
                ul(e, 0),
                e.getString(ULS),
                e.getString(ULS + 33),
                e.getString(ULS + 66),
                e.getString(ULS + 83),
                e.get(JAVA_INT, TLOGIN) != 0));
      }
      return out;
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Opens a session with the token in slot and, with a PIN, logs the
   * user in. Throws VERIFY for a wrong or locked PIN.
   *
   * @param slot the slot
   * @param pin the PIN, or null for a session without login
   */
  public void login(long slot, String pin) {
    byte[] b = pin == null ? null : pin.getBytes(StandardCharsets.UTF_8);
    try (Arena m = Arena.ofConfined()) {
      MemorySegment pn = Native.in(m, b);
      int c =
          W
              ? (int) LOGIN.invoke(live(), (int) slot, pn, Mail.len(b))
              : (int) LOGIN.invoke(live(), slot, pn, Mail.len(b));
      if (b != null && b.length > 0) {
        Native.wipe(pn, b.length);
      }
      Native.rc(c);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  private static Key key(MemorySegment k) throws Throwable {
    boolean kem = k.get(JAVA_INT, 0) != 0;
    int alg = k.get(JAVA_INT, 4);
    long il = Math.min(32, k.get(JAVA_LONG, KIDLEN));
    return new Key(
        Native.str((MemorySegment) (kem ? Native.NQKNAME : Native.NQSNAME).invoke(alg)),
        kem,
        k.getString(KLABEL),
        k.asSlice(KID, il).toArray(JAVA_BYTE),
        ul(k, 8));
  }

  /** The nqp11k of a Key, in m. */
  private static MemorySegment ck(Arena m, Key k, String kind) {
    Noqtis.Alg a = Noqtis.find(k.alg(), kind);
    if (k.id() == null || k.id().length > 32) {
      throw new NoqtisException(-1, "a key ID is at most 32 bytes");
    }
    MemorySegment s = m.allocate(KSIZE, 8);
    s.set(JAVA_INT, 0, k.kem() ? 1 : 0);
    s.set(JAVA_INT, 4, a.id());
    if (W) {
      s.set(JAVA_INT, 8, (int) k.handle());
    } else {
      s.set(JAVA_LONG, 8, k.handle());
    }
    MemorySegment.copy(MemorySegment.ofArray(k.id()), 0, s, KID, k.id().length);
    s.set(JAVA_LONG, KIDLEN, k.id().length);
    return s;
  }

  /**
   * The private keys of the token that noqtis can use. A token shows its
   * private keys after the PIN.
   *
   * @return the keys
   */
  public List<Key> keys() {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment ks = m.allocate(KSIZE * 64, 8), n = m.allocate(JAVA_LONG);
      int c = (int) KEYS.invoke(live(), ks, 64L, n);
      if (c != -2) {
        Native.rc(c);
      }
      List<Key> out = new ArrayList<>();
      long got = Math.min(64, n.get(JAVA_LONG, 0));
      for (long i = 0; i < got; i++) {
        out.add(key(ks.asSlice(i * KSIZE, KSIZE)));
      }
      return out;
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The public key of k, as {@link Sign#verify} and {@link Kem#encap}
   * take it.
   *
   * @param k the key
   * @return its public key
   */
  public byte[] publicKey(Key k) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment h = live(), c = ck(m, k, k.kem() ? "kem" : "sign");
      return Native.sized(m, 4096, (o, cap, n) -> (int) PUB.invoke(h, c, o, cap, n));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Signs msg on the token with the signature key k and the context ctx:
   * the signature {@link Sign#sign} makes, which {@link Sign#verify}
   * checks.
   *
   * @param k the key
   * @param msg the message
   * @param ctx the context, at most 255 bytes, or null
   * @return the signature
   */
  public byte[] sign(Key k, byte[] msg, byte[] ctx) {
    Noqtis.Alg a = Noqtis.find(k.alg(), "sign");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment h = live(), c = ck(m, k, "sign");
      MemorySegment mm = Native.in(m, msg), cx = Native.in(m, ctx);
      return Native.sized(
          m,
          a.sig(),
          (o, cap, n) ->
              (int) SIGN.invoke(h, c, mm, Mail.len(msg), cx, Mail.len(ctx), o, cap, n));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Decapsulates the ML-KEM ciphertext ct on the token with the key k, as
   * {@link Kem#decap} does. The module must be of PKCS #11 version 3.2;
   * an older one throws UNSUPPORTED.
   *
   * @param k the key
   * @param ct the ciphertext
   * @return the shared secret
   */
  public byte[] decap(Key k, byte[] ct) {
    Noqtis.Alg a = Noqtis.find(k.alg(), "kem");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment ss = m.allocate(a.ss());
      Native.rc(
          (int)
              DEC.invoke(
                  live(), ck(m, k, "kem"), Native.in(m, ct), Mail.len(ct), ss, (long) a.ss()));
      byte[] out = Native.bytes(ss, a.ss());
      Native.wipe(ss, a.ss());
      return out;
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Makes a key pair of alg on the token under label; the private key is
   * marked never to leave it. ML-DSA, SLH-DSA, Ed25519 and ML-KEM keys
   * are made on tokens; others throw UNSUPPORTED.
   *
   * @param alg the algorithm
   * @param label the label, 1 to 64 bytes
   * @return the key
   */
  public Key generate(String alg, String label) {
    Noqtis.Alg a = Noqtis.alg(alg);
    try (Arena m = Arena.ofConfined()) {
      MemorySegment k = m.allocate(KSIZE, 8);
      Native.rc(
          (int)
              GEN.invoke(
                  live(),
                  a.kind().equals("kem") ? 1 : 0,
                  a.id(),
                  Mail.cs(m, label == null ? "" : label, "label"),
                  k));
      return key(k);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }
}
