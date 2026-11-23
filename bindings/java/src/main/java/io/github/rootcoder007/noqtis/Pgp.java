// SPDX-License-Identifier: LGPL-3.0-or-later
package io.github.rootcoder007.noqtis;

import static io.github.rootcoder007.noqtis.Native.I;
import static io.github.rootcoder007.noqtis.Native.P;
import static io.github.rootcoder007.noqtis.Native.Z;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

/**
 * OpenPGP (RFC 9580) in its version 6 forms, with Ed25519 and X25519 and
 * the post-quantum algorithms of RFC 9980: keys, signatures
 * and encrypted messages. Keys and messages are binary packets; {@link
 * #armor} and {@link #dearmor} make them text and back, and {@link
 * #verify} and {@link #decrypt} take either.
 *
 * <pre>{@code
 * Pgp.KeyPair k = Pgp.generate(Pgp.MLDSA65, Pgp.MLKEM768, "Ada <ada@example.org>", null, null);
 * byte[] s = Pgp.sign(k.secret(), null, msg, Pgp.INLINE, null);
 * byte[] data = Pgp.verify(k.cert(), s, null).data(); // throws VERIFY
 * }</pre>
 */
public final class Pgp {
  private Pgp() {}

  /** X25519 (RFC 9580), an encryption subkey. */
  public static final int X25519 = 25;

  /** Ed25519 (RFC 9580). */
  public static final int ED25519 = 27;

  /** ML-DSA-65 with Ed25519. */
  public static final int MLDSA65 = 30;

  /** SLH-DSA-SHAKE-128s. */
  public static final int SLH128S = 32;

  /** SLH-DSA-SHAKE-128f. */
  public static final int SLH128F = 33;

  /** SLH-DSA-SHAKE-256s. */
  public static final int SLH256S = 34;

  /** ML-KEM-768 with X25519, an encryption subkey. */
  public static final int MLKEM768 = 35;

  /** {@link #sign}: a signed message that carries the data. */
  public static final int INLINE = 0;

  /** {@link #sign}: the signature alone. */
  public static final int DETACHED = 1;

  /** {@link #sign}: the text with the armored signature under it. */
  public static final int CLEAR = 2;

  /** Armor: PGP MESSAGE. */
  public static final int MESSAGE = 1;

  /** Armor: PGP PUBLIC KEY BLOCK. */
  public static final int PUBLICKEY = 2;

  /** Armor: PGP PRIVATE KEY BLOCK. */
  public static final int PRIVATEKEY = 3;

  /** Armor: PGP SIGNATURE. */
  public static final int SIGNATURE = 4;

  private static final MethodHandle GEN =
      Native.fn("nqpgpgen", I, I, I, P, Z, P, Z, P, Z, P, P, Z, P);
  private static final MethodHandle INFO = Native.fn("nqpgpinfo", I, P, Z, P);
  private static final MethodHandle SIGN =
      Native.fn("nqpgpsign", I, P, Z, P, Z, P, Z, I, Z, P, Z, P);
  private static final MethodHandle VRFY =
      Native.fn("nqpgpvrfy", I, P, Z, P, Z, P, Z, P, Z, P, P);
  private static final MethodHandle ENC =
      Native.fn("nqpgpenc", I, P, P, Z, P, Z, P, Z, P, Z, P, Z, Z, P, Z, P);
  private static final MethodHandle DEC =
      Native.fn("nqpgpdec", I, P, Z, P, Z, P, Z, P, Z, P, Z, P, P, P);
  private static final MethodHandle ARM = Native.fn("nqpgparm", I, I, P, Z, P, Z, P);
  private static final MethodHandle DEARM = Native.fn("nqpgpdearm", I, P, Z, P, P, Z, P);

  /**
   * A new key.
   *
   * @param secret the transferable secret key
   * @param cert the certificate, to give to others
   */
  public record KeyPair(byte[] secret, byte[] cert) {}

  /**
   * What an OpenPGP key or certificate says of itself.
   *
   * @param alg the primary key's algorithm
   * @param encAlg the encryption subkey's, 0 when it has none
   * @param secret whether it is a secret key
   * @param locked whether it is under a passphrase
   * @param fingerprint the primary key's, in hex
   * @param encFingerprint the encryption subkey's, or null
   * @param created when it was made
   * @param expires when it expires, or null for never
   * @param userId the user ID
   */
  public record Key(
      int alg,
      int encAlg,
      boolean secret,
      boolean locked,
      String fingerprint,
      String encFingerprint,
      Instant created,
      Instant expires,
      String userId) {}

  /**
   * A signature that verified.
   *
   * @param data what was signed
   * @param at the time of the signature
   */
  public record Verified(byte[] data, Instant at) {}

  /**
   * A message that opened.
   *
   * @param data the content
   * @param signed whether the signature of the signer certificate verified
   * @param at the time of that signature, or null
   */
  public record Opened(byte[] data, boolean signed, Instant at) {}

  /**
   * One armor read back.
   *
   * @param kind {@link #MESSAGE}, {@link #PUBLICKEY}, {@link #PRIVATEKEY} or {@link #SIGNATURE}
   * @param data its packets
   */
  public record Armored(int kind, byte[] data) {}

  /**
   * Makes a version 6 OpenPGP key: a primary key of sigAlg that certifies
   * and signs, the user ID (by convention {@code Name <address>}), and,
   * when encAlg is not 0, an encryption subkey.
   *
   * @param sigAlg the primary key's algorithm
   * @param encAlg the encryption subkey's, or 0 for none
   * @param userId the user ID
   * @param created when it is made, or null for now
   * @param passphrase a passphrase to keep the secret key under, or null
   * @return the secret key and the certificate
   */
  public static KeyPair generate(
      int sigAlg, int encAlg, String userId, Instant created, byte[] passphrase) {
    final long cap = 1L << 18;
    try (Arena m = Arena.ofConfined()) {
      MemorySegment s = m.allocate(cap), p = m.allocate(cap);
      MemorySegment sn = m.allocate(JAVA_LONG), pn = m.allocate(JAVA_LONG);
      int c =
          (int)
              GEN.invoke(
                  sigAlg,
                  encAlg,
                  Mail.cs(m, userId == null ? "" : userId, "userId"),
                  Mail.at(created),
                  Native.in(m, passphrase),
                  Mail.len(passphrase),
                  s,
                  cap,
                  sn,
                  p,
                  cap,
                  pn);
      if (c != 0) {
        Native.wipe(s, cap);
        Native.rc(c);
      }
      KeyPair k =
          new KeyPair(
              Native.bytes(s, sn.get(JAVA_LONG, 0)), Native.bytes(p, pn.get(JAVA_LONG, 0)));
      Native.wipe(s, cap);
      return k;
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Reads an OpenPGP key or certificate (binary). Only what a
   * self-signature of the primary key binds is taken; a key with none, or
   * a revoked one, throws VERIFY.
   *
   * @param key the key or certificate
   * @return what it says
   */
  public static Key info(byte[] key) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment f = m.allocate(352);
      Native.rc((int) INFO.invoke(Native.in(m, key), Mail.len(key), f));
      int enc = f.get(JAVA_INT, 4);
      long exp = f.get(JAVA_LONG, 88);
      HexFormat hx = HexFormat.of();
      return new Key(
          f.get(JAVA_INT, 0),
          enc,
          f.get(JAVA_INT, 8) != 0,
          f.get(JAVA_INT, 12) != 0,
          hx.formatHex(f.asSlice(16, 32).toArray(JAVA_BYTE)),
          enc == 0 ? null : hx.formatHex(f.asSlice(48, 32).toArray(JAVA_BYTE)),
          Instant.ofEpochSecond(f.get(JAVA_LONG, 80)),
          exp == 0 ? null : Instant.ofEpochSecond(exp),
          f.getString(96));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Signs msg with the secret key. The result is binary packets, except
   * with {@link #CLEAR}, which is text.
   *
   * @param key the secret key
   * @param passphrase its passphrase, or null
   * @param msg the message
   * @param mode {@link #INLINE}, {@link #DETACHED} or {@link #CLEAR}
   * @param at the signing time, or null for now
   * @return the signed message or the signature
   */
  public static byte[] sign(byte[] key, byte[] passphrase, byte[] msg, int mode, Instant at) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment k = Native.in(m, key), pw = Native.in(m, passphrase);
      MemorySegment mm = Native.in(m, msg);
      long when = Mail.at(at);
      return Native.sized(
          m,
          3 * Mail.len(msg) + (1L << 17),
          (o, cap, n) ->
              (int)
                  SIGN.invoke(
                      k,
                      Mail.len(key),
                      pw,
                      Mail.len(passphrase),
                      mm,
                      Mail.len(msg),
                      mode,
                      when,
                      o,
                      cap,
                      n));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Checks a signed message, a cleartext signature or a detached
   * signature, armored or binary, under the certificate. Throws VERIFY
   * when it does not verify.
   *
   * @param cert the signer's certificate
   * @param sig the signed message or the signature
   * @param msg what a detached signature signs, or null
   * @return the data that was signed and the time of the signature
   */
  public static Verified verify(byte[] cert, byte[] sig, byte[] msg) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment at = m.allocate(JAVA_LONG), n = m.allocate(JAVA_LONG);
      long cap = Mail.len(sig) + Mail.len(msg) + 1;
      MemorySegment o = Native.out(m, cap);
      // an empty message is still a message: null alone means none
      MemorySegment mm = msg == null ? MemorySegment.NULL : Native.out(m, msg.length);
      if (msg != null && msg.length > 0) {
        mm.copyFrom(MemorySegment.ofArray(msg));
      }
      Native.rc(
          (int)
              VRFY.invoke(
                  Native.in(m, cert),
                  Mail.len(cert),
                  Native.in(m, sig),
                  Mail.len(sig),
                  mm,
                  Mail.len(msg),
                  o,
                  cap,
                  n,
                  at));
      return new Verified(
          Native.bytes(o, n.get(JAVA_LONG, 0)), Instant.ofEpochSecond(at.get(JAVA_LONG, 0)));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Encrypts msg to the encryption subkeys of certs (at most 64) and,
   * with passphrase not null, to that passphrase as well: AES-256 with
   * OCB. With signer, a secret key, the message is signed first.
   *
   * @param certs the recipients' certificates, or null
   * @param passphrase a passphrase that opens it as well, or null
   * @param signer a secret key to sign with first, or null
   * @param signerPass its passphrase, or null
   * @param msg the message
   * @param at the time, or null for now
   * @return the encrypted message
   */
  public static byte[] encrypt(
      List<byte[]> certs,
      byte[] passphrase,
      byte[] signer,
      byte[] signerPass,
      byte[] msg,
      Instant at) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment[] cl = Mail.lists(m, certs);
      MemorySegment pw = Native.in(m, passphrase), sg = Native.in(m, signer);
      MemorySegment sp = Native.in(m, signerPass), mm = Native.in(m, msg);
      long nc = certs == null ? 0 : certs.size(), when = Mail.at(at);
      return Native.sized(
          m,
          Mail.len(msg) + Mail.len(msg) / 512 + 2048 * nc + (1L << 17),
          (o, cap, n) ->
              (int)
                  ENC.invoke(
                      cl[0],
                      cl[1],
                      nc,
                      pw,
                      Mail.len(passphrase),
                      sg,
                      Mail.len(signer),
                      sp,
                      Mail.len(signerPass),
                      mm,
                      Mail.len(msg),
                      when,
                      o,
                      cap,
                      n));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Opens an encrypted message, armored or binary, with the secret key
   * (passphrase is then the key's) or, with key null, with the passphrase
   * of the message. With signer, a certificate, the message inside must
   * be signed by it. Throws VERIFY when it does not open or the signature
   * does not verify.
   *
   * @param key the secret key, or null
   * @param passphrase the key's passphrase, or the message's
   * @param signer a certificate the message must be signed by, or null
   * @param msg the encrypted message
   * @return the content
   */
  public static Opened decrypt(byte[] key, byte[] passphrase, byte[] signer, byte[] msg) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment sb = m.allocate(JAVA_INT), at = m.allocate(JAVA_LONG);
      MemorySegment n = m.allocate(JAVA_LONG);
      long cap = Mail.len(msg) + 1;
      MemorySegment o = Native.out(m, cap);
      Native.rc(
          (int)
              DEC.invoke(
                  Native.in(m, key),
                  Mail.len(key),
                  Native.in(m, passphrase),
                  Mail.len(passphrase),
                  Native.in(m, signer),
                  Mail.len(signer),
                  Native.in(m, msg),
                  Mail.len(msg),
                  o,
                  cap,
                  n,
                  sb,
                  at));
      boolean signed = sb.get(JAVA_INT, 0) != 0;
      byte[] data = Native.bytes(o, n.get(JAVA_LONG, 0));
      Native.wipe(o, cap);
      return new Opened(
          data, signed, signed ? Instant.ofEpochSecond(at.get(JAVA_LONG, 0)) : null);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Writes OpenPGP packets as ASCII armor.
   *
   * @param kind {@link #MESSAGE}, {@link #PUBLICKEY}, {@link #PRIVATEKEY} or {@link #SIGNATURE}
   * @param data the packets
   * @return the armor
   */
  public static String armor(int kind, byte[] data) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment d = Native.in(m, data), n = m.allocate(JAVA_LONG);
      Native.rc((int) ARM.invoke(kind, d, Mail.len(data), MemorySegment.NULL, 0L, n));
      long cap = n.get(JAVA_LONG, 0);
      MemorySegment o = Native.out(m, cap);
      Native.rc((int) ARM.invoke(kind, d, Mail.len(data), o, cap, n));
      return new String(Native.bytes(o, n.get(JAVA_LONG, 0)), StandardCharsets.US_ASCII);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Reads one OpenPGP armor back.
   *
   * @param text the armor
   * @return its kind and packets
   */
  public static Armored dearmor(String text) {
    byte[] b = text.getBytes(StandardCharsets.UTF_8);
    try (Arena m = Arena.ofConfined()) {
      MemorySegment kind = m.allocate(JAVA_INT), n = m.allocate(JAVA_LONG);
      MemorySegment o = Native.out(m, b.length);
      Native.rc(
          (int) DEARM.invoke(Native.in(m, b), (long) b.length, kind, o, (long) b.length, n));
      return new Armored(kind.get(JAVA_INT, 0), Native.bytes(o, n.get(JAVA_LONG, 0)));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }
}
