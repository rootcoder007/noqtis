// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
package io.github.rootcoder007.noqtis;

import static io.github.rootcoder007.noqtis.Native.I;
import static io.github.rootcoder007.noqtis.Native.P;
import static io.github.rootcoder007.noqtis.Native.Z;
import static java.lang.foreign.ValueLayout.ADDRESS;
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
 * Text armor, X.509 certificates for noqtis keys, and signed and
 * encrypted messages with them: the Cryptographic Message Syntax (RFC
 * 5652) and S/MIME (RFC 8551).
 *
 * <pre>{@code
 * Sign.KeyPair k = Sign.keygen("ML-DSA-65");
 * byte[] cert = Mail.selfCert("ML-DSA-65", k.sk(), k.pk(), "Ada Example", null, from, to);
 * byte[] s = Mail.cmsSign("ML-DSA-65", k.sk(), cert, msg, false, null);
 * Mail.Signed v = Mail.cmsVerify(s, null, List.of(cert), null); // throws VERIFY
 * }</pre>
 */
public final class Mail {
  private Mail() {}

  private static final MethodHandle ARMLEN = Native.fn("nqarmlen", I, P, Z, P);
  private static final MethodHandle ARMENC = Native.fn("nqarmenc", I, P, P, Z, P, Z, P);
  private static final MethodHandle ARMDEC = Native.fn("nqarmdec", I, P, Z, P, Z, P, Z, P);
  private static final MethodHandle X5SELF =
      Native.fn("nqx5self", I, I, P, Z, P, Z, P, P, Z, Z, P, Z, P);
  private static final MethodHandle X5KEM =
      Native.fn("nqx5kem", I, I, P, Z, P, Z, I, P, Z, Z, Z, P, Z, P);
  private static final MethodHandle X5INFO = Native.fn("nqx5info", I, P, Z, P);
  private static final MethodHandle CMSSIGN =
      Native.fn("nqcmssign", I, I, P, Z, P, Z, P, Z, I, Z, P, Z, P);
  private static final MethodHandle CMSVRFY =
      Native.fn("nqcmsvrfy", I, P, Z, P, Z, P, P, Z, Z, P, Z, P, P);
  private static final MethodHandle CMSENC = Native.fn("nqcmsenc", I, P, P, Z, P, Z, P, Z, P);
  private static final MethodHandle CMSDEC =
      Native.fn("nqcmsdec", I, I, P, Z, P, Z, P, Z, P, Z, P);
  private static final MethodHandle SMSIGN =
      Native.fn("nqsmsign", I, I, P, Z, P, Z, P, Z, I, Z, P, Z, P);
  private static final MethodHandle SMVRFY =
      Native.fn("nqsmvrfy", I, P, Z, P, P, Z, Z, P, Z, P, P);
  private static final MethodHandle SMENC = Native.fn("nqsmenc", I, P, P, Z, P, Z, P, Z, P);
  private static final MethodHandle SMDEC =
      Native.fn("nqsmdec", I, I, P, Z, P, Z, P, Z, P, Z, P);

  // nqx5f of noqtis.h (64-bit platforms, as Native requires): the offsets
  private static final long X5SIZE = 592;
  private static final long X5ALG = 4, X5FP = 8, X5NB = 40, X5NA = 48, X5CA = 56;
  private static final long X5NAME = 60, X5EMAIL = 316, X5PKOFF = 576, X5PKLEN = 584;

  /**
   * What an X.509 certificate says of its key and holder.
   *
   * @param alg the key's algorithm, "" for a kind noqtis does not have
   * @param kem whether it is an ML-KEM key
   * @param fingerprint SHA-256 of the certificate, in hex
   * @param notBefore valid from
   * @param notAfter valid to
   * @param ca whether it may issue certificates
   * @param name the subject's common name, "" when it has none
   * @param email its first e-mail address, "" when it has none
   * @param pk the public key; empty when read as a signer alone
   */
  public record Cert(
      String alg,
      boolean kem,
      String fingerprint,
      Instant notBefore,
      Instant notAfter,
      boolean ca,
      String name,
      String email,
      byte[] pk) {}

  /**
   * A signature that verified.
   *
   * @param content what was signed
   * @param signer the signer's certificate, as {@link #readCert} gives
   */
  public record Signed(byte[] content, Cert signer) {}

  static MemorySegment cs(Arena m, String s, String what) {
    if (s == null) {
      return MemorySegment.NULL;
    }
    if (s.indexOf('\0') >= 0) {
      throw new NoqtisException(-1, what + ": a NUL character");
    }
    return m.allocateFrom(s);
  }

  static long len(byte[] b) {
    return b == null ? 0 : b.length;
  }

  static long at(Instant t) {
    return (t == null ? Instant.now() : t).getEpochSecond();
  }

  /** The certificates as arrays of pointers and lengths in m. */
  static MemorySegment[] lists(Arena m, List<byte[]> bs) {
    int n = bs == null ? 0 : bs.size();
    MemorySegment p = m.allocate(ADDRESS, Math.max(n, 1));
    MemorySegment l = m.allocate(JAVA_LONG, Math.max(n, 1));
    for (int i = 0; i < n; i++) {
      p.setAtIndex(ADDRESS, i, Native.in(m, bs.get(i)));
      l.setAtIndex(JAVA_LONG, i, len(bs.get(i)));
    }
    return new MemorySegment[] {p, l};
  }

  static long sum(List<byte[]> bs) {
    long s = 0;
    if (bs != null) {
      for (byte[] b : bs) {
        s += len(b);
      }
    }
    return s;
  }

  private static Cert cert(MemorySegment f, byte[] der) throws Throwable {
    boolean kem = f.get(JAVA_INT, 0) != 0;
    int alg = f.get(JAVA_INT, X5ALG);
    String an = "";
    if (alg != 0) {
      an = Native.str((MemorySegment) (kem ? Native.NQKNAME : Native.NQSNAME).invoke(alg));
    }
    long off = f.get(JAVA_LONG, X5PKOFF), pl = f.get(JAVA_LONG, X5PKLEN);
    byte[] pk = new byte[0];
    if (der != null && off + pl <= der.length) {
      pk = java.util.Arrays.copyOfRange(der, (int) off, (int) (off + pl));
    }
    return new Cert(
        an,
        kem,
        HexFormat.of().formatHex(f.asSlice(X5FP, 32).toArray(JAVA_BYTE)),
        Instant.ofEpochSecond(f.get(JAVA_LONG, X5NB)),
        Instant.ofEpochSecond(f.get(JAVA_LONG, X5NA)),
        f.get(JAVA_INT, X5CA) != 0,
        f.getString(X5NAME),
        f.getString(X5EMAIL),
        pk);
  }

  /**
   * Writes data as text (RFC 7468): a {@code -----BEGIN label-----} line,
   * base64 in lines of 64, and the END line.
   *
   * @param label capitals and digits with single spaces between them
   * @param data the bytes
   * @return the armor
   */
  public static String armor(String label, byte[] data) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment l = cs(m, label == null ? "" : label, "label"), d = Native.in(m, data);
      MemorySegment n = m.allocate(JAVA_LONG);
      Native.rc((int) ARMLEN.invoke(l, len(data), n));
      long cap = n.get(JAVA_LONG, 0);
      MemorySegment o = Native.out(m, cap);
      Native.rc((int) ARMENC.invoke(l, d, len(data), o, cap, n));
      return new String(Native.bytes(o, n.get(JAVA_LONG, 0)), StandardCharsets.US_ASCII);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * One armor read back.
   *
   * @param label its label
   * @param data its bytes
   */
  public record Armored(String label, byte[] data) {}

  /**
   * Reads one armor back. Text that is not exactly one well-formed armor
   * throws DECODE.
   *
   * @param text the armor
   * @return its label and bytes
   */
  public static Armored dearmor(String text) {
    byte[] t = text.getBytes(StandardCharsets.UTF_8);
    try (Arena m = Arena.ofConfined()) {
      MemorySegment lab = m.allocate(64), n = m.allocate(JAVA_LONG);
      MemorySegment o = Native.out(m, t.length);
      Native.rc(
          (int) ARMDEC.invoke(Native.in(m, t), (long) t.length, lab, 64L, o, (long) t.length, n));
      return new Armored(lab.getString(0), Native.bytes(o, n.get(JAVA_LONG, 0)));
    } catch (Throwable t2) {
      throw Native.wrap(t2);
    }
  }

  /**
   * A self-signed X.509 certificate (DER) for the signature key pair (sk,
   * pk) of alg, an ML-DSA, SLH-DSA or Ed25519 key. It is a CA of path
   * length 0, so that it can issue a {@link #kemCert}.
   *
   * @param alg the signature algorithm
   * @param sk the secret key
   * @param pk the public key
   * @param name the holder's name
   * @param email the holder's address, or null
   * @param notBefore valid from
   * @param notAfter valid to
   * @return the certificate
   */
  public static byte[] selfCert(
      String alg,
      byte[] sk,
      byte[] pk,
      String name,
      String email,
      Instant notBefore,
      Instant notAfter) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment ks = Native.in(m, sk), ps = Native.in(m, pk);
      MemorySegment nm = cs(m, name == null ? "" : name, "name"), em = cs(m, email, "email");
      return Native.sized(
          m,
          len(pk) + a.sig() + 2048,
          (o, cap, n) ->
              (int)
                  X5SELF.invoke(
                      a.id(),
                      ks,
                      len(sk),
                      ps,
                      len(pk),
                      nm,
                      em,
                      notBefore.getEpochSecond(),
                      notAfter.getEpochSecond(),
                      o,
                      cap,
                      n));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * A certificate (DER) for the ML-KEM public key pk of alg, issued by
   * the signature key issuerSk under the name of its own certificate:
   * what others encrypt to.
   *
   * @param issuerAlg the issuer's signature algorithm
   * @param issuerSk the issuer's secret key
   * @param issuerCert the issuer's certificate, from {@link #selfCert}
   * @param alg the ML-KEM algorithm
   * @param pk the ML-KEM public key
   * @param notBefore valid from
   * @param notAfter valid to
   * @return the certificate
   */
  public static byte[] kemCert(
      String issuerAlg,
      byte[] issuerSk,
      byte[] issuerCert,
      String alg,
      byte[] pk,
      Instant notBefore,
      Instant notAfter) {
    Noqtis.Alg ia = Noqtis.find(issuerAlg, "sign"), a = Noqtis.find(alg, "kem");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment ks = Native.in(m, issuerSk), ic = Native.in(m, issuerCert);
      MemorySegment ps = Native.in(m, pk);
      return Native.sized(
          m,
          len(pk) + len(issuerCert) + ia.sig() + 2048,
          (o, cap, n) ->
              (int)
                  X5KEM.invoke(
                      ia.id(),
                      ks,
                      len(issuerSk),
                      ic,
                      len(issuerCert),
                      a.id(),
                      ps,
                      len(pk),
                      notBefore.getEpochSecond(),
                      notAfter.getEpochSecond(),
                      o,
                      cap,
                      n));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Reads a certificate (DER): its key, holder and dates. It checks no
   * signature; {@link #cmsVerify} and {@link #smimeVerify} do, against
   * anchors.
   *
   * @param cert the certificate
   * @return what it says
   */
  public static Cert readCert(byte[] cert) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment f = m.allocate(X5SIZE);
      Native.rc((int) X5INFO.invoke(Native.in(m, cert), len(cert), f));
      return cert(f, cert);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * A CMS SignedData (RFC 5652, DER) of msg, signed with the key sk of
   * alg whose certificate is cert.
   *
   * @param alg the signature algorithm
   * @param sk the secret key
   * @param cert its certificate
   * @param msg the content
   * @param detached true to leave the content out
   * @param at the signing time, or null for now
   * @return the SignedData
   */
  public static byte[] cmsSign(
      String alg, byte[] sk, byte[] cert, byte[] msg, boolean detached, Instant at) {
    return sign(CMSSIGN, alg, sk, cert, msg, detached, at);
  }

  private static byte[] sign(
      MethodHandle h, String alg, byte[] sk, byte[] cert, byte[] msg, boolean det, Instant at) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment ks = Native.in(m, sk), cc = Native.in(m, cert), mm = Native.in(m, msg);
      long when = at(at);
      return Native.sized(
          m,
          3 * len(msg) + 2 * (len(cert) + a.sig()) + 8192,
          (o, cap, n) ->
              (int)
                  h.invoke(
                      a.id(), ks, len(sk), cc, len(cert), mm, len(msg), det ? 1 : 0, when, o, cap,
                      n));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Checks a SignedData against the anchors, certificates (DER) the
   * caller trusts: the signer's certificate must be one of them. Throws
   * VERIFY when the signature does not verify or the signer is not an
   * anchor.
   *
   * @param cms the SignedData
   * @param msg the content of a detached signature, or null
   * @param anchors the trusted certificates
   * @param at when to judge the certificates' dates, or null for now
   * @return the content and the signer
   */
  public static Signed cmsVerify(byte[] cms, byte[] msg, List<byte[]> anchors, Instant at) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment[] al = lists(m, anchors);
      MemorySegment f = m.allocate(X5SIZE), n = m.allocate(JAVA_LONG);
      long cap = len(cms) + len(msg) + 1;
      MemorySegment o = Native.out(m, cap);
      Native.rc(
          (int)
              CMSVRFY.invoke(
                  Native.in(m, cms),
                  len(cms),
                  Native.in(m, msg),
                  len(msg),
                  al[0],
                  al[1],
                  (long) (anchors == null ? 0 : anchors.size()),
                  at(at),
                  o,
                  cap,
                  n,
                  f));
      return new Signed(Native.bytes(o, n.get(JAVA_LONG, 0)), cert(f, null));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * A CMS AuthEnvelopedData (RFC 5083, AES-256-GCM, DER) of msg to the
   * ML-KEM certificates certs (RFC 9629, RFC 9936): the secret key of any
   * one of them opens it.
   *
   * @param certs the recipients' certificates
   * @param msg the content
   * @return the AuthEnvelopedData
   */
  public static byte[] cmsEncrypt(List<byte[]> certs, byte[] msg) {
    return enc(CMSENC, certs, msg);
  }

  private static byte[] enc(MethodHandle h, List<byte[]> certs, byte[] msg) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment[] cl = lists(m, certs);
      MemorySegment mm = Native.in(m, msg);
      long nc = certs == null ? 0 : certs.size();
      return Native.sized(
          m,
          3 * len(msg) + 2 * sum(certs) + 4096 * nc + 8192,
          (o, cap, n) -> (int) h.invoke(cl[0], cl[1], nc, mm, len(msg), o, cap, n));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Opens an AuthEnvelopedData with the ML-KEM secret key sk of alg.
   * Throws VERIFY when it is not for this key or was changed.
   *
   * @param alg the ML-KEM algorithm
   * @param sk the secret key
   * @param cert the key's certificate, naming the recipient to use, or null
   * @param cms the AuthEnvelopedData
   * @return the content
   */
  public static byte[] cmsDecrypt(String alg, byte[] sk, byte[] cert, byte[] cms) {
    return dec(CMSDEC, alg, sk, cert, cms);
  }

  private static byte[] dec(MethodHandle h, String alg, byte[] sk, byte[] cert, byte[] in) {
    Noqtis.Alg a = Noqtis.find(alg, "kem");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment ks = Native.in(m, sk), cc = Native.in(m, cert), mm = Native.in(m, in);
      return Native.sized(
          m,
          len(in) + 1,
          (o, cap, n) ->
              (int) h.invoke(a.id(), ks, len(sk), cc, len(cert), mm, len(in), o, cap, n));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  private static String text(byte[] b) {
    return new String(b, StandardCharsets.UTF_8);
  }

  private static byte[] utf8(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  /**
   * An S/MIME message (RFC 8551) of the MIME entity (header lines, an
   * empty line, the body), signed as {@link #cmsSign} signs:
   * application/pkcs7-mime, or with detached multipart/signed, which
   * keeps the entity readable.
   *
   * @param alg the signature algorithm
   * @param sk the secret key
   * @param cert its certificate
   * @param entity the MIME entity
   * @param detached true for multipart/signed
   * @param at the signing time, or null for now
   * @return the message
   */
  public static String smimeSign(
      String alg, byte[] sk, byte[] cert, String entity, boolean detached, Instant at) {
    return text(sign(SMSIGN, alg, sk, cert, utf8(entity), detached, at));
  }

  /**
   * A signed S/MIME message that verified.
   *
   * @param entity the MIME entity that was signed
   * @param signer the signer's certificate
   */
  public record SignedMail(String entity, Cert signer) {}

  /**
   * Checks a signed S/MIME message against the anchors, as {@link
   * #cmsVerify} does. Throws VERIFY when it does not verify.
   *
   * @param mime the message
   * @param anchors the trusted certificates
   * @param at when to judge the certificates' dates, or null for now
   * @return the entity and the signer
   */
  public static SignedMail smimeVerify(String mime, List<byte[]> anchors, Instant at) {
    byte[] b = utf8(mime);
    try (Arena m = Arena.ofConfined()) {
      MemorySegment[] al = lists(m, anchors);
      MemorySegment f = m.allocate(X5SIZE), n = m.allocate(JAVA_LONG);
      long cap = b.length + 1L;
      MemorySegment o = Native.out(m, cap);
      Native.rc(
          (int)
              SMVRFY.invoke(
                  Native.in(m, b),
                  (long) b.length,
                  al[0],
                  al[1],
                  (long) (anchors == null ? 0 : anchors.size()),
                  at(at),
                  o,
                  cap,
                  n,
                  f));
      return new SignedMail(text(Native.bytes(o, n.get(JAVA_LONG, 0))), cert(f, null));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * An encrypted S/MIME message (authEnveloped-data) of the MIME entity
   * to the ML-KEM certificates certs.
   *
   * @param certs the recipients' certificates
   * @param entity the MIME entity
   * @return the message
   */
  public static String smimeEncrypt(List<byte[]> certs, String entity) {
    return text(enc(SMENC, certs, utf8(entity)));
  }

  /**
   * Opens an encrypted S/MIME message, as {@link #cmsDecrypt} does.
   *
   * @param alg the ML-KEM algorithm
   * @param sk the secret key
   * @param cert the key's certificate, or null
   * @param mime the message
   * @return the MIME entity inside
   */
  public static String smimeDecrypt(String alg, byte[] sk, byte[] cert, String mime) {
    return text(dec(SMDEC, alg, sk, cert, utf8(mime)));
  }
}
