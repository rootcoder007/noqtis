// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
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
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * A store of other people's public keys in a folder: keys under names
 * and addresses, certifications of them, and how far each owner is
 * trusted. A key is valid when a fully trusted valid key certified it, or
 * three marginally trusted ones; the owner's own keys are trusted
 * ultimately. The folder is plain files that nothing signs: keep it where
 * only you can write.
 *
 * <pre>{@code
 * KeyStore ks = new KeyStore(Path.of("keys"));
 * byte[] bob = ks.add("ML-KEM-768", pk, "Bob", "bob@example.org", null);
 * ks.trust(mine, KeyStore.TRUST_ULTIMATE);
 * ks.certify("ML-DSA-65", sk, mypk, bob, null);
 * }</pre>
 */
public final class KeyStore {
  /** Trust: not said. */
  public static final int TRUST_UNKNOWN = 0;

  /** Never trusted to certify. */
  public static final int TRUST_NEVER = 1;

  /** Trusted marginally. */
  public static final int TRUST_MARGINAL = 2;

  /** Trusted fully. */
  public static final int TRUST_FULL = 3;

  /** The owner's own key. */
  public static final int TRUST_ULTIMATE = 4;

  /** Validity: not known to belong to its name. */
  public static final int VALID_NONE = 0;

  /** Marginally valid. */
  public static final int VALID_MARGINAL = 1;

  /** Fully valid. */
  public static final int VALID_FULL = 2;

  private static final MethodHandle ADD =
      Native.fn("nqksadd", I, P, I, I, P, Z, P, P, P, Z, P);
  private static final MethodHandle LIST = Native.fn("nqkslist", I, P, P, P, Z, P);
  private static final MethodHandle GET = Native.fn("nqksget", I, P, P, P, P, P, Z, P);
  private static final MethodHandle CERT =
      Native.fn("nqkscert", I, P, I, P, Z, P, Z, P, Z, P, Z, P);
  private static final MethodHandle CPUT = Native.fn("nqkscput", I, P, P, Z);
  private static final MethodHandle TRUST = Native.fn("nqkstrust", I, P, P, I);
  private static final MethodHandle DEL = Native.fn("nqksdel", I, P, P);
  private static final MethodHandle EXP = Native.fn("nqksexp", I, P, P, P, Z, P);
  private static final MethodHandle IMP = Native.fn("nqksimp", I, P, P, Z, P, P, P);
  private static final MethodHandle URL = Native.fn("nqksurl", I, P, P, Z);

  // nqkse of noqtis.h (64-bit platforms): its size and offsets
  private static final long KSE = 584;
  private static final long EALG = 4, EFP = 8, ENAME = 48, EEMAIL = 304;
  private static final long ECARD = 560, ETRUST = 564, EVALID = 568, ENCERT = 576;

  private final String dir;

  /**
   * One public key of a store.
   *
   * @param alg its algorithm
   * @param kem whether it is a KEM key
   * @param fingerprint SHA-256 of the public key, 32 bytes
   * @param name the name it is kept under
   * @param email its address, "" when it has none
   * @param card whether the store holds its identity card
   * @param trust one of the TRUST_ values
   * @param valid one of the VALID_ values
   * @param certs certifications of it under its present name
   */
  public record Key(
      String alg,
      boolean kem,
      byte[] fingerprint,
      String name,
      String email,
      boolean card,
      int trust,
      int valid,
      int certs) {}

  /**
   * A key given back.
   *
   * @param alg its algorithm
   * @param pk the public key
   */
  public record Got(String alg, byte[] pk) {}

  /**
   * What an import brought in.
   *
   * @param fingerprint of the first key
   * @param keys how many keys came in
   */
  public record Imported(byte[] fingerprint, int keys) {}

  /**
   * The store in the folder dir, which must exist.
   *
   * @param dir the folder
   */
  public KeyStore(Path dir) {
    this.dir = dir.toString();
  }

  private static MemorySegment fp(Arena m, byte[] fp) {
    if (fp == null || fp.length != 32) {
      throw new NoqtisException(-1, "a fingerprint is 32 bytes");
    }
    return Native.in(m, fp);
  }

  private static String name(boolean kem, int alg) throws Throwable {
    return Native.str((MemorySegment) (kem ? Native.NQKNAME : Native.NQSNAME).invoke(alg));
  }

  /**
   * Puts the public key pk of alg into the store.
   *
   * @param alg its algorithm, a signature or a KEM algorithm
   * @param pk the public key
   * @param name the name to keep it under; null with card
   * @param email its address, or null
   * @param card its identity card, which then says who the key is, or null
   * @return the key's fingerprint
   */
  public byte[] add(String alg, byte[] pk, String name, String email, byte[] card) {
    Noqtis.Alg a = Noqtis.alg(alg);
    try (Arena m = Arena.ofConfined()) {
      MemorySegment f = m.allocate(32);
      Native.rc(
          (int)
              ADD.invoke(
                  m.allocateFrom(dir),
                  a.kind().equals("kem") ? 1 : 0,
                  a.id(),
                  Native.in(m, pk),
                  Mail.len(pk),
                  Mail.cs(m, name, "name"),
                  Mail.cs(m, email, "email"),
                  Native.in(m, card),
                  Mail.len(card),
                  f));
      return f.toArray(JAVA_BYTE);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The keys whose name, address or fingerprint (in hex, from its start)
   * matches query; all of them with null.
   *
   * @param query what to look for, or null
   * @return the keys
   */
  public List<Key> list(String query) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment d = m.allocateFrom(dir), q = Mail.cs(m, query, "query");
      MemorySegment n = m.allocate(JAVA_LONG);
      int c = (int) LIST.invoke(d, q, MemorySegment.NULL, 0L, n);
      if (c != -2) {
        Native.rc(c);
      }
      long cap = n.get(JAVA_LONG, 0);
      List<Key> out = new ArrayList<>();
      if (cap == 0) {
        return out;
      }
      MemorySegment es = m.allocate(KSE * cap, 8);
      Native.rc((int) LIST.invoke(d, q, es, cap, n));
      long got = Math.min(cap, n.get(JAVA_LONG, 0));
      for (long i = 0; i < got; i++) {
        MemorySegment e = es.asSlice(i * KSE, KSE);
        boolean kem = e.get(JAVA_INT, 0) != 0;
        out.add(
            new Key(
                name(kem, e.get(JAVA_INT, EALG)),
                kem,
                e.asSlice(EFP, 32).toArray(JAVA_BYTE),
                e.getString(ENAME),
                e.getString(EEMAIL),
                e.get(JAVA_INT, ECARD) != 0,
                e.get(JAVA_INT, ETRUST),
                e.get(JAVA_INT, EVALID),
                (int) e.get(JAVA_LONG, ENCERT)));
      }
      return out;
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The algorithm and the public key of the key with the fingerprint.
   *
   * @param fingerprint the key
   * @return its algorithm and public key
   */
  public Got get(byte[] fingerprint) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment kem = m.allocate(JAVA_INT), alg = m.allocate(JAVA_INT);
      MemorySegment n = m.allocate(JAVA_LONG), o = m.allocate(65536);
      Native.rc(
          (int) GET.invoke(m.allocateFrom(dir), fp(m, fingerprint), kem, alg, o, 65536L, n));
      return new Got(
          name(kem.get(JAVA_INT, 0) != 0, alg.get(JAVA_INT, 0)),
          Native.bytes(o, n.get(JAVA_LONG, 0)));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Signs, with the signature key pair (sk, pk) of alg, that the key
   * belongs to the name and address the store has for it. The
   * certification is kept in the store and returned, to pass on.
   *
   * @param alg the signature algorithm
   * @param sk the certifier's secret key
   * @param pk the certifier's public key
   * @param fingerprint the key to certify
   * @param at when, or null for now
   * @return the certification (text)
   */
  public String certify(String alg, byte[] sk, byte[] pk, byte[] fingerprint, Instant at) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment d = m.allocateFrom(dir), ks = Native.in(m, sk), ps = Native.in(m, pk);
      MemorySegment f = fp(m, fingerprint);
      long when = Mail.at(at);
      byte[] b =
          Native.sized(
              m,
              2L * a.sig() + 4096,
              (o, cap, n) ->
                  (int)
                      CERT.invoke(
                          d, a.id(), ks, Mail.len(sk), ps, Mail.len(pk), f, when, o, cap, n));
      return new String(b, StandardCharsets.UTF_8);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Puts a certification someone else made into the store: both keys
   * must be in it, and its signature must verify.
   *
   * @param cert the certification
   */
  public void addCert(String cert) {
    byte[] b = cert.getBytes(StandardCharsets.UTF_8);
    try (Arena m = Arena.ofConfined()) {
      Native.rc((int) CPUT.invoke(m.allocateFrom(dir), Native.in(m, b), (long) b.length));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Sets how far the owner of the key is trusted to certify other keys.
   *
   * @param fingerprint the key
   * @param level one of the TRUST_ values
   */
  public void trust(byte[] fingerprint, int level) {
    try (Arena m = Arena.ofConfined()) {
      Native.rc((int) TRUST.invoke(m.allocateFrom(dir), fp(m, fingerprint), level));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Removes the key and what the store holds about it.
   *
   * @param fingerprint the key
   */
  public void delete(byte[] fingerprint) {
    try (Arena m = Arena.ofConfined()) {
      Native.rc((int) DEL.invoke(m.allocateFrom(dir), fp(m, fingerprint)));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * A bundle of a signature key that has an identity card: the card,
   * then every other key it certified under its own name and address,
   * each with that certification. It is what another store imports and
   * what is published at its {@link #url}.
   *
   * @param fingerprint the key
   * @return the bundle (text)
   */
  public String export(byte[] fingerprint) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment d = m.allocateFrom(dir), f = fp(m, fingerprint);
      byte[] b = Native.sized(m, 65536, (o, cap, n) -> (int) EXP.invoke(d, f, o, cap, n));
      return new String(b, StandardCharsets.UTF_8);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Puts the keys of a bundle into the store.
   *
   * @param bundle the bundle
   * @param email the address its keys must be for, or null
   * @return the fingerprint of the first key and how many came in
   */
  public Imported imports(String bundle, String email) {
    byte[] b = bundle.getBytes(StandardCharsets.UTF_8);
    try (Arena m = Arena.ofConfined()) {
      MemorySegment f = m.allocate(32), n = m.allocate(JAVA_LONG);
      Native.rc(
          (int)
              IMP.invoke(
                  m.allocateFrom(dir),
                  Native.in(m, b),
                  (long) b.length,
                  Mail.cs(m, email, "email"),
                  f,
                  n));
      return new Imported(f.toArray(JAVA_BYTE), (int) n.get(JAVA_LONG, 0));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Where the bundle of an address is looked for, over https at its own
   * domain: {@code https://<domain>/.well-known/noqtis/<hash of the local
   * part>}. Fetch it, and give what comes back to {@link #imports} with
   * the address.
   *
   * @param email the address
   * @return the URL
   */
  public static String url(String email) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment u = m.allocate(512);
      Native.rc((int) URL.invoke(Mail.cs(m, email == null ? "" : email, "email"), u, 512L));
      return u.getString(0);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }
}
