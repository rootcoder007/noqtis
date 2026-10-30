// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
package io.github.rootcoder007.noqtis;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemoryLayout.PathElement;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.time.Instant;
import java.util.HexFormat;

/**
 * Identity cards (noqtis-idcard-1): a signing key with its holder's name
 * and, when given, ORCID iD, e-mail address, web page and affiliation,
 * signed by the key itself under the card's own context, so that a card
 * is never taken for a seal or a key statement.
 *
 * <p>A card is self-signed: it shows that whoever holds the key wrote it
 * and that it is unchanged, not that the name is true. Compare {@link
 * Card#keySha256()} with the one its holder published, or pin the key.
 *
 * <pre>{@code
 * byte[] card = IdCard.make("ML-DSA-65", k.sk(), k.pk(),
 *     IdCard.Fields.of("Ada Lovelace").withOrcid("0000-0002-1825-0097"), null);
 * IdCard.Card c = IdCard.verify(card, k.pk()); // null unless it verifies
 * }</pre>
 */
public final class IdCard {
  private IdCard() {}

  /**
   * What a card says: the name, and the other fields when not null. The
   * library checks each: name and affil 1 to 255 bytes of text, no
   * control character, no space at either end; orcid an ORCID iD (or its
   * https://orcid.org/ address) whose check digit is right; email
   * local@domain.tld in at most 254 bytes; url an https:// address in at
   * most 1024 bytes.
   *
   * @param name your name, as you want it shown
   * @param orcid your ORCID iD, or null
   * @param email your e-mail address, or null
   * @param url your web page, or null
   * @param affil your affiliation, or null
   */
  public record Fields(String name, String orcid, String email, String url, String affil) {
    /**
     * The name alone.
     *
     * @param name your name
     * @return the fields
     */
    public static Fields of(String name) {
      return new Fields(name, null, null, null, null);
    }

    /**
     * These fields with an ORCID iD.
     *
     * @param v the iD
     * @return the fields
     */
    public Fields withOrcid(String v) {
      return new Fields(name, v, email, url, affil);
    }

    /**
     * These fields with an e-mail address.
     *
     * @param v the address
     * @return the fields
     */
    public Fields withEmail(String v) {
      return new Fields(name, orcid, v, url, affil);
    }

    /**
     * These fields with a web page.
     *
     * @param v the https:// address
     * @return the fields
     */
    public Fields withUrl(String v) {
      return new Fields(name, orcid, email, v, affil);
    }

    /**
     * These fields with an affiliation.
     *
     * @param v the affiliation
     * @return the fields
     */
    public Fields withAffil(String v) {
      return new Fields(name, orcid, email, url, v);
    }
  }

  /**
   * A card that verified.
   *
   * @param name the name
   * @param orcid the bare ORCID iD, or null
   * @param email the e-mail address, or null
   * @param url the web page, or null
   * @param affil the affiliation, or null
   * @param created when it was made, YYYY-MM-DDTHH:MM:SSZ
   * @param alg the key's algorithm
   * @param pk the public key
   * @param keySha256 the SHA-256 of the public key in hex, as {@code
   *     noqtis inspect} shows a seal's key
   */
  public record Card(
      String name,
      String orcid,
      String email,
      String url,
      String affil,
      String created,
      String alg,
      byte[] pk,
      String keySha256) {}

  private static MemoryLayout chars(long n, String name) {
    return MemoryLayout.sequenceLayout(n, JAVA_BYTE).withName(name);
  }

  // nqcardf of noqtis.h (64-bit platforms, as Native requires)
  static final StructLayout CARDF =
      MemoryLayout.structLayout(
          JAVA_INT.withName("alg"),
          chars(2624, "pk"),
          MemoryLayout.paddingLayout(4),
          JAVA_LONG.withName("pklen"),
          chars(32, "fp"),
          JAVA_LONG.withName("created"),
          chars(21, "utc"),
          chars(256, "name"),
          chars(20, "orcid"),
          chars(255, "email"),
          chars(1025, "url"),
          chars(256, "affil"),
          MemoryLayout.paddingLayout(7));

  private static long off(String f) {
    return CARDF.byteOffset(PathElement.groupElement(f));
  }

  private static MemorySegment cs(Arena m, String s, String what) {
    if (s == null) {
      return MemorySegment.NULL;
    }
    if (s.indexOf('\0') >= 0) {
      throw new NoqtisException(-1, what + ": a NUL character");
    }
    return m.allocateFrom(s);
  }

  /**
   * An identity card (JSON) for the key pair (sk, pk) of alg, made at
   * created (null for now) and signed by it. A field out of its limits,
   * or keys that are not one pair, throw ARG; Ed25519 alone UNSUPPORTED.
   *
   * @param alg the signature algorithm
   * @param sk the secret key
   * @param pk its public key
   * @param f the fields
   * @param created when it is made, or null for now
   * @return the card
   */
  public static byte[] make(String alg, byte[] sk, byte[] pk, Fields f, Instant created) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    if (f == null || f.name() == null) {
      throw new NoqtisException(-1, "a card needs a name");
    }
    long at = (created == null ? Instant.now() : created).getEpochSecond();
    try (Arena m = Arena.ofConfined()) {
      MemorySegment ks = Native.in(m, sk), ps = Native.in(m, pk), n = m.allocate(JAVA_LONG);
      MemorySegment nm = cs(m, f.name(), "name"), oi = cs(m, f.orcid(), "orcid");
      MemorySegment em = cs(m, f.email(), "email"), ur = cs(m, f.url(), "url");
      MemorySegment af = cs(m, f.affil(), "affil");
      long kl = sk == null ? 0 : sk.length, pl = pk == null ? 0 : pk.length;
      int c =
          (int)
              Native.NQCARD.invoke(
                  a.id(), ks, kl, ps, pl, nm, oi, em, ur, af, at, MemorySegment.NULL, 0L, n);
      if (c != -2) {
        Native.rc(c);
      }
      long cap = n.get(JAVA_LONG, 0);
      MemorySegment out = Native.out(m, cap);
      Native.rc(
          (int) Native.NQCARD.invoke(a.id(), ks, kl, ps, pl, nm, oi, em, ur, af, at, out, cap, n));
      return Native.bytes(out, n.get(JAVA_LONG, 0));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  private static String opt(MemorySegment f, String name) {
    String s = f.getString(off(name));
    return s.isEmpty() ? null : s;
  }

  /**
   * Checks a card (at most 256 KiB): the card when it verifies and, with
   * pk not null, is for that public key; null when its signature does not
   * verify or it is for another key, as {@link Sign#verify} returns false.
   * Input that is not a card throws DECODE.
   *
   * @param card the card's bytes
   * @param pk the public key it must be for, or null
   * @return the card, or null
   */
  public static Card verify(byte[] card, byte[] pk) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment cb = Native.in(m, card), ps = pk == null ? MemorySegment.NULL : Native.in(m, pk);
      MemorySegment f = m.allocate(CARDF);
      long n = card == null ? 0 : card.length;
      int c = (int) Native.NQCARDVRFY.invoke(cb, n, ps, pk == null ? 0L : (long) pk.length, f);
      if (c == -3) {
        return null;
      }
      Native.rc(c);
      long pl = f.get(JAVA_LONG, off("pklen"));
      byte[] fp = f.asSlice(off("fp"), 32).toArray(JAVA_BYTE);
      String alg = Native.str((MemorySegment) Native.NQSNAME.invoke(f.get(JAVA_INT, off("alg"))));
      return new Card(
          f.getString(off("name")),
          opt(f, "orcid"),
          opt(f, "email"),
          opt(f, "url"),
          opt(f, "affil"),
          f.getString(off("utc")),
          alg,
          f.asSlice(off("pk"), pl).toArray(JAVA_BYTE),
          HexFormat.of().formatHex(fp));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }
}
