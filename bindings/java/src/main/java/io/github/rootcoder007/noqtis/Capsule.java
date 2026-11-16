// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
package io.github.rootcoder007.noqtis;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Capsules: a folder sealed with a manifest of every file in it
 * ({@code noqtis.json}) and a post-quantum signature over it ({@code
 * noqtis.sig}), the same files the {@code noqtis} command writes and
 * checks.
 */
public final class Capsule {
  private Capsule() {}

  /**
   * One check of a capsule.
   *
   * @param check "manifest.digest", "file", "key", "info.alg", ...
   * @param ok whether it passed
   * @param detail what was found
   */
  public record Row(String check, boolean ok, String detail) {}

  /**
   * What a check (or {@link #inspect}) found.
   *
   * @param code the library's return code: 0, or a negative {@code NQE*}
   *     code such as -3 when a check failed
   * @param rows every check, in order
   */
  public record Report(int code, List<Row> rows) {
    /**
     * @return true when every check made passed; with {@link #partial()}
     *     true those checks left files out (only, a proof) and this says
     *     nothing of the others: the capsule passed as a whole only when
     *     {@code ok() && !partial()}
     */
    public boolean ok() {
      return code == 0 && rows.stream().allMatch(Row::ok);
    }

    /**
     * @return true when only some files were checked (a "partial" row says
     *     which were left out)
     */
    public boolean partial() {
      return rows.stream().anyMatch(r -> r.check().equals("partial"));
    }

    /**
     * @return the rows that did not pass
     */
    public List<Row> failed() {
      return rows.stream().filter(r -> !r.ok()).toList();
    }

    /**
     * @param check a row name ("info.alg", "key", ...)
     * @return the first row of that name
     */
    public Optional<Row> get(String check) {
      return rows.stream().filter(r -> r.check().equals(check)).findFirst();
    }

    @Override
    public String toString() {
      StringBuilder b = new StringBuilder();
      for (Row r : rows) {
        b.append(String.format("%-4s %s: %s%n", r.ok() ? "ok" : "FAIL", r.check(), r.detail()));
      }
      return b.toString();
    }
  }

  /**
   * What {@link #check} and {@link #checkProof} check beyond the seal
   * itself; {@link #none()} is nothing, and each {@code with} method
   * returns a changed copy.
   *
   * @param trust the public key the seal must carry, or null to accept the
   *     key in the seal (the "key" row then says so)
   * @param anchors TSA trust anchors (DER certificates, at most 32): the
   *     seal must then carry an RFC 3161 timestamp that verifies under one
   * @param only a partial check of these paths ('/' separated)
   * @param lineage capsule folders to find a format 2 capsule's inputs in
   * @param stmts key statements (noqtis-keys-1), at most 32; they need a
   *     trusted key
   */
  public record Opts(
      byte[] trust, List<byte[]> anchors, List<String> only, List<Path> lineage,
      List<byte[]> stmts) {
    /**
     * @return no options
     */
    public static Opts none() {
      return new Opts(null, List.of(), List.of(), List.of(), List.of());
    }

    /**
     * @param pk the trusted public key
     * @return a copy with it
     */
    public Opts withTrust(byte[] pk) {
      return new Opts(pk, anchors, only, lineage, stmts);
    }

    /**
     * @param a the TSA trust anchors
     * @return a copy with them
     */
    public Opts withAnchors(List<byte[]> a) {
      return new Opts(trust, a, only, lineage, stmts);
    }

    /**
     * @param p the paths to check
     * @return a copy with them
     */
    public Opts withOnly(List<String> p) {
      return new Opts(trust, anchors, p, lineage, stmts);
    }

    /**
     * @param d the folders to find inputs in
     * @return a copy with them
     */
    public Opts withLineage(List<Path> d) {
      return new Opts(trust, anchors, only, d, stmts);
    }

    /**
     * @param s the key statements
     * @return a copy with them
     */
    public Opts withStmts(List<byte[]> s) {
      return new Opts(trust, anchors, only, lineage, s);
    }
  }

  /**
   * An input of a format 2 capsule.
   *
   * @param id the input capsule's id ({@link #capid})
   * @param name a short name for it, 1 to 255 bytes of UTF-8
   */
  public record Input(byte[] id, String name) {}

  private static MemorySegment cs(Arena m, String s) {
    if (s.indexOf('\0') >= 0) {
      throw new NoqtisException(-1, "a NUL character in \"" + s + "\"");
    }
    return m.allocateFrom(s);
  }

  private static MemorySegment dir(Arena m, Path d) {
    return cs(m, d.toString());
  }

  private static MemorySegment strs(Arena m, List<String> ss) {
    if (ss == null || ss.isEmpty()) {
      return MemorySegment.NULL;
    }
    MemorySegment a = m.allocate(ADDRESS, ss.size());
    for (int i = 0; i < ss.size(); i++) {
      a.setAtIndex(ADDRESS, i, cs(m, ss.get(i)));
    }
    return a;
  }

  // a C array of buffers at o and their lengths at o + 8, the count at o + 16
  private static void blobs(Arena m, MemorySegment x, long o, List<byte[]> bs) {
    if (bs == null || bs.isEmpty()) {
      return;
    }
    MemorySegment a = m.allocate(ADDRESS, bs.size()), l = m.allocate(JAVA_LONG, bs.size());
    for (int i = 0; i < bs.size(); i++) {
      byte[] b = bs.get(i);
      a.setAtIndex(ADDRESS, i, b.length > 0 ? m.allocateFrom(JAVA_BYTE, b) : Native.out(m, 1));
      l.setAtIndex(JAVA_LONG, i, b.length);
    }
    x.set(ADDRESS, o, a);
    x.set(ADDRESS, o + 8, l);
    x.set(JAVA_LONG, o + 16, bs.size());
  }

  // nqcopt: twelve 8-byte members
  private static MemorySegment copt(Arena m, Opts o) {
    MemorySegment x = m.allocate(96, 8);
    if (o == null) {
      return x;
    }
    if (o.trust() != null) {
      x.set(ADDRESS, 0, Native.in(m, o.trust()));
      x.set(JAVA_LONG, 8, o.trust().length);
    }
    blobs(m, x, 16, o.anchors());
    x.set(ADDRESS, 40, strs(m, o.only()));
    x.set(JAVA_LONG, 48, o.only() == null ? 0 : o.only().size());
    List<String> lin = new ArrayList<>();
    if (o.lineage() != null) {
      for (Path p : o.lineage()) {
        lin.add(p.toString());
      }
    }
    x.set(ADDRESS, 56, strs(m, lin));
    x.set(JAVA_LONG, 64, lin.size());
    blobs(m, x, 72, o.stmts());
    return x;
  }

  /** The report the library made at *rp (freed here), or its error. */
  private static Report report(int c, MemorySegment rp) throws Throwable {
    MemorySegment r = rp.get(ADDRESS, 0);
    if (r.equals(MemorySegment.NULL)) {
      throw new NoqtisException(c == 0 ? -10 : c);
    }
    List<Row> rows = new ArrayList<>();
    try (Arena m = Arena.ofConfined()) {
      long n = (long) Native.NQREPN.invoke(r);
      MemorySegment pc = m.allocate(ADDRESS), po = m.allocate(JAVA_INT), pd = m.allocate(ADDRESS);
      for (long i = 0; i < n; i++) {
        if ((int) Native.NQREPI.invoke(r, i, pc, po, pd) != 0) {
          break;
        }
        rows.add(
            new Row(
                Native.str(pc.get(ADDRESS, 0)),
                po.get(JAVA_INT, 0) != 0,
                Native.str(pd.get(ADDRESS, 0))));
      }
    } finally {
      Native.NQREPFREE.invoke(r);
    }
    return new Report(c, List.copyOf(rows));
  }

  /**
   * Writes noqtis.json and noqtis.sig into dir (format 1), covering every
   * regular file in it. The creation time is SOURCE_DATE_EPOCH when set,
   * else the clock.
   *
   * @param dir the folder
   * @param alg the signature algorithm
   * @param sk the secret key
   * @param pk its public key, written into the seal
   * @param meta JSON text (an object) kept in the manifest, or null
   */
  public static void seal(Path dir, String alg, byte[] sk, byte[] pk, String meta) {
    seal2(dir, alg, sk, pk, meta, null);
  }

  /**
   * {@link #seal} in format 2: the manifest also carries a Merkle tree
   * over its entries, so that {@link #prove} can show single files without
   * the rest, and the capsules it was made from.
   *
   * @param dir the folder
   * @param alg the signature algorithm
   * @param sk the secret key
   * @param pk its public key
   * @param meta JSON text (an object), or null
   * @param inputs the capsules it was made from (at most 1024), or an
   *     empty list; null seals in format 1
   */
  public static void seal2(
      Path dir, String alg, byte[] sk, byte[] pk, String meta, List<Input> inputs) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment d = dir(m, dir), mt = meta == null ? MemorySegment.NULL : cs(m, meta);
      MemorySegment ks = Native.in(m, sk), ps = Native.in(m, pk);
      int c;
      if (inputs == null) {
        c =
            (int)
                Native.NQSEAL.invoke(
                    d, a.id(), ks, (long) sk.length, ps, (long) pk.length, mt, MemorySegment.NULL);
      } else {
        MemorySegment in = MemorySegment.NULL;
        if (!inputs.isEmpty()) {
          in = m.allocate(40L * inputs.size(), 8);
          for (int i = 0; i < inputs.size(); i++) {
            Input x = inputs.get(i);
            if (x.id().length != 32) {
              throw new NoqtisException(-1, "an input id is 32 bytes");
            }
            MemorySegment.copy(x.id(), 0, in, JAVA_BYTE, 40L * i, 32);
            in.set(ADDRESS, 40L * i + 32, cs(m, x.name()));
          }
        }
        c =
            (int)
                Native.NQSEAL2.invoke(
                    d, a.id(), ks, (long) sk.length, ps, (long) pk.length, mt, in,
                    (long) inputs.size());
      }
      Native.rc(c);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The id of the capsule in dir: the SHA-256 of the bytes its seal
   * signs. Nothing else is checked: check the capsule first.
   *
   * @param dir the folder
   * @return 32 bytes
   */
  public static byte[] capid(Path dir) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment id = m.allocate(32);
      Native.rc((int) Native.NQCAPID.invoke(dir(m, dir), id));
      return Native.bytes(id, 32);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Checks dir against its seal, with the key in the seal accepted.
   *
   * @param dir the folder
   * @return the report
   */
  public static Report check(Path dir) {
    return check(dir, Opts.none());
  }

  /**
   * Checks dir against its seal, with the options of o. A failed check is
   * a report, not an exception.
   *
   * @param dir the folder
   * @param o the options
   * @return the report: {@link Report#ok()} is true only when all passed
   */
  public static Report check(Path dir, Opts o) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment rp = m.allocate(ADDRESS);
      int c = (int) Native.NQCHKX.invoke(dir(m, dir), copt(m, o), rp);
      return report(c, rp);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * What the capsule in dir says, with nothing checked: the report ends
   * with info.format, info.alg, info.key, info.created, info.files,
   * info.bytes, info.timestamp and, when there is one, info.meta.
   *
   * @param dir the folder
   * @return the report
   */
  public static Report inspect(Path dir) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment rp = m.allocate(ADDRESS);
      int c = (int) Native.NQINSP.invoke(dir(m, dir), rp);
      return report(c, rp);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * {@link #inspect}, with one "info.file" row per listed file first: its
   * size, SHA-256 and path, with a space between.
   *
   * @param dir the folder
   * @return the report
   */
  public static Report files(Path dir) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment rp = m.allocate(ADDRESS);
      int c = (int) Native.NQFILES.invoke(dir(m, dir), rp);
      return report(c, rp);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * A proof (noqtis-proof-1, JSON) that the files paths are in the format
   * 2 capsule in dir, which shows nothing of the other files. Check the
   * capsule first.
   *
   * @param dir the folder
   * @param paths the files to prove ('/' separated)
   * @return the proof
   */
  public static byte[] prove(Path dir, List<String> paths) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment d = dir(m, dir), ps = strs(m, paths), n = m.allocate(JAVA_LONG);
      long np = paths.size();
      int c = (int) Native.NQPROVE.invoke(d, ps, np, MemorySegment.NULL, 0L, n);
      if (c != -2) {
        Native.rc(c);
      }
      long cap = n.get(JAVA_LONG, 0);
      MemorySegment out = Native.out(m, cap);
      Native.rc((int) Native.NQPROVE.invoke(d, ps, np, out, cap, n));
      return Native.bytes(out, n.get(JAVA_LONG, 0));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Checks a proof from {@link #prove}: its seal (with o's trusted key and
   * TSA anchors; its other members are not used) and each entry's audit
   * path; with dir, each proven file there against its entry.
   *
   * @param proof the proof
   * @param o the options
   * @param dir the capsule folder, or null
   * @return the report
   */
  public static Report checkProof(byte[] proof, Opts o, Path dir) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment rp = m.allocate(ADDRESS);
      MemorySegment d = dir == null ? MemorySegment.NULL : dir(m, dir);
      int c =
          (int)
              Native.NQCHKP.invoke(
                  Native.in(m, proof), (long) proof.length, copt(m, o), d, rp);
      return report(c, rp);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Why {@link #seal} refused dir (an ARG error): the first thing in it a
   * capsule cannot hold.
   *
   * @param why "link", "odd" (not a file or folder), "name", "case" (a
   *     path equal to another but for ASCII case) or "key" (a noqtis secret
   *     key file)
   * @param path its path in the folder
   */
  public record Why(String why, String path) {}

  /**
   * Why {@link #seal} refused dir, or empty when nothing in it stops a
   * seal (the keys given were then not one pair).
   *
   * @param dir the folder
   * @return the reason
   */
  public static java.util.Optional<Why> sealWhy(Path dir) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment w = m.allocate(JAVA_INT), p = m.allocate(4200);
      Native.rc((int) Native.NQSEALWHY.invoke(dir(m, dir), w, p, 4200L));
      int k = w.get(JAVA_INT, 0);
      if (k == 0) {
        return java.util.Optional.empty();
      }
      String[] n = {"link", "odd", "name", "case", "key"};
      return java.util.Optional.of(
          new Why(k <= n.length ? n[k - 1] : Integer.toString(k), p.getString(0)));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  private static NoqtisException whyf(int c, MemorySegment w) {
    MemorySegment s = w.get(ADDRESS, 0);
    return new NoqtisException(c, s.equals(MemorySegment.NULL) ? null : Native.str(s));
  }

  /**
   * The RFC 3161 TimeStampReq for the seal in dir: send it to a TSA (the
   * library makes no network request) and give its reply to
   * {@link #tsput}.
   *
   * @param dir the sealed capsule
   * @param nonce at most 32 bytes, or null
   * @return the request
   */
  public static byte[] tsreq(Path dir, byte[] nonce) {
    byte[] nc = nonce == null ? new byte[0] : nonce;
    try (Arena m = Arena.ofConfined()) {
      MemorySegment q = m.allocate(256), n = m.allocate(JAVA_LONG);
      Native.rc(
          (int) Native.NQTSREQ.invoke(dir(m, dir), Native.in(m, nc), (long) nc.length, q, 256L, n));
      return Native.bytes(q, n.get(JAVA_LONG, 0));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  private static MemorySegment anc(Arena m, List<byte[]> a) {
    MemorySegment x = m.allocate(24, 8);
    blobs(m, x, 0, a);
    return x;
  }

  /**
   * Stores the TSA's reply as the seal's timestamp once it checks (with
   * anchors, DER certificates, its TSA must chain to one). VERIFY, with
   * what failed, when it does not check.
   *
   * @param dir the sealed capsule
   * @param reply the TSA's reply
   * @param nonce the request's nonce, or null
   * @param anchors TSA trust anchors, or null
   * @return the time it gives, in seconds since 1970
   */
  public static long tsput(Path dir, byte[] reply, byte[] nonce, List<byte[]> anchors) {
    byte[] nc = nonce == null ? new byte[0] : nonce;
    try (Arena m = Arena.ofConfined()) {
      MemorySegment a = anc(m, anchors), gt = m.allocate(JAVA_LONG), w = m.allocate(ADDRESS);
      int c =
          (int)
              Native.NQTSPUT.invoke(
                  dir(m, dir), Native.out(m, reply.length).copyFrom(MemorySegment.ofArray(reply)),
                  (long) reply.length, Native.in(m, nc), (long) nc.length, a.get(ADDRESS, 0),
                  a.get(ADDRESS, 8), a.get(JAVA_LONG, 16), gt, w);
      if (c != 0) {
        throw whyf(c, w);
      }
      return gt.get(JAVA_LONG, 0);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The TimeStampReq of the next archive timestamp of the capsule's
   * evidence record (RFC 4998).
   *
   * @param dir the sealed capsule
   * @param hash "SHA-256", "SHA-384" or "SHA-512" for a hash-tree renewal,
   *     null to keep the record's
   * @param nonce at most 32 bytes, or null
   * @return the request
   */
  public static byte[] ersreq(Path dir, String hash, byte[] nonce) {
    byte[] nc = nonce == null ? new byte[0] : nonce;
    int h = hash == null ? 0 : Noqtis.hid(hash);
    try (Arena m = Arena.ofConfined()) {
      MemorySegment q = m.allocate(256), n = m.allocate(JAVA_LONG), w = m.allocate(ADDRESS);
      int c =
          (int)
              Native.NQERSREQ.invoke(
                  dir(m, dir), h, Native.in(m, nc), (long) nc.length, q, 256L, n, w);
      if (c != 0) {
        throw whyf(c, w);
      }
      return Native.bytes(q, n.get(JAVA_LONG, 0));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * What {@link #ersput} did.
   *
   * @param time the new archive timestamp's time, in seconds since 1970
   * @param how "new", "timestamp" or "hash-tree": the kind of renewal
   */
  public record Renewal(long time, String how) {}

  /**
   * Adds the reply to {@link #ersreq} to the evidence record (noqtis.ers)
   * once it and the record check.
   *
   * @param dir the sealed capsule
   * @param hash as for {@link #ersreq}
   * @param reply the TSA's reply
   * @param nonce the request's nonce, or null
   * @param anchors TSA trust anchors, or null
   * @return what was done
   */
  public static Renewal ersput(
      Path dir, String hash, byte[] reply, byte[] nonce, List<byte[]> anchors) {
    byte[] nc = nonce == null ? new byte[0] : nonce;
    int h = hash == null ? 0 : Noqtis.hid(hash);
    try (Arena m = Arena.ofConfined()) {
      MemorySegment a = anc(m, anchors), gt = m.allocate(JAVA_LONG), how = m.allocate(JAVA_INT);
      MemorySegment w = m.allocate(ADDRESS);
      int c =
          (int)
              Native.NQERSPUT.invoke(
                  dir(m, dir), h,
                  Native.out(m, reply.length).copyFrom(MemorySegment.ofArray(reply)),
                  (long) reply.length, Native.in(m, nc), (long) nc.length, a.get(ADDRESS, 0),
                  a.get(ADDRESS, 8), a.get(JAVA_LONG, 16), gt, how, w);
      if (c != 0) {
        throw whyf(c, w);
      }
      String[] k = {"new", "timestamp", "hash-tree"};
      return new Renewal(gt.get(JAVA_LONG, 0), k[Math.min(how.get(JAVA_INT, 0), 2)]);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  private static byte[] kstmt(
      String alg, byte[] sk, byte[] pk, String nalg, byte[] nsk, byte[] npk, long at,
      String reason) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    Noqtis.Alg na = nalg == null ? a : Noqtis.find(nalg, "sign");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment r = reason == null ? MemorySegment.NULL : cs(m, reason);
      MemorySegment k = Native.in(m, sk), nk = nsk == null ? MemorySegment.NULL : Native.in(m, nsk);
      try {
        return Native.sized(
            m,
            65536,
            (o, cap, n) ->
                (int)
                    Native.NQKSTMT.invoke(
                        a.id(), k, (long) sk.length, Native.in(m, pk), (long) pk.length, na.id(),
                        nk, nsk == null ? 0L : (long) nsk.length,
                        npk == null ? MemorySegment.NULL : Native.in(m, npk),
                        npk == null ? 0L : (long) npk.length, at, r, o, cap, n));
      } finally {
        Native.wipe(k, sk.length);
        if (nsk != null) {
          Native.wipe(nk, nsk.length);
        }
      }
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * A key statement (noqtis-keys-1, JSON) that the key pair (sk, pk) of
   * alg is replaced by (nsk, npk) of nalg from at, signed by both keys;
   * give it to {@link #check} in {@link Opts#withStmts}.
   *
   * @param alg the old pair's algorithm
   * @param sk the old secret key
   * @param pk the old public key
   * @param nalg the new pair's algorithm
   * @param nsk the new secret key
   * @param npk the new public key
   * @param at when, in seconds since 1970
   * @param reason up to 255 bytes of text, or null
   * @return the statement
   */
  public static byte[] rotate(
      String alg, byte[] sk, byte[] pk, String nalg, byte[] nsk, byte[] npk, long at,
      String reason) {
    return kstmt(alg, sk, pk, nalg, nsk, npk, at, reason);
  }

  /**
   * A key statement that the key pair (sk, pk) is revoked from at, signed
   * by it.
   *
   * @param alg the pair's algorithm
   * @param sk the secret key
   * @param pk the public key
   * @param at when, in seconds since 1970
   * @param reason up to 255 bytes of text, or null
   * @return the statement
   */
  public static byte[] revoke(String alg, byte[] sk, byte[] pk, long at, String reason) {
    return kstmt(alg, sk, pk, null, null, null, at, reason);
  }
}
