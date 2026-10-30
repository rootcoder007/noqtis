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
     * @return true only when the library passed the capsule as a whole
     */
    public boolean ok() {
      return code == 0 && rows.stream().allMatch(Row::ok);
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
}
