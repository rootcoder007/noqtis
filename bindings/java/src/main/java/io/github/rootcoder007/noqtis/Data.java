// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
package io.github.rootcoder007.noqtis;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_DOUBLE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * The data record of a capsule ({@code noqtis.data.json}, noqtis-data-1):
 * where each data file came from, the schema of its CSV files, summaries
 * that show drift later, and the steps and checks made with it. It is a
 * file of the capsule like any other: seal the folder after changing it,
 * and the seal covers it. Elements go in and come out as JSON text, and
 * the library writes the record in canonical form, the same bytes the
 * {@code noqtis} command and every other binding write.
 *
 * <p>The data layer is a library of its own beside libnoqtis ({@code
 * libnqd}, {@code nqd-0.dll}): the file named by the system property
 * {@code noqtis.nqd} or the environment variable {@code NOQTIS_NQD}; else
 * the one beside the noqtis library named by {@code noqtis.library} (or
 * in its {@code nqd/} folder, as CMake builds it); else {@code libnqd} on
 * the system's library path.
 */
@SuppressWarnings("restricted") // the FFM calls this class exists to make
public final class Data {
  private Data() {}

  /**
   * One row of a data check.
   *
   * @param check what was checked: "record", "source", "schema", "rule", "drift", "drift.warn",
   *     "file", ...
   * @param ok whether it passed
   * @param detail what was found
   * @param stats the row's numbers as canonical JSON, or null
   */
  public record Row(String check, boolean ok, String detail, String stats) {}

  /**
   * What a data check found.
   *
   * @param code the library's return code (0, or -3 when a row failed)
   * @param rows every row, in order
   */
  public record Report(int code, List<Row> rows) {
    /**
     * Whether the library passed it as a whole (and there was a row).
     *
     * @return true when every row passed
     */
    public boolean ok() {
      return code == 0 && !rows.isEmpty() && rows.stream().allMatch(Row::ok);
    }

    /**
     * For {@link #diff}: nothing differs.
     *
     * @return true when the two capsules are the same
     */
    public boolean same() {
      return code == 0;
    }

    /**
     * The level of a drift check.
     *
     * @return "ok", "warn" (a "drift.warn" row and none failed) or "fail"
     */
    public String level() {
      if (!ok()) {
        return "fail";
      }
      return rows.stream().anyMatch(r -> r.check().equals("drift.warn")) ? "warn" : "ok";
    }
  }

  /**
   * Where a source file came from, for {@link #add}; any member may be null.
   *
   * @param url where it was fetched from
   * @param title its title
   * @param publisher who published it
   * @param licence its licence
   * @param retrieved "now" (SOURCE_DATE_EPOCH when set, else the clock) or a UTC time
   *     YYYY-MM-DDTHH:MM:SSZ
   * @param synthetic it is a synthetic stand-in, not the real data
   */
  public record Src(
      String url,
      String title,
      String publisher,
      String licence,
      String retrieved,
      boolean synthetic) {
    /**
     * Nothing said of the file.
     *
     * @return a Src with every member empty
     */
    public static Src none() {
      return new Src(null, null, null, null, null, false);
    }
  }

  /**
   * How a CSV file is read.
   *
   * @param delim the delimiter, one ASCII character (not a quote or a line break)
   * @param header the first line names the columns
   * @param ranges {@link #schema} pins each number and date column's range too
   */
  public record Csv(char delim, boolean header, boolean ranges) {
    /** ',' and a header line. */
    public static final Csv DEFAULT = new Csv(',', true, false);
  }

  /**
   * When {@link #drift} calls a column drifted (noqtis-drift(1)).
   *
   * @param psiwarn a PSI at or over this warns
   * @param psifail a PSI at or over this fails, when both samples have minn values
   * @param alpha a KS or chi-square p-value below this warns
   * @param minn see psifail
   * @param benford test first digits against Benford's law too
   */
  public record Drift(
      double psiwarn, double psifail, double alpha, double minn, boolean benford) {
    /** PSI 0.1 warns and 0.25 fails, alpha 0.001, minn 1,000, no Benford test. */
    public static final Drift DEFAULT = new Drift(0.1, 0.25, 0.001, 1000, false);
  }

  /** The handles of libnqd, loaded on first use. */
  static final class N {
    private N() {}

    static final SymbolLookup LIB = lookup();
    static final MethodHandle NEW = fn("nqdnew", I, P);
    static final MethodHandle PARSE = fn("nqdparse", I, P, Z, P, P, Z);
    static final MethodHandle LOAD = fn("nqdload", I, P, P, P, Z);
    static final MethodHandle JSON = fn("nqdjson", I, P, P, Z, P);
    static final MethodHandle SAVE = fn("nqdsave", I, P, P);
    static final MethodHandle RFREE = fn("nqdrfree", null, P);
    static final MethodHandle LEN = fn("nqdlen", Z, P, P);
    static final MethodHandle AT = fn("nqdat", I, P, P, Z, P, Z, P);
    static final MethodHandle KEY = fn("nqdkey", I, P, P, P, P, Z, P);
    static final MethodHandle PUT = fn("nqdput", I, P, P, P, Z, P, Z);
    static final MethodHandle DEL = fn("nqddel", I, P, P, P);
    static final MethodHandle SET = fn("nqdset", I, P, P, P, P, P, Z, P, Z);
    static final MethodHandle SRC = fn("nqdsrc", I, P, P, P, P, Z);
    static final MethodHandle INFER = fn("nqdinfer", I, P, P, P, P, Z, P, P, Z);
    static final MethodHandle STATS = fn("nqdstats", I, P, P, P, P, Z, P, P, Z);
    static final MethodHandle DRIFT = fn("nqddrift", I, P, Z, P, P, P, P);
    static final MethodHandle DIFF = fn("nqddiff", I, P, P, P);
    static final MethodHandle CHK = fn("nqdchk", I, P, P);
    static final MethodHandle REPN = fn("nqdrepn", Z, P);
    static final MethodHandle REPI = fn("nqdrepi", I, P, Z, P, P, P);
    static final MethodHandle REPJ = fn("nqdrepj", P, P, Z);
    static final MethodHandle REPFREE = fn("nqdrepfree", null, P);
    static final MethodHandle ADDR = fn("nqdaddr", I, P, P, Z, P, P, Z, P);
    static final MethodHandle VRFY = fn("nqdvrfy", I, P, P, P, Z);
    static final MethodHandle FLD = fn("nqdfld", I, P, P, Z, P, P, Z, P);
    static final MethodHandle RSLV = fn("nqdrslv", I, P, Z, P, Z, P, P, Z);
    static final MethodHandle RSP = fn("nqdrsp", I, P, Z, P, Z, P, Z, P, P, P, Z);
    static final MethodHandle WB = fn("nqdwb", I, P, P, Z, P);

    private static MethodHandle fn(
        String name, java.lang.foreign.MemoryLayout ret, java.lang.foreign.MemoryLayout... a) {
      return Native.fn(LIB, name, ret, a);
    }

    private static SymbolLookup lookup() {
      // libnoqtis first: libnqd needs it
      Object unused = Native.LIB;
      List<String> tried = new ArrayList<>();
      String p = prop("noqtis.nqd", "NOQTIS_NQD");
      if (p != null) {
        Path f = Path.of(p).toAbsolutePath();
        if (!Files.isRegularFile(f)) {
          throw new UnsatisfiedLinkError("noqtis: no nqd library at " + f);
        }
        return SymbolLookup.libraryLookup(f, Arena.global());
      }
      String[] names = {
        System.mapLibraryName("nqd"), "libnqd.so.0", "libnqd.0.dylib", "nqd-0.dll", "libnqd-0.dll"
      };
      String q = prop("noqtis.library", "NOQTIS_LIBRARY");
      if (q != null) {
        Path d = Path.of(q).toAbsolutePath().getParent();
        for (Path dd : new Path[] {d, d.resolve("nqd")}) {
          for (String n : names) {
            Path f = dd.resolve(n);
            if (Files.isRegularFile(f)) {
              return SymbolLookup.libraryLookup(f, Arena.global());
            }
            tried.add(f.toString());
          }
        }
      }
      for (String n : names) {
        try {
          return SymbolLookup.libraryLookup(n, Arena.global());
        } catch (IllegalArgumentException e) {
          tried.add(n);
        }
      }
      throw new UnsatisfiedLinkError(
          "noqtis: cannot load the data layer (tried "
              + String.join(", ", tried)
              + "); set -Dnoqtis.nqd=<path> or NOQTIS_NQD");
    }

    private static String prop(String k, String env) {
      String v = System.getProperty(k);
      if (v == null || v.isEmpty()) {
        v = System.getenv(env);
      }
      return v == null || v.isEmpty() ? null : v;
    }
  }

  private static final java.lang.foreign.MemoryLayout I = JAVA_INT, Z = JAVA_LONG, P = ADDRESS;
  private static final int WHY = 600;

  private static MemorySegment cs(Arena m, String s) {
    if (s.indexOf('\0') >= 0) {
      throw new NoqtisException(-1, "a NUL character in \"" + s + "\"");
    }
    return m.allocateFrom(s);
  }

  private static long blen(String s) {
    return s.getBytes(StandardCharsets.UTF_8).length;
  }

  private static NoqtisException fail(int c, MemorySegment why) {
    return new NoqtisException(c, why.getString(0));
  }

  @FunctionalInterface
  private interface Out {
    int call(MemorySegment out, long cap, MemorySegment len) throws Throwable;
  }

  /**
   * The text a call writes to (out, cap), its length to *len: tried with 64 KiB, then once more
   * with room for all of it (NQEBUF). The code when it fails, as a negative number in [0].
   */
  private static Object grow(Out f) throws Throwable {
    long cap = 1 << 16;
    try (Arena m = Arena.ofConfined()) {
      MemorySegment n = m.allocate(JAVA_LONG);
      for (; ; ) {
        MemorySegment o = m.allocate(cap);
        int c = f.call(o, cap, n);
        long l = n.get(JAVA_LONG, 0);
        if (c == -2 && l + 1 > cap) {
          cap = l + 1;
          continue;
        }
        if (c != 0) {
          return c;
        }
        return new String(o.asSlice(0, l).toArray(JAVA_BYTE), StandardCharsets.UTF_8);
      }
    }
  }

  private static String text(Out f, MemorySegment why) throws Throwable {
    Object r = grow(f);
    if (r instanceof Integer c) {
      throw why == null ? new NoqtisException(c) : fail(c, why);
    }
    return (String) r;
  }

  /** The record of dir; with mk, a new one when there is none. */
  private static MemorySegment rec(Arena m, MemorySegment d, boolean mk) throws Throwable {
    MemorySegment rp = m.allocate(ADDRESS), why = m.allocate(WHY);
    int c = (int) N.LOAD.invoke(d, rp, why, (long) WHY);
    if (c == -7 && mk) {
      c = (int) N.NEW.invoke(rp);
    }
    if (c != 0) {
      throw fail(c, why);
    }
    return rp.get(ADDRESS, 0);
  }

  private static String json(MemorySegment r) throws Throwable {
    return text((o, cap, n) -> (int) N.JSON.invoke(r, o, cap, n), null);
  }

  private static void put(Arena m, MemorySegment r, String member, String json) throws Throwable {
    MemorySegment why = m.allocate(WHY);
    int c = (int) N.PUT.invoke(r, cs(m, member), cs(m, json), blen(json), why, (long) WHY);
    if (c != 0) {
      throw fail(c, why);
    }
  }

  private static Optional<String> key(Arena m, MemorySegment r, String member, String key)
      throws Throwable {
    MemorySegment mc = cs(m, member), kc = cs(m, key);
    Object x = grow((o, cap, n) -> (int) N.KEY.invoke(r, mc, kc, o, cap, n));
    if (x instanceof Integer c) {
      if (c == -7) {
        return Optional.empty();
      }
      throw new NoqtisException(c);
    }
    return Optional.of((String) x);
  }

  /** The report the library made at *rp (freed here), or its error. */
  private static Report report(int c, MemorySegment rp) throws Throwable {
    MemorySegment r = rp.get(ADDRESS, 0);
    if (r.equals(MemorySegment.NULL)) {
      throw new NoqtisException(c == 0 ? -10 : c);
    }
    List<Row> rows = new ArrayList<>();
    try (Arena m = Arena.ofConfined()) {
      long n = (long) N.REPN.invoke(r);
      MemorySegment pc = m.allocate(ADDRESS), po = m.allocate(JAVA_INT), pd = m.allocate(ADDRESS);
      for (long i = 0; i < n; i++) {
        if ((int) N.REPI.invoke(r, i, pc, po, pd) != 0) {
          break;
        }
        MemorySegment j = (MemorySegment) N.REPJ.invoke(r, i);
        rows.add(
            new Row(
                Native.str(pc.get(ADDRESS, 0)),
                po.get(JAVA_INT, 0) != 0,
                Native.str(pd.get(ADDRESS, 0)),
                j.equals(MemorySegment.NULL) ? null : Native.str(j)));
      }
    } finally {
      N.REPFREE.invoke(r);
    }
    return new Report(c, List.copyOf(rows));
  }

  private static MemorySegment csv(Arena m, Csv o) {
    if (o == null) {
      o = Csv.DEFAULT;
    }
    if (o.delim() == 0 || o.delim() > 127) {
      throw new NoqtisException(-1, "delim must be one ASCII character");
    }
    // nqdcsvopt: char delim, int noheader, int ranges
    MemorySegment x = m.allocate(12, 4);
    x.set(JAVA_BYTE, 0, (byte) o.delim());
    x.set(JAVA_INT, 4, o.header() ? 0 : 1);
    x.set(JAVA_INT, 8, o.ranges() ? 1 : 0);
    return x;
  }

  /**
   * The record in dir as its canonical JSON text.
   *
   * @param dir the capsule folder
   * @return the record
   */
  public static String text(Path dir) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment r = rec(m, cs(m, dir.toString()), false);
      try {
        return json(r);
      } finally {
        N.RFREE.invoke(r);
      }
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The JSON text of a record in canonical form, after checking it as the library checks a record
   * it reads (the bytes {@link #text} gives for it).
   *
   * @param json the record
   * @return its canonical form
   */
  public static String canon(String json) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment rp = m.allocate(ADDRESS), why = m.allocate(WHY);
      int c = (int) N.PARSE.invoke(cs(m, json), blen(json), rp, why, (long) WHY);
      if (c != 0) {
        throw fail(c, why);
      }
      MemorySegment r = rp.get(ADDRESS, 0);
      try {
        return json(r);
      } finally {
        N.RFREE.invoke(r);
      }
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /** One string as JSON text. */
  static String jstr(String s) {
    StringBuilder b = new StringBuilder("\"");
    for (int i = 0; i < s.length(); i++) {
      char ch = s.charAt(i);
      if (ch == '"' || ch == '\\') {
        b.append('\\').append(ch);
      } else if (ch < 0x20) {
        b.append(String.format("\\u%04x", (int) ch));
      } else {
        b.append(ch);
      }
    }
    return b.append('"').toString();
  }

  private static String now() {
    String e = System.getenv("SOURCE_DATE_EPOCH");
    Instant t = Instant.now();
    if (e != null && !e.isEmpty()) {
      t = Instant.ofEpochSecond(Long.parseLong(e.trim()));
    }
    return DateTimeFormatter.ISO_INSTANT.format(t.truncatedTo(ChronoUnit.SECONDS));
  }

  /**
   * Records each file's SHA-256 and size (paths relative to dir, '/' between folders) as a source,
   * keeping what the record already says of it, with where it came from. Makes the record when
   * there is none.
   *
   * @param dir the capsule folder
   * @param files the files
   * @param s where they came from, or null
   */
  public static void add(Path dir, List<String> files, Src s) {
    if (s == null) {
      s = Src.none();
    }
    if (s.url() != null && files.size() > 1) {
      throw new NoqtisException(-1, "url describes one file: add the files one at a time");
    }
    String ret = "now".equals(s.retrieved()) ? now() : s.retrieved();
    List<String[]> f = new ArrayList<>();
    String[][] kv = {
      {"url", s.url()},
      {"title", s.title()},
      {"publisher", s.publisher()},
      {"licence", s.licence()},
      {"retrieved", ret}
    };
    for (String[] x : kv) {
      if (x[1] != null) {
        f.add(new String[] {x[0], jstr(x[1])});
      }
    }
    if (s.synthetic()) {
      f.add(new String[] {"synthetic", "true"});
    }
    try (Arena m = Arena.ofConfined()) {
      MemorySegment d = cs(m, dir.toString()), why = m.allocate(WHY);
      MemorySegment r = rec(m, d, true);
      try {
        MemorySegment src = cs(m, "sources");
        for (String p : files) {
          MemorySegment pc = cs(m, p);
          int c = (int) N.SRC.invoke(r, d, pc, why, (long) WHY);
          if (c != 0) {
            throw fail(c, why);
          }
          for (String[] x : f) {
            c =
                (int)
                    N.SET.invoke(
                        r, src, pc, cs(m, x[0]), cs(m, x[1]), blen(x[1]), why, (long) WHY);
            if (c != 0) {
              throw fail(c, why);
            }
          }
        }
        Native.rc((int) N.SAVE.invoke(r, d));
      } finally {
        N.RFREE.invoke(r);
      }
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Adds an element (JSON text) to a member: "sources", "schemas", "stats", "chunks" (the one with
   * the same path is replaced), "checks" (the same name), "steps", "commits" (appended), or sets
   * "env" or "cite". Makes the record when there is none.
   *
   * @param dir the capsule folder
   * @param member the member
   * @param json the element
   */
  public static void put(Path dir, String member, String json) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment d = cs(m, dir.toString());
      MemorySegment r = rec(m, d, true);
      try {
        put(m, r, member, json);
        Native.rc((int) N.SAVE.invoke(r, d));
      } finally {
        N.RFREE.invoke(r);
      }
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Removes the element of member with path or name key, or the whole member when key is null.
   *
   * @param dir the capsule folder
   * @param member the member
   * @param key the element's path or name, or null
   */
  public static void del(Path dir, String member, String key) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment d = cs(m, dir.toString());
      MemorySegment r = rec(m, d, false);
      try {
        Native.rc(
            (int) N.DEL.invoke(r, cs(m, member), key == null ? MemorySegment.NULL : cs(m, key)));
        Native.rc((int) N.SAVE.invoke(r, d));
      } finally {
        N.RFREE.invoke(r);
      }
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The element of a keyed member ("sources", "schemas", "stats", "chunks" by path, "checks" by
   * name) with key.
   *
   * @param dir the capsule folder
   * @param member the member
   * @param key the element's path or name
   * @return the element, or empty when there is none
   */
  public static Optional<String> key(Path dir, String member, String key) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment r = rec(m, cs(m, dir.toString()), false);
      try {
        return key(m, r, member, key);
      } finally {
        N.RFREE.invoke(r);
      }
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Checks the record and every file it lists: each source's SHA-256 and size, each schema and its
   * rules, and the checks recorded as failed.
   *
   * @param dir the capsule folder
   * @return the report
   */
  public static Report check(Path dir) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment rp = m.allocate(ADDRESS);
      int c = (int) N.CHK.invoke(cs(m, dir.toString()), rp);
      return report(c, rp);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The schema of a CSV file as a "schemas" element: its columns with the narrowest type of each,
   * missing values, rows (with o.ranges(), number and date ranges). {@link #put} records it.
   *
   * @param dir the capsule folder
   * @param file the file, relative to dir
   * @param o how to read it, or null
   * @return the element
   */
  public static String schema(Path dir, String file, Csv o) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment d = cs(m, dir.toString()), f = cs(m, file), co = csv(m, o);
      MemorySegment why = m.allocate(WHY);
      return text((out, cap, n) -> (int) N.INFER.invoke(d, f, co, out, cap, n, why, (long) WHY), why);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The "schema" and "rule" rows of {@link #check}, of the files named only when files is not
   * empty.
   *
   * @param dir the capsule folder
   * @param files the files, or an empty list for all
   * @return the report
   */
  public static Report schemaCheck(Path dir, List<String> files) {
    List<Row> rows = new ArrayList<>();
    for (Row x : check(dir).rows()) {
      String p = x.detail().split(":", 2)[0];
      if (p.endsWith(" [synthetic]")) {
        p = p.substring(0, p.length() - 12);
      }
      if ((x.check().equals("schema") || x.check().equals("rule"))
          && (files == null || files.isEmpty() || files.contains(p))) {
        rows.add(x);
      }
    }
    boolean ok = !rows.isEmpty() && rows.stream().allMatch(Row::ok);
    return new Report(ok ? 0 : -3, List.copyOf(rows));
  }

  /**
   * Records each CSV file's summaries (a "stats" element, noqtis-drift(1)) in the record, which
   * {@link #drift} later compares a file with.
   *
   * @param dir the capsule folder
   * @param files the files, relative to dir
   * @param o how to read them, or null
   */
  public static void pin(Path dir, List<String> files, Csv o) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment d = cs(m, dir.toString()), co = csv(m, o), why = m.allocate(WHY);
      MemorySegment r = rec(m, d, true);
      try {
        for (String p : files) {
          MemorySegment f = cs(m, p);
          String s =
              text(
                  (out, cap, n) -> (int) N.STATS.invoke(d, f, co, out, cap, n, why, (long) WHY),
                  why);
          put(m, r, "stats", s);
        }
        Native.rc((int) N.SAVE.invoke(r, d));
      } finally {
        N.RFREE.invoke(r);
      }
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /** The value of the top-level member "path" of a canonical JSON object, or null. */
  // only the escapes a capsule path can need (\" and \\)
  static String pathOf(String j) {
    int depth = 0;
    for (int i = 0; i < j.length(); i++) {
      char ch = j.charAt(i);
      if (ch == '{' || ch == '[') {
        depth++;
      } else if (ch == '}' || ch == ']') {
        depth--;
      } else if (ch == '"') {
        int s = ++i;
        while (i < j.length() && j.charAt(i) != '"') {
          i += j.charAt(i) == '\\' ? 2 : 1;
        }
        if (depth == 1 && i < j.length() && j.substring(s, i).equals("path")
            && j.startsWith(":\"", i + 1)) {
          StringBuilder b = new StringBuilder();
          for (int k = i + 3; k < j.length(); k++) {
            char c = j.charAt(k);
            if (c == '\\' && k + 1 < j.length()) {
              b.append(j.charAt(++k));
            } else if (c == '"') {
              return b.toString();
            } else {
              b.append(c);
            }
          }
          return null;
        }
      }
    }
    return null;
  }

  /**
   * Compares each summarised file (or the file of current in its place) with its summary:
   * Kolmogorov-Smirnov, PSI and Jensen-Shannon, chi-square of homogeneity, Benford
   * (noqtis-drift(1)).
   *
   * @param dir the capsule folder
   * @param files the files, or an empty list for every file the record summarises
   * @param current an empty list for the files themselves, else one path per file
   * @param o how to read them, or null
   * @param d the thresholds, or null for {@link Drift#DEFAULT}
   * @return the report: {@link Report#level()}
   */
  public static Report drift(
      Path dir, List<String> files, List<Path> current, Csv o, Drift d) {
    if (d == null) {
      d = Drift.DEFAULT;
    }
    try (Arena m = Arena.ofConfined()) {
      MemorySegment r = rec(m, cs(m, dir.toString()), false);
      try {
        List<String> fs = new ArrayList<>(files == null ? List.of() : files);
        if (fs.isEmpty()) {
          MemorySegment st = cs(m, "stats");
          long n = (long) N.LEN.invoke(r, st);
          for (long i = 0; i < n; i++) {
            long k = i;
            String p = pathOf(text((out, cap, l) -> (int) N.AT.invoke(r, st, k, out, cap, l), null));
            if (p != null) {
              fs.add(p);
            }
          }
        }
        if (fs.isEmpty()) {
          throw new NoqtisException(-1, "the record has no summaries: pin some first");
        }
        boolean cur = current != null && !current.isEmpty();
        if (cur && current.size() != fs.size()) {
          throw new NoqtisException(-1, "current needs one path per file");
        }
        MemorySegment co = csv(m, o);
        // nqddopt: four doubles and an int
        MemorySegment x = m.allocate(40, 8);
        x.set(JAVA_DOUBLE, 0, d.psiwarn());
        x.set(JAVA_DOUBLE, 8, d.psifail());
        x.set(JAVA_DOUBLE, 16, d.alpha());
        x.set(JAVA_DOUBLE, 24, d.minn());
        x.set(JAVA_INT, 32, d.benford() ? 1 : 0);
        int code = 0;
        List<Row> rows = new ArrayList<>();
        for (int i = 0; i < fs.size(); i++) {
          String f = fs.get(i);
          String s =
              key(m, r, "stats", f)
                  .orElseThrow(
                      () -> new NoqtisException(-1, "no summary of " + f + ": pin one first"));
          Path p = cur ? current.get(i) : dir.resolve(f);
          MemorySegment rp = m.allocate(ADDRESS);
          int c = (int) N.DRIFT.invoke(cs(m, s), blen(s), cs(m, p.toString()), co, x, rp);
          Report y = report(c, rp);
          if (code == 0) {
            code = y.code();
          }
          rows.addAll(y.rows());
        }
        return new Report(code, List.copyOf(rows));
      } finally {
        N.RFREE.invoke(r);
      }
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * What changed from capsule a to capsule b: one failed row per difference (files, sources,
   * schemas, summaries, env, ...).
   *
   * @param a the older capsule
   * @param b the newer one
   * @return the report: {@link Report#same()} when nothing differs
   */
  public static Report diff(Path a, Path b) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment rp = m.allocate(ADDRESS);
      int c = (int) N.DIFF.invoke(cs(m, a.toString()), cs(m, b.toString()), rp);
      return report(c, rp);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  // ---- sources (nqdaddr(3)) ----

  /**
   * Where a source can be fetched.
   *
   * @param kind "url", "portal" (the request to send, whose reply {@link #reply} reads), "mirror"
   *     or "archived" (a Wayback Machine copy's raw bytes)
   * @param url the address
   */
  public record Addr(String kind, String url) {}

  /** The resolved address of a source and, for the Wayback Machine, the copy's time. */
  public record Resolved(String url, String time) {}

  private static final String[] KINDS = {"", "url", "portal", "mirror", "archived"};

  /**
   * The addresses the source file can be fetched from, in the order to try them.
   *
   * @param dir the capsule folder
   * @param file the source's path
   * @return the addresses; none for a synthetic source
   */
  public static List<Addr> addrs(Path dir, String file) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment r = rec(m, cs(m, dir.toString()), false), f = cs(m, file);
      MemorySegment k = m.allocate(JAVA_INT);
      List<Addr> out = new ArrayList<>();
      try {
        for (long i = 0; ; i++) {
          long ii = i;
          Object x = grow((o, cap, n) -> (int) N.ADDR.invoke(r, f, ii, k, o, cap, n));
          if (x instanceof Integer c) {
            if (c == -1 || (c == -7 && i > 0)) {
              return out;
            }
            throw new NoqtisException(c);
          }
          int kd = k.get(JAVA_INT, 0);
          out.add(new Addr(KINDS[kd >= 1 && kd <= 4 ? kd : 4], (String) x));
        }
      } finally {
        N.RFREE.invoke(r);
      }
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Whether the bytes are the source file's recorded bytes (its size and SHA-256): only such bytes
   * may be taken for it.
   *
   * @param dir the capsule folder
   * @param file the source's path
   * @param b what was fetched
   * @return true when they are
   */
  public static boolean verify(Path dir, String file, byte[] b) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment r = rec(m, cs(m, dir.toString()), false);
      MemorySegment bs = m.allocate(Math.max(1, b.length));
      MemorySegment.copy(b, 0, bs, JAVA_BYTE, 0, b.length);
      try {
        int c = (int) N.VRFY.invoke(r, cs(m, file), bs, (long) b.length);
        if (c != 0 && c != -3) {
          throw new NoqtisException(c);
        }
        return c == 0;
      } finally {
        N.RFREE.invoke(r);
      }
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The field of element i of member (0 for "env" and "cite"): a string as its text, anything
   * else as canonical JSON.
   *
   * @param dir the capsule folder
   * @param member the member
   * @param i the element's index, from 0
   * @param name the field
   * @return the value, or empty when there is none
   */
  public static Optional<String> field(Path dir, String member, long i, String name) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment r = rec(m, cs(m, dir.toString()), false);
      MemorySegment mc = cs(m, member), fc = cs(m, name);
      try {
        Object x = grow((o, cap, n) -> (int) N.FLD.invoke(r, mc, i, fc, o, cap, n));
        if (x instanceof Integer c) {
          if (c == -7) {
            return Optional.empty();
          }
          throw new NoqtisException(c);
        }
        return Optional.of((String) x);
      } finally {
        N.RFREE.invoke(r);
      }
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The address to ask (a GET) for the file of a source's resolver (CKAN, Socrata, ArcGIS or the
   * Wayback Machine).
   *
   * @param resolver the resolver, as JSON
   * @return the address
   */
  public static String request(String resolver) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment why = m.allocate(WHY), j = cs(m, resolver);
      return text((o, cap, n) -> (int) N.RSLV.invoke(j, blen(resolver), o, cap, n, why,
          (long) WHY), why);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * Reads the portal's reply to {@link #request}.
   *
   * @param resolver the resolver, as JSON
   * @param reply the reply's bytes
   * @return the file's address, and for the Wayback Machine the copy's time ("" otherwise)
   */
  public static Resolved reply(String resolver, byte[] reply) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment why = m.allocate(WHY), j = cs(m, resolver), tm = m.allocate(21);
      MemorySegment rp = m.allocate(Math.max(1, reply.length));
      MemorySegment.copy(reply, 0, rp, JAVA_BYTE, 0, reply.length);
      String u = text((o, cap, n) -> (int) N.RSP.invoke(j, blen(resolver), rp,
          (long) reply.length, o, cap, n, tm, why, (long) WHY), why);
      return new Resolved(u, tm.getString(0));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /**
   * The raw-bytes address of a Wayback Machine copy (any other http:// or https:// address as it
   * is).
   *
   * @param url the address
   * @return the raw-bytes address
   */
  public static String wayback(String url) {
    try (Arena m = Arena.ofConfined()) {
      MemorySegment u = cs(m, url);
      return text((o, cap, n) -> (int) N.WB.invoke(u, o, cap, n), null);
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }
}
