// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
package io.github.rootcoder007.noqtis;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.io.IOException;
import java.io.InputStream;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.ArrayList;
import java.util.List;

/**
 * The functions of noqtis.h, through the Foreign Function and Memory API.
 * The shared library is the file named by the system property
 * {@code noqtis.library} or the environment variable
 * {@code NOQTIS_LIBRARY}; else the copy the jar carries for this operating
 * system and CPU ({@code native/<os>-<arch>/}, in the jar published to
 * Maven Central), unpacked to a private temporary folder; else
 * {@code libnoqtis} (or {@code noqtis-0.dll}) on the system's library path.
 */
@SuppressWarnings("restricted") // the FFM calls this class exists to make
final class Native {
  private Native() {}

  static final Linker L = Linker.nativeLinker();
  static final SymbolLookup LIB = lookup();

  // size_t is passed as a Java long: 64-bit platforms only
  static {
    MemoryLayout st = L.canonicalLayouts().get("size_t");
    if (st == null || st.byteSize() != 8) {
      throw new UnsupportedOperationException("noqtis for Java needs a 64-bit platform");
    }
  }

  private static SymbolLookup lookup() {
    List<String> tried = new ArrayList<>();
    String p = System.getProperty("noqtis.library");
    if (p == null || p.isEmpty()) {
      p = System.getenv("NOQTIS_LIBRARY");
    }
    if (p != null && !p.isEmpty()) {
      Path f = Path.of(p).toAbsolutePath();
      if (!Files.isRegularFile(f)) {
        throw new UnsatisfiedLinkError("noqtis: no library at " + f);
      }
      return SymbolLookup.libraryLookup(f, Arena.global());
    }
    SymbolLookup b = bundled(tried);
    if (b != null) {
      return b;
    }
    for (String n :
        new String[] {
          System.mapLibraryName("noqtis"), "libnoqtis.so.0", "libnoqtis.0.dylib", "noqtis-0.dll"
        }) {
      try {
        return SymbolLookup.libraryLookup(n, Arena.global());
      } catch (IllegalArgumentException e) {
        tried.add(n);
      }
    }
    throw new UnsatisfiedLinkError(
        "noqtis: cannot load the library (tried "
            + String.join(", ", tried)
            + "); set -Dnoqtis.library=<path> or NOQTIS_LIBRARY");
  }

  /** The platform's name in the jar: linux, macos or windows, then x86_64 or arm64. */
  static String platform() {
    String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
    String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
    String o =
        os.startsWith("linux")
            ? "linux"
            : os.startsWith("mac") ? "macos" : os.startsWith("windows") ? "windows" : null;
    String a =
        arch.equals("amd64") || arch.equals("x86_64")
            ? "x86_64"
            : arch.equals("aarch64") || arch.equals("arm64") ? "arm64" : null;
    return o == null || a == null ? null : o + "-" + a;
  }

  /** The library the jar carries for this platform, or null when it has none or it will not load. */
  private static SymbolLookup bundled(List<String> tried) {
    String pl = platform();
    if (pl == null) {
      return null;
    }
    String file = pl.startsWith("windows") ? "noqtis-0.dll" : System.mapLibraryName("noqtis");
    try {
      Path f = unpack(file);
      return f == null ? null : SymbolLookup.libraryLookup(f, Arena.global());
    } catch (IOException | IllegalArgumentException e) {
      tried.add("jar:/native/" + pl + "/" + file);
      return null;
    }
  }

  // the folder the jar's libraries are unpacked to: one for all of them
  private static Path dir;

  /**
   * A library the jar carries for this platform, unpacked to a fresh folder
   * only this user can open; null when the jar has none of that name. The
   * file and the folder are deleted at exit.
   */
  static synchronized Path unpack(String file) throws IOException {
    String pl = platform();
    if (pl == null) {
      return null;
    }
    try (InputStream in = Native.class.getResourceAsStream("/native/" + pl + "/" + file)) {
      if (in == null) {
        return null;
      }
      if (dir == null) {
        dir = Files.createTempDirectory("noqtis");
        dir.toFile().deleteOnExit();
      }
      Path f = dir.resolve(file);
      Files.copy(in, f, StandardCopyOption.REPLACE_EXISTING);
      // registered after the folder, so deleted before it
      f.toFile().deleteOnExit();
      return f;
    }
  }

  static MethodHandle fn(String name, MemoryLayout ret, MemoryLayout... args) {
    return fn(LIB, name, ret, args);
  }

  static MethodHandle fn(SymbolLookup lib, String name, MemoryLayout ret, MemoryLayout... args) {
    MemorySegment s =
        lib.find(name).orElseThrow(() -> new UnsatisfiedLinkError("noqtis: no symbol " + name));
    FunctionDescriptor d =
        ret == null ? FunctionDescriptor.ofVoid(args) : FunctionDescriptor.of(ret, args);
    return L.downcallHandle(s, d);
  }

  static final MemoryLayout I = JAVA_INT, Z = JAVA_LONG, P = ADDRESS;

  static final MethodHandle NQERR = fn("nqerr", P, I);
  static final MethodHandle NQVER = fn("nqver", P);
  static final MethodHandle NQSELF = fn("nqselftest", I);
  static final MethodHandle NQRAND = fn("nqrand", I, P, Z);
  static final MethodHandle NQHLEN = fn("nqhlen", Z, I);
  static final MethodHandle NQHASH = fn("nqhash", I, I, P, Z, P, Z);
  static final MethodHandle NQHMAC = fn("nqhmac", I, I, P, Z, P, Z, P, Z);
  static final MethodHandle NQSSIZE = fn("nqssize", I, I, P);
  static final MethodHandle NQSNAME = fn("nqsname", P, I);
  static final MethodHandle NQSKG = fn("nqskg", I, I, P, Z, P, Z);
  static final MethodHandle NQSKGD = fn("nqskgd", I, I, P, Z, P, Z, P, Z);
  static final MethodHandle NQSIGN = fn("nqsign", I, I, P, Z, P, Z, P, Z, I, P, Z, P);
  static final MethodHandle NQSIGND = fn("nqsignd", I, I, P, Z, P, Z, P, Z, I, P, Z, P, Z, P);
  static final MethodHandle NQVRFY = fn("nqvrfy", I, I, P, Z, P, Z, P, Z, I, P, Z);
  static final MethodHandle NQKSIZE = fn("nqksize", I, I, P);
  static final MethodHandle NQKNAME = fn("nqkname", P, I);
  static final MethodHandle NQKKG = fn("nqkkg", I, I, P, Z, P, Z);
  static final MethodHandle NQKKGD = fn("nqkkgd", I, I, P, Z, P, Z, P, Z);
  static final MethodHandle NQENC = fn("nqenc", I, I, P, Z, P, Z, P, Z);
  static final MethodHandle NQENCD = fn("nqencd", I, I, P, Z, P, Z, P, Z, P, Z);
  static final MethodHandle NQDEC = fn("nqdec", I, I, P, Z, P, Z, P, Z);
  static final MethodHandle NQSEAL = fn("nqseal", I, P, I, P, Z, P, Z, P, P);
  static final MethodHandle NQSEAL2 = fn("nqseal2", I, P, I, P, Z, P, Z, P, P, Z);
  static final MethodHandle NQCAPID = fn("nqcapid", I, P, P);
  static final MethodHandle NQCHKX = fn("nqchkx", I, P, P, P);
  static final MethodHandle NQPROVE = fn("nqprove", I, P, P, Z, P, Z, P);
  static final MethodHandle NQCHKP = fn("nqchkp", I, P, Z, P, P, P);
  static final MethodHandle NQINSP = fn("nqinsp", I, P, P);
  static final MethodHandle NQFILES = fn("nqfiles", I, P, P);
  static final MethodHandle NQREPN = fn("nqrepn", Z, P);
  static final MethodHandle NQREPI = fn("nqrepi", I, P, Z, P, P, P);
  static final MethodHandle NQREPFREE = fn("nqrepfree", null, P);
  static final MethodHandle NQCARD = fn("nqcard", I, I, P, Z, P, Z, P, P, P, P, P, Z, P, Z, P);
  static final MethodHandle NQCARDVRFY = fn("nqcardvrfy", I, P, Z, P, Z, P);

  /** A C string the library returned, or "" for NULL. */
  static String str(MemorySegment p) {
    if (p.equals(MemorySegment.NULL)) {
      return "";
    }
    return p.reinterpret(Long.MAX_VALUE).getString(0);
  }

  /** The bytes of b in a, or NULL when b is empty. */
  static MemorySegment in(Arena a, byte[] b) {
    if (b == null || b.length == 0) {
      return MemorySegment.NULL;
    }
    return a.allocateFrom(JAVA_BYTE, b);
  }

  /** n bytes in a (at least one, so the address is never NULL). */
  static MemorySegment out(Arena a, long n) {
    return a.allocate(Math.max(n, 1));
  }

  static byte[] bytes(MemorySegment s, long n) {
    return s.asSlice(0, n).toArray(JAVA_BYTE);
  }

  /** NQOK, or throws the error of code c. */
  static void rc(int c) {
    if (c != 0) {
      throw new NoqtisException(c);
    }
  }

  /** A Throwable from a downcall: rethrown as it is, or wrapped. */
  static RuntimeException wrap(Throwable t) {
    if (t instanceof RuntimeException r) {
      return r;
    }
    if (t instanceof Error e) {
      throw e;
    }
    return new IllegalStateException(t);
  }

  static final MethodHandle NQWIPE = fn("nqwipe", null, P, Z);
  static final MethodHandle NQCTEQ = fn("nqcteq", I, P, P, Z);
  static final MethodHandle NQB2B = fn("nqb2b", I, P, Z, P, Z, P, Z);
  static final MethodHandle NQA2ID = fn("nqa2id", I, P, Z, P, Z, P, Z, P, Z, I, I, I, P, Z);
  static final MethodHandle NQHINI = fn("nqhini", I, P, I);
  static final MethodHandle NQHUPD = fn("nqhupd", I, P, P, Z);
  static final MethodHandle NQHFIN = fn("nqhfin", I, P, P, Z);
  static final MethodHandle NQPWENC = fn("nqpwenc", I, P, Z, P, Z, I, I, I, P, Z, P, Z, P);
  static final MethodHandle NQPWDEC = fn("nqpwdec", I, P, Z, P, Z, P, Z, P, Z, P);
  static final MethodHandle NQSMU = fn("nqsmu", I, I, P, Z, P, Z, P, Z, I, P, Z);
  static final MethodHandle NQSIGNMU = fn("nqsignmu", I, I, P, Z, P, Z, P, Z, P, Z, P);
  static final MethodHandle NQVRFYMU = fn("nqvrfymu", I, I, P, Z, P, Z, P, Z);
  static final MethodHandle NQSINI = fn("nqsini", I, P, I, P, Z, P, Z, I);
  static final MethodHandle NQVINI = fn("nqvini", I, P, I, P, Z, P, Z, I);
  static final MethodHandle NQSUPD = fn("nqsupd", I, P, P, Z);
  static final MethodHandle NQSFIN = fn("nqsfin", I, P, P, Z, P, Z, P, Z, P);
  static final MethodHandle NQVFIN = fn("nqvfin", I, P, P, Z, P, Z);
  static final MethodHandle NQKSEAL = fn("nqkseal", I, I, P, Z, P, Z, P, Z, P, Z, P);
  static final MethodHandle NQKOPEN = fn("nqkopen", I, I, P, Z, P, Z, P, Z, P, Z, P);
  static final MethodHandle NQKFEINI = fn("nqkfeini", I, P, I, P, Z, P, Z, I, P, Z, P);
  static final MethodHandle NQKFDINI = fn("nqkfdini", I, P, I, P, Z, P, Z, P, Z, P);
  static final MethodHandle NQKFEUPD = fn("nqkfeupd", I, P, P, Z, P, Z, P);
  static final MethodHandle NQKFEFIN = fn("nqkfefin", I, P, P, Z, P, Z, P);
  static final MethodHandle NQKFDUPD = fn("nqkfdupd", I, P, P, Z, P, Z, P);
  static final MethodHandle NQKFDFIN = fn("nqkfdfin", I, P, P, Z, P, Z, P);

  /** Wipes n bytes at s (nqwipe). */
  static void wipe(MemorySegment s, long n) {
    try {
      NQWIPE.invoke(s, n);
    } catch (Throwable t) {
      throw wrap(t);
    }
  }

  /** A call that writes to (out, cap) and its size to *n, NQEBUF with the size when short. */
  @FunctionalInterface
  interface Out {
    int call(MemorySegment out, long cap, MemorySegment n) throws Throwable;
  }

  /** The bytes f writes: with cap bytes, then once more with the size it asked for. */
  static byte[] sized(Arena m, long cap, Out f) throws Throwable {
    MemorySegment n = m.allocate(JAVA_LONG);
    for (int k = 0; k < 2; k++) {
      MemorySegment o = out(m, cap);
      int c = f.call(o, cap, n);
      long l = n.get(JAVA_LONG, 0);
      if (c == -2 && l > cap && k == 0) {
        cap = l + 1;
        continue;
      }
      rc(c);
      byte[] b = bytes(o, l);
      wipe(o, cap);
      return b;
    }
    throw new NoqtisException(-2);
  }

  static final MethodHandle NQSEALWHY = fn("nqsealwhy", I, P, P, P, Z);
  static final MethodHandle NQTSREQ = fn("nqtsreq", I, P, P, Z, P, Z, P);
  static final MethodHandle NQTSPUT = fn("nqtsput", I, P, P, Z, P, Z, P, P, Z, P, P);
  static final MethodHandle NQERSREQ = fn("nqersreq", I, P, I, P, Z, P, Z, P, P);
  static final MethodHandle NQERSPUT = fn("nqersput", I, P, I, P, Z, P, Z, P, P, Z, P, P, P);
  static final MethodHandle NQKSTMT =
      fn("nqkstmt", I, I, P, Z, P, Z, I, P, Z, P, Z, JAVA_LONG, P, P, Z, P);
  static final MethodHandle NQDSSE = fn("nqdsse", I, I, P, Z, P, Z, P, P, Z, P, Z, P);
  static final MethodHandle NQDSSEVRFY = fn("nqdssevrfy", I, I, P, Z, P, Z, P, Z, P, P);
}
