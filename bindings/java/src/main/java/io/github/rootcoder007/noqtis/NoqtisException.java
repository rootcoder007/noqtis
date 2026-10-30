// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
package io.github.rootcoder007.noqtis;

import java.lang.foreign.MemorySegment;

/**
 * A failed noqtis call: {@link #code()} is the library's {@code NQE*} code
 * (-1 for NQEARG, ...), {@link #kind()} the same as a {@link Code}, {@link
 * #nqerr()} the library's message for it, and the exception's message
 * adds, for a check this binding makes, what was wrong.
 */
public class NoqtisException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  /** One per {@code NQE*} code of noqtis.h. */
  public enum Code {
    /** An argument is out of range or NULL (NQEARG). */
    ARG,
    /** An output buffer is too small (NQEBUF). */
    BUF,
    /** A signature, MAC or digest does not verify (NQEVRFY). */
    VERIFY,
    /** Input is not in the encoding the standard defines (NQEDEC). */
    DECODE,
    /** The operating system's random source failed (NQERNG). */
    RAND,
    /** An allocation failed (NQEMEM). */
    MEM,
    /** A file could not be read or written (NQEIO). */
    IO,
    /** An algorithm or option noqtis does not provide (NQENOSUP). */
    UNSUPPORTED,
    /** Input exceeds a size or depth limit (NQELIM). */
    LIMIT,
    /** A context was used out of order (NQESTATE). */
    STATE,
    /** A code this binding does not know. */
    OTHER;

    static Code of(int c) {
      return c <= -1 && c >= -10 ? values()[-c - 1] : OTHER;
    }
  }

  private final int code;
  private final String nqerr;

  NoqtisException(int code) {
    this(code, null);
  }

  NoqtisException(int code, String why) {
    super(msg(code, why));
    this.code = code;
    this.nqerr = errmsg(code);
  }

  private static String msg(int code, String why) {
    String m = "noqtis: " + errmsg(code);
    return why == null || why.isEmpty() ? m : m + ": " + why;
  }

  /** The library's message for an {@code NQE*} code ({@code nqerr}). */
  public static String errmsg(int code) {
    try {
      return Native.str((MemorySegment) Native.NQERR.invoke(code));
    } catch (Throwable t) {
      throw Native.wrap(t);
    }
  }

  /** The {@code NQE*} code, a negative number. */
  public int code() {
    return code;
  }

  /** The code as a {@link Code}. */
  public Code kind() {
    return Code.of(code);
  }

  /** The library's message for the code ({@code nqerr}). */
  public String nqerr() {
    return nqerr;
  }
}
