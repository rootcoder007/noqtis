// SPDX-License-Identifier: LGPL-3.0-or-later
package io.github.rootcoder007.noqtis;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Optional;

/**
 * DSSE envelopes, the in-toto and SLSA signing wrapper: a payload and its
 * type, signed over PAE(type, payload).
 *
 * <pre>{@code
 * byte[] e = Dsse.sign("ML-DSA-44", sk, pk, "application/vnd.in-toto+json", stmt);
 * Optional<Dsse.Payload> p = Dsse.verify("ML-DSA-44", pk, e);
 * }</pre>
 */
public final class Dsse {
  private Dsse() {}

  /**
   * A payload that verified.
   *
   * @param type its payloadType
   * @param payload its bytes
   */
  public record Payload(String type, byte[] payload) {}

  /**
   * The envelope (canonical JSON) of payload of type, signed by the pair
   * (sk, pk); its keyid is the hex SHA-256 of pk.
   *
   * @param alg the signature algorithm
   * @param sk the secret key
   * @param pk its public key
   * @param type 1 to 255 printable ASCII bytes, no quote or backslash
   * @param payload the payload
   * @return the envelope
   */
  public static byte[] sign(String alg, byte[] sk, byte[] pk, String type, byte[] payload) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    if (type.indexOf('\0') >= 0) {
      throw new NoqtisException(-1, "type: a NUL character");
    }
    try (Arena m = Arena.ofConfined()) {
      MemorySegment k = Native.in(m, sk), t = m.allocateFrom(type);
      try {
        return Native.sized(
            m,
            4L * payload.length + 4L * a.sig() + 1024,
            (o, cap, n) ->
                (int)
                    Native.NQDSSE.invoke(
                        a.id(), k, (long) sk.length, Native.in(m, pk), (long) pk.length, t,
                        Native.in(m, payload), (long) payload.length, o, cap, n));
      } finally {
        Native.wipe(k, sk.length);
      }
    } catch (Throwable x) {
      throw Native.wrap(x);
    }
  }

  /**
   * The type and payload when one of the envelope's signatures verifies
   * under pk, empty when none does; DECODE for text that is not an
   * envelope.
   *
   * @param alg the signature algorithm
   * @param pk the public key
   * @param env the envelope
   * @return the payload, or empty
   */
  public static Optional<Payload> verify(String alg, byte[] pk, byte[] env) {
    Noqtis.Alg a = Noqtis.find(alg, "sign");
    try (Arena m = Arena.ofConfined()) {
      MemorySegment t = m.allocate(256), e = Native.out(m, env.length);
      e.copyFrom(MemorySegment.ofArray(env));
      byte[] p =
          Native.sized(
              m,
              env.length + 1L,
              (o, cap, n) ->
                  (int)
                      Native.NQDSSEVRFY.invoke(
                          a.id(), Native.in(m, pk), (long) pk.length, e, (long) env.length, o,
                          cap, n, t));
      return Optional.of(new Payload(t.getString(0), p));
    } catch (NoqtisException x) {
      if (x.code() == -3) {
        return Optional.empty();
      }
      throw x;
    } catch (Throwable x) {
      throw Native.wrap(x);
    }
  }
}
