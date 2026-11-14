// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
package io.github.rootcoder007.noqtis;

import static io.github.rootcoder007.noqtis.Tests.HEX;
import static io.github.rootcoder007.noqtis.Tests.REPO;
import static io.github.rootcoder007.noqtis.Tests.b;
import static io.github.rootcoder007.noqtis.Tests.eq;
import static io.github.rootcoder007.noqtis.Tests.fails;
import static io.github.rootcoder007.noqtis.Tests.mk;
import static io.github.rootcoder007.noqtis.Tests.ok;

import io.github.rootcoder007.noqtis.NoqtisException.Code;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Passphrase key files, streaming signatures and hashes, sealed messages
 * and streams, external mu, BLAKE2b and Argon2id against the known
 * answers of tests/vectors (pwk, kseal, kstream, acvp/mu.txt, b2b,
 * argon2).
 */
final class More {
  private More() {}

  static byte[] h(String s) {
    return HEX.parseHex(s);
  }

  /** The records of a key=value vector file under tests/vectors. */
  static List<Map<String, String>> kv(String name) throws Exception {
    List<Map<String, String>> out = new ArrayList<>();
    Map<String, String> cur = new HashMap<>();
    List<String> ls = new ArrayList<>(Files.readAllLines(REPO.resolve("tests/vectors/" + name)));
    ls.add("");
    for (String l : ls) {
      if (l.startsWith("#")) {
        continue;
      }
      if (l.isEmpty()) {
        if (!cur.isEmpty()) {
          out.add(cur);
          cur = new HashMap<>();
        }
        continue;
      }
      int i = l.indexOf('=');
      cur.put(l.substring(0, i), l.substring(i + 1));
    }
    return out;
  }

  static void pw() throws Exception {
    List<Map<String, String>> v = kv("pwk/kat.txt");
    for (var r : v) {
      ok(Arrays.equals(KeyFile.pwdec(h(r.get("pw")), h(r.get("out")), h(r.get("ad"))), h(r.get("sk"))), "pwk");
    }
    var r = v.get(0);
    byte[] pw = h(r.get("pw")), ad = h(r.get("ad")), out = h(r.get("out"));
    eq(fails(() -> KeyFile.pwdec(b("wrong"), out, ad)), Code.VERIFY, "wrong passphrase");
    eq(fails(() -> KeyFile.pwdec(pw, out, b("x"))), Code.VERIFY, "wrong ad");
    eq(fails(() -> KeyFile.pwdec(pw, Arrays.copyOf(out, 40), ad)), Code.DECODE, "cut");
    byte[] o2 = out.clone();
    o2[o2.length - 1] ^= 1;
    eq(fails(() -> KeyFile.pwdec(pw, o2, ad)), Code.VERIFY, "changed");
    byte[] sk = Sign.keygen("ML-DSA-44").sk();
    eq(fails(() -> KeyFile.pwenc(pw, sk, null, 1024, 1, 1)), Code.ARG, "small memory");
    String t = KeyFile.encode("ML-DSA-44", "sec", sk, "pass".toCharArray());
    ok(t.startsWith("noqtis-key-1 ML-DSA-44 sec\n"), "header");
    ok(Arrays.equals(KeyFile.decode(b(t), "pass".toCharArray()).key(), sk), "round trip");
    eq(fails(() -> KeyFile.decode(b(t))), Code.ARG, "no passphrase");
    try {
      KeyFile.decode(b(t), "nope".toCharArray());
      ok(false, "a wrong passphrase opened it");
    } catch (NoqtisException e) {
      ok(e.kind() == Code.VERIFY && !e.getMessage().contains("nope") && !e.getMessage().contains("pass"), "message " + e);
    }
    Path f = mk("nqjpw").resolve("k");
    KeyFile.write(f, "ML-DSA-44", "sec", sk, false, "pw".toCharArray());
    ok(Arrays.equals(KeyFile.read(f, "sec", "pw".toCharArray()).key(), sk), "file");
  }

  static void stream() throws Exception {
    byte[] msg = new byte[10000];
    for (int i = 0; i < msg.length; i++) {
      msg[i] = (byte) (i % 251);
    }
    Object[][] cs = {
      {"ML-DSA-44", null, 32}, {"ML-DSA-65", "SHA-512", 32}, {"SLH-DSA-SHA2-128f", "SHA-256", 48},
      {"Ed25519", "SHA-512", 32}, {"ML-DSA-65+Ed25519", "SHA-512", 64}
    };
    for (Object[] c : cs) {
      String alg = (String) c[0];
      byte[] seed = new byte[(int) c[2]];
      for (int i = 0; i < seed.length; i++) {
        seed[i] = (byte) i;
      }
      Sign.KeyPair k = Sign.keygen(alg, seed);
      Sign.Opts o = Sign.Opts.none().withCtx(b("c")).withPrehash((String) c[1]).withDeterministic();
      byte[] want = Sign.sign(alg, k.sk(), msg, o);
      for (int n : new int[] {1, 7, 4096, msg.length}) {
        try (Signer s = new Signer(alg, k.sk(), o)) {
          for (int i = 0; i < msg.length; i += n) {
            s.update(msg, i, Math.min(n, msg.length - i));
          }
          ok(Arrays.equals(s.sign(o), want), alg + " " + n);
          eq(fails(() -> s.update(msg)), Code.STATE, "used twice");
        }
      }
      try (Verifier v = new Verifier(alg, k.pk(), o)) {
        v.update(new ByteArrayInputStream(msg));
        ok(v.verify(want), alg + " verifies");
      }
      try (Verifier v = new Verifier(alg, k.pk(), o)) {
        v.update(Arrays.copyOf(msg, 9999));
        ok(!v.verify(want), alg + " another message");
      }
    }
    byte[] sk = Sign.keygen("SLH-DSA-SHA2-128f").sk();
    eq(fails(() -> new Signer("SLH-DSA-SHA2-128f", sk, Sign.Opts.none())), Code.UNSUPPORTED, "pure SLH");
    for (String a : new String[] {"SHA-256", "SHA3-384", "SHA-512/224"}) {
      try (Hasher x = new Hasher(a)) {
        x.update(msg, 0, 5000);
        x.update(msg, 5000, 5000);
        ok(Arrays.equals(x.digest(), Noqtis.hash(a, msg)), a);
      }
    }
    try (Hasher x = new Hasher("SHAKE128")) {
      x.update(msg);
      byte[] a = x.digest(5), z = x.digest(27);
      byte[] all = Arrays.copyOf(a, 32);
      System.arraycopy(z, 0, all, 5, 27);
      ok(Arrays.equals(all, Noqtis.hash("SHAKE128", msg, 32)), "squeeze");
    }
  }

  static byte[] unboxed(Map<String, String> r, byte[] data) throws Exception {
    byte[] sk = Kem.keygen(r.get("alg"), h(r.get("kseed"))).sk();
    ByteArrayOutputStream o = new ByteArrayOutputStream();
    Box.unbox(r.get("alg"), sk, new ByteArrayInputStream(data), o, h(r.get("ctx")));
    return o.toByteArray();
  }

  static Code unboxFails(Map<String, String> r, byte[] data) {
    try {
      unboxed(r, data);
    } catch (NoqtisException e) {
      return e.kind();
    } catch (Exception e) {
      throw new AssertionError(e);
    }
    throw new AssertionError("no exception");
  }

  static void box() throws Exception {
    List<Map<String, String>> v = kv("kseal/kat.txt");
    for (var r : v) {
      byte[] sk = Kem.keygen(r.get("alg"), h(r.get("kseed"))).sk();
      ok(Arrays.equals(Kem.open(r.get("alg"), sk, h(r.get("out")), h(r.get("ctx"))), h(r.get("msg"))), "kseal");
    }
    var r = v.get(v.size() - 1);
    Sign.KeyPair k = Kem.keygen(r.get("alg"), h(r.get("kseed")));
    byte[] out = h(r.get("out"));
    out[30] ^= 1;
    eq(fails(() -> Kem.open(r.get("alg"), k.sk(), out, h(r.get("ctx")))), Code.VERIFY, "changed");
    eq(fails(() -> Kem.open(r.get("alg"), k.sk(), Arrays.copyOf(out, 10), null)), Code.DECODE, "short");
    byte[] c = Kem.seal(r.get("alg"), k.pk(), b("round"), b("x"));
    eq(new String(Kem.open(r.get("alg"), k.sk(), c, b("x"))), "round", "round trip");
    eq(fails(() -> Kem.open(r.get("alg"), k.sk(), c, b("y"))), Code.VERIFY, "other ctx");
    Map<String, String> big = null;
    for (var s : kv("kstream/kat.txt")) {
      ok(Arrays.equals(unboxed(s, h(s.get("out"))), h(s.get("msg"))), "kstream");
      if (big == null || s.get("out").length() > big.get("out").length()) {
        big = s;
      }
    }
    byte[] o = h(big.get("out"));
    int hl = 17 + Noqtis.alg(big.get("alg")).ct(), n = Integer.parseInt(big.get("chunk")) + 16;
    byte[] ch = o.clone();
    ch[hl + 5] ^= 1;
    eq(unboxFails(big, ch), Code.VERIFY, "changed chunk");
    eq(unboxFails(big, Arrays.copyOf(o, o.length - 3)), Code.VERIFY, "cut inside");
    int last = hl + ((o.length - hl - 1) / n) * n;
    eq(unboxFails(big, Arrays.copyOf(o, last)), Code.VERIFY, "cut at a chunk");
    byte[] sw = o.clone();
    System.arraycopy(o, hl, sw, hl + n, n);
    System.arraycopy(o, hl + n, sw, hl, n);
    eq(unboxFails(big, sw), Code.VERIFY, "swapped");
    eq(unboxFails(big, Arrays.copyOf(o, o.length + 1)), Code.VERIFY, "extended");
    Sign.KeyPair kp = Kem.keygen("ML-KEM-768");
    for (int m : new int[] {0, 1, 1023, 1024, 1025, 4096, 5000}) {
      byte[] p = new byte[m];
      for (int i = 0; i < m; i++) {
        p[i] = (byte) (i % 251);
      }
      ByteArrayOutputStream e = new ByteArrayOutputStream(), d = new ByteArrayOutputStream();
      Box.box("ML-KEM-768", kp.pk(), new ByteArrayInputStream(p), e, b("ctx"), 1024);
      Box.unbox("ML-KEM-768", kp.sk(), new ByteArrayInputStream(e.toByteArray()), d, b("ctx"));
      ok(Arrays.equals(d.toByteArray(), p), "round trip " + m);
    }
    eq(fails(() -> new Box.Sealer("ML-KEM-768", kp.pk(), null, 100)), Code.ARG, "small chunk");
  }

  static void mu() throws Exception {
    for (var r : kv("acvp/mu.txt")) {
      byte[] k = h(r.get("key")), mu = h(r.get("mu")), sig = h(r.get("sig"));
      if (r.get("kind").equals("gen")) {
        ok(Arrays.equals(Sign.signmu(r.get("alg"), k, mu, Sign.Opts.none().withRnd(h(r.get("rnd")))), sig), "sigGen");
      } else {
        eq(Sign.verifymu(r.get("alg"), k, mu, sig), r.get("ok").equals("1"), "sigVer");
      }
    }
    Sign.KeyPair k = Sign.keygen("ML-DSA-65");
    Sign.Opts o = Sign.Opts.none().withCtx(b("c")).withDeterministic();
    byte[] mu = Sign.mu("ML-DSA-65", k.pk(), b("msg"), o);
    ok(Arrays.equals(Sign.signmu("ML-DSA-65", k.sk(), mu, o), Sign.sign("ML-DSA-65", k.sk(), b("msg"), o)), "signmu is sign");
    eq(fails(() -> Sign.mu("Ed25519", new byte[32], b("m"), null)), Code.UNSUPPORTED, "Ed25519");
    for (var r : kv("b2b/kat.txt")) {
      byte[] d = h(r.get("hash"));
      ok(Arrays.equals(Noqtis.blake2b(h(r.get("in")), h(r.get("key")), d.length), d), "blake2b");
    }
    eq(fails(() -> Noqtis.blake2b(new byte[0], null, 65)), Code.ARG, "65 bytes");
    List<Map<String, String>> a = new ArrayList<>(kv("argon2/rfc9106.txt"));
    a.addAll(kv("argon2/ossl.txt"));
    for (var r : a) {
      if (!r.get("y").equals("2")) {
        continue;
      }
      byte[] t = h(r.get("tag"));
      byte[] got =
          Noqtis.argon2id(
              h(r.get("pw")), h(r.get("salt")), Integer.parseInt(r.get("t")),
              Integer.parseInt(r.get("m")), Integer.parseInt(r.get("p")), t.length,
              h(r.get("key")), h(r.get("ad")));
      ok(Arrays.equals(got, t), "argon2id");
    }
    ok(Noqtis.cteq(b("abc"), b("abc")) && !Noqtis.cteq(b("abc"), b("abd")) && !Noqtis.cteq(b("a"), b("ab")), "cteq");
  }
}
