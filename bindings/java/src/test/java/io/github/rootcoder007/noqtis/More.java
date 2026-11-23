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
    // RFC 7914 section 11: "passwd", "salt", 1 iteration, 64 bytes
    byte[] pb =
        h("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
            + "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783");
    ok(Arrays.equals(Noqtis.pbkdf2("SHA-256", b("passwd"), b("salt"), 1, 64), pb), "pbkdf2");
    eq(fails(() -> Noqtis.pbkdf2("SHA-256", b("passwd"), b("salt"), 0, 64)), Code.ARG, "pbkdf2 0");
    // a secret key file under PBKDF2, as keygen --kdf pbkdf2 writes one
    byte[] kad = b("noqtis-key-1 ML-DSA-44 sec");
    byte[] pe = KeyFile.pwenc2(KeyFile.KDF_PBKDF2, b("pass"), sk, kad, 0, 100000, 0);
    ok(pe[5] == KeyFile.KDF_PBKDF2, "the KDF byte");
    ok(Arrays.equals(KeyFile.pwdec(b("pass"), pe, kad), sk), "pwenc2 round trip");
    String pt = "noqtis-key-1 ML-DSA-44 sec\n" + java.util.Base64.getMimeEncoder(64, b("\n"))
        .encodeToString(pe) + "\n";
    ok(Arrays.equals(KeyFile.decode(b(pt), "pass".toCharArray()).key(), sk), "PBKDF2 key file");
    eq(fails(() -> KeyFile.pwenc2(KeyFile.KDF_PBKDF2, b("pass"), sk, kad, 0, 99999, 0)), Code.ARG,
        "pwenc2 few iterations");
    eq(fails(() -> KeyFile.pwenc2(3, b("pass"), sk, kad, 0, 0, 0)), Code.ARG, "pwenc2 kdf");
    String t = KeyFile.encode("ML-DSA-44", "sec", sk, "pass".toCharArray());
    // a signature key: its version 2 container, under the passphrase
    byte[] sx = Sign.sxmake("ML-DSA-44", sk);
    ok(t.startsWith("noqtis-key-2 ML-DSA-44 sec\n"), "header");
    ok(Arrays.equals(KeyFile.decode(b(t), "pass".toCharArray()).key(), sx), "round trip");
    eq(fails(() -> KeyFile.decode(b(t))), Code.ARG, "no passphrase");
    try {
      KeyFile.decode(b(t), "nope".toCharArray());
      ok(false, "a wrong passphrase opened it");
    } catch (NoqtisException e) {
      ok(e.kind() == Code.VERIFY && !e.getMessage().contains("nope") && !e.getMessage().contains("pass"), "message " + e);
    }
    Path f = mk("nqjpw").resolve("k");
    KeyFile.write(f, "ML-DSA-44", "sec", sk, false, "pw".toCharArray());
    ok(Arrays.equals(KeyFile.read(f, "sec", "pw".toCharArray()).key(), sx), "file");
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
    boxto();
  }

  // a stream to several recipients, signed or not: each recipient opens
  // it, another key does not, and the sender's key decides
  static void boxto() throws Exception {
    String[] algs = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    Sign.KeyPair[] ks = new Sign.KeyPair[3];
    byte[][] pks = new byte[3][];
    for (int i = 0; i < 3; i++) {
      ks[i] = Kem.keygen(algs[i]);
      pks[i] = ks[i].pk();
    }
    Sign.KeyPair x = Kem.keygen("ML-KEM-768");
    Sign.KeyPair me = Sign.keygen("ML-DSA-44"), other = Sign.keygen("ML-DSA-44");
    for (int m : new int[] {0, 1, 1024, 1025, 5000}) {
      byte[] p = new byte[m];
      for (int i = 0; i < m; i++) {
        p[i] = (byte) (i % 249);
      }
      for (boolean signed : new boolean[] {false, true}) {
        ByteArrayOutputStream e = new ByteArrayOutputStream();
        Box.boxTo(
            algs, pks, signed ? "ML-DSA-44" : null, signed ? me.sk() : null,
            new ByteArrayInputStream(p), e, b("ctx"), 1024);
        byte[] s = e.toByteArray();
        ok(s[0] == 'N' && s[1] == 'Q' && s[2] == 'K' && s[3] == 'M', "the second format");
        for (int i = 0; i < 3; i++) {
          ByteArrayOutputStream d = new ByteArrayOutputStream();
          String name =
              Box.unboxFrom(
                  algs[i], ks[i].sk(), signed ? me.pk() : null, new ByteArrayInputStream(s), d,
                  b("ctx"));
          ok(Arrays.equals(d.toByteArray(), p), "boxTo round trip " + m + " " + algs[i]);
          ok(
              java.util.Objects.equals(name, signed ? "ML-DSA-44" : null),
              "the signature algorithm");
        }
        ByteArrayOutputStream d = new ByteArrayOutputStream();
        eq(
            fails(() -> unboxFrom("ML-KEM-768", x.sk(), null, s, d, b("ctx"))), Code.VERIFY,
            "not a recipient");
        eq(
            fails(() -> unboxFrom(algs[0], ks[0].sk(), null, s, d, null)), Code.VERIFY,
            "another context");
        eq(
            fails(() -> unboxFrom(algs[1], ks[1].sk(), other.pk(), s, d, b("ctx"))),
            Code.VERIFY, "another sender, or not signed");
        // not asked who sent it: it opens, signed or not
        Box.unboxFrom(algs[2], ks[2].sk(), null, new ByteArrayInputStream(s), d, b("ctx"));
        byte[] bad = s.clone();
        bad[bad.length - 3] ^= 1;
        eq(
            fails(() -> unboxFrom(algs[0], ks[0].sk(), null, bad, d, b("ctx"))), Code.VERIFY,
            "changed");
      }
    }
    ByteArrayOutputStream e = new ByteArrayOutputStream();
    eq(
        fails(() -> boxTo(new String[0], new byte[0][], null, null, e)), Code.ARG,
        "no recipient");
    eq(fails(() -> boxTo(algs, pks, "ML-DSA-44", null, e)), Code.ARG, "half a sender");
    eq(
        fails(() -> unboxFrom("ML-KEM-768", x.sk(), null, b("NQKM"), e, null)), Code.DECODE,
        "cut short");
    eq(
        fails(() -> unboxFrom("ML-KEM-768", x.sk(), null, new byte[40], e, null)),
        Code.DECODE, "not a stream");
  }

  private static void unboxFrom(
      String alg, byte[] sk, byte[] sender, byte[] s, ByteArrayOutputStream d, byte[] ctx) {
    try {
      Box.unboxFrom(alg, sk, sender, new ByteArrayInputStream(s), d, ctx);
    } catch (java.io.IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private static void boxTo(
      String[] algs, byte[][] pks, String sa, byte[] ssk, ByteArrayOutputStream e) {
    try {
      Box.boxTo(algs, pks, sa, ssk, new ByteArrayInputStream(new byte[1]), e, null, 0);
    } catch (java.io.IOException x) {
      throw new IllegalStateException(x);
    }
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
    // KangarooTwelve, ChaCha20, AES-SIV, AES-GCM-SIV: an answer of each RFC
    byte[] z = new byte[0];
    byte[] p17 = new byte[17];
    for (int i = 0; i < 17; i++) {
      p17[i] = (byte) i;
    }
    ok(Arrays.equals(Noqtis.kt128(z, null, 32), h("1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5")), "KT128 empty");
    ok(Arrays.equals(Noqtis.kt128(p17, null, 32), h("6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888")), "KT128 ptn(17)");
    ok(Arrays.equals(Noqtis.kt256(z, z, 32), h("b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404")), "KT256 empty");
    ok(!Arrays.equals(Noqtis.kt128(p17, b("a"), 32), Noqtis.kt128(p17, null, 32)), "KT customization");
    eq(fails(() -> Noqtis.kt128(new byte[0], null, 0)), Code.ARG, "KT 0 bytes");
    ok(Arrays.equals(Noqtis.chacha20(new byte[32], new byte[12], 0, new byte[32]),
        h("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7")), "ChaCha20");
    byte[] ck = Noqtis.kt128(b("key"), null, 32);
    byte[] cn = Noqtis.kt128(b("nonce"), null, 12);
    ok(Arrays.equals(Noqtis.chacha20(ck, cn, 7, Noqtis.chacha20(ck, cn, 7, b("a message"))), b("a message")), "ChaCha20 round trip");
    eq(fails(() -> Noqtis.chacha20(new byte[16], new byte[12], 0, new byte[4])), Code.ARG, "ChaCha20 key");
    eq(fails(() -> Noqtis.chacha20(new byte[32], new byte[12], 0xffffffffL, new byte[65])), Code.LIMIT, "ChaCha20 counter");
    byte[] sk = h("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    byte[] sad = h("101112131415161718191a1b1c1d1e1f2021222324252627");
    byte[] spt = h("112233445566778899aabbccddee");
    byte[] sout = h("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c");
    ok(Arrays.equals(Noqtis.sivenc(sk, new byte[][] {sad}, spt), sout), "AES-SIV RFC 5297");
    ok(Arrays.equals(Noqtis.sivdec(sk, new byte[][] {sad}, sout), spt), "AES-SIV decrypt");
    ok(!Arrays.equals(Noqtis.sivenc(sk, null, spt), sout), "AES-SIV strings");
    ok(Noqtis.sivdec(sk, null, Noqtis.sivenc(sk, null, new byte[0])).length == 0, "AES-SIV empty");
    eq(fails(() -> Noqtis.sivdec(sk, null, sout)), Code.VERIFY, "AES-SIV other strings");
    eq(fails(() -> Noqtis.sivenc(new byte[40], null, spt)), Code.ARG, "AES-SIV key");
    eq(fails(() -> Noqtis.sivdec(sk, null, new byte[5])), Code.ARG, "AES-SIV short");
    byte[] gk = h("01000000000000000000000000000000");
    byte[] gn = h("030000000000000000000000");
    byte[] gp = h("0100000000000000");
    byte[] go = h("b5d839330ac7b786578782fff6013b815b287c22493a364c");
    ok(Arrays.equals(Noqtis.gsivenc(gk, gn, null, gp), go), "AES-GCM-SIV RFC 8452");
    ok(Arrays.equals(Noqtis.gsivdec(gk, gn, null, go), gp), "AES-GCM-SIV decrypt");
    eq(fails(() -> Noqtis.gsivdec(gk, gn, b("x"), go)), Code.VERIFY, "AES-GCM-SIV other data");
    eq(fails(() -> Noqtis.gsivenc(new byte[24], gn, null, gp)), Code.ARG, "AES-GCM-SIV key");
    eq(fails(() -> Noqtis.gsivdec(gk, gn, null, new byte[3])), Code.ARG, "AES-GCM-SIV short");
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
