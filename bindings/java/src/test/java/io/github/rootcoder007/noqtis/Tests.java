// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
package io.github.rootcoder007.noqtis;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The binding against known answers (NIST ACVP, RFC 8032, RFC 4231, the
 * repository's golden capsule) and round trips of every algorithm. A
 * plain runner (no JUnit, so the build needs no downloads): exit status 0
 * when every test passed. The repository is the system property
 * noqtis.repo, else ../..
 */
public final class Tests {
  private Tests() {}

  static final HexFormat HEX = HexFormat.of();
  static final Path REPO = Path.of(System.getProperty("noqtis.repo", "../.."));

  static void ok(boolean c, String what) {
    if (!c) {
      throw new AssertionError(what);
    }
  }

  static void eq(Object a, Object b, String what) {
    if (!a.equals(b)) {
      throw new AssertionError(what + ": " + a + " != " + b);
    }
  }

  static NoqtisException.Code fails(Runnable r) {
    try {
      r.run();
    } catch (NoqtisException e) {
      ok(e.getMessage().startsWith("noqtis: ") && !e.nqerr().isEmpty(), "message " + e);
      return e.kind();
    }
    throw new AssertionError("no exception");
  }

  static byte[] b(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  static String sha256(byte[] x) {
    return HEX.formatHex(Noqtis.hash("SHA-256", x));
  }

  static final List<Path> TMP = new java.util.ArrayList<>();

  static Path mk(String p) throws Exception {
    Path d = Files.createTempDirectory(p);
    TMP.add(d);
    return d;
  }

  static void rmtree(Path d) throws Exception {
    try (var w = Files.walk(d)) {
      for (Path p : w.sorted(java.util.Comparator.reverseOrder()).toList()) {
        Files.delete(p);
      }
    }
  }

  static Path tmp() throws Exception {
    Path d = mk("nqjava");
    Files.createDirectories(d.resolve("data"));
    Files.writeString(d.resolve("a.txt"), "hello\n");
    Files.writeString(d.resolve("data/b.csv"), "x,y\n1,2\n");
    return d;
  }

  static void table() {
    eq(Noqtis.version(), "0.1.2", "version");
    long s = Noqtis.algs().stream().filter(a -> a.kind().equals("sign")).count();
    long k = Noqtis.algs().stream().filter(a -> a.kind().equals("kem")).count();
    ok(s == 19 && k == 6, s + " and " + k + " algorithms");
    Noqtis.Alg a = Noqtis.alg("ml-dsa-44");
    eq(a, new Noqtis.Alg("ML-DSA-44", "sign", a.id(), 1312, 2560, 2420, 0, 0), "ML-DSA-44");
    a = Noqtis.alg("ML-KEM-768");
    ok(a.pk() == 1184 && a.sk() == 2400 && a.ct() == 1088 && a.ss() == 32, "ML-KEM-768");
    eq(Noqtis.hashes().size(), 12, "hashes");
    eq(fails(() -> Noqtis.alg("nope")), NoqtisException.Code.UNSUPPORTED, "unknown");
  }

  static void hashes() {
    String abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    eq(HEX.formatHex(Noqtis.hash("SHA-256", b("abc"))), abc, "SHA-256");
    eq(HEX.formatHex(Noqtis.hash("sha256", b("abc"))), abc, "sha256");
    eq(
        HEX.formatHex(Noqtis.hash("SHA3-256", b("abc"))),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        "SHA3-256");
    eq(
        HEX.formatHex(Noqtis.hash("SHAKE128", new byte[0])),
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        "SHAKE128");
    eq(Noqtis.hash("shake_256", b("x"), 100).length, 100, "SHAKE256 n");
    eq(fails(() -> Noqtis.hash("SHA-256", b("x"), 5)), NoqtisException.Code.ARG, "fixed n");
    // RFC 4231 test case 2
    eq(
        HEX.formatHex(Noqtis.hmac("SHA-256", b("Jefe"), b("what do ya want for nothing?"))),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "HMAC");
    eq(fails(() -> Noqtis.hash("MD5", new byte[0])), NoqtisException.Code.UNSUPPORTED, "MD5");
    byte[] r = Noqtis.random(32);
    ok(r.length == 32 && !Arrays.equals(r, Noqtis.random(32)), "random");
  }

  static void signKats() {
    // ACVP ML-DSA-keyGen-FIPS204, tcId 1 (digests of the expected keys)
    Sign.KeyPair k =
        Sign.keygen(
            "ML-DSA-44",
            HEX.parseHex("7194b13c95231010afd2c909992bd2003ba6f437c3886bdbe3f6b867a14ba161"));
    eq(sha256(k.pk()), "838b88b6ac41e2c60698173e08ca173d0b0d2839205806e56a8a3d53195f3a03", "pk");
    eq(sha256(k.sk()), "1c911d163cd0a5563e06f22403f7e16334fee17c2abb66f11ddf39ca6307ec58", "sk");
    // ACVP SLH-DSA-keyGen-FIPS205, tcId 21
    k =
        Sign.keygen(
            "SLH-DSA-SHA2-128f",
            HEX.parseHex(
                "c42bcb3b5a6f331f5cce899253c6d9e29ff2b7ead7a04bab1794db8cc659c3b4"
                    + "a868f1bd5debc12d4c9fad66aabd0a94"));
    eq(
        HEX.formatHex(k.pk()),
        "a868f1bd5debc12d4c9fad66aabd0a94b546df247be4c457f3d467cdfcfabd39",
        "SLH-DSA pk");
    // RFC 8032 section 7.1, test 1
    k =
        Sign.keygen(
            "Ed25519",
            HEX.parseHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    eq(
        HEX.formatHex(k.pk()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "Ed25519 pk");
    byte[] s = Sign.sign("Ed25519", k.sk(), new byte[0]);
    eq(
        HEX.formatHex(s),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065"
            + "224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24"
            + "655141438e7a100b",
        "Ed25519 sig");
    ok(Sign.verify("Ed25519", k.pk(), new byte[0], s), "Ed25519 verify");
  }

  static void signRoundTrips() {
    for (Noqtis.Alg a : Noqtis.algs()) {
      if (!a.kind().equals("sign") || a.name().endsWith("s")) {
        continue; // SLH-DSA "s" signs slowly; see signSlow
      }
      String n = a.name();
      Sign.KeyPair k = Sign.keygen(n);
      ok(k.pk().length == a.pk() && k.sk().length == a.sk(), n + " sizes");
      Sign.Opts o = Sign.Opts.none().withCtx(b("c"));
      byte[] m = b("noqtis java " + n);
      byte[] s = Sign.sign(n, k.sk(), m, o);
      ok(s.length == a.sig() && Sign.verify(n, k.pk(), m, s, o), n + " round trip");
      ok(!Sign.verify(n, k.pk(), b("other"), s, o), n + " other message");
      ok(!Sign.verify(n, k.pk(), m, s), n + " other context");
      byte[] bad = s.clone();
      bad[bad.length / 2] ^= 1;
      ok(!Sign.verify(n, k.pk(), m, bad, o), n + " bad signature");
      ok(!Sign.verify(n, k.pk(), m, Arrays.copyOf(s, s.length - 1), o), n + " short");
      Sign.Opts d = Sign.Opts.none().withDeterministic();
      byte[] d1 = Sign.sign(n, k.sk(), m, d);
      ok(Arrays.equals(d1, Sign.sign(n, k.sk(), m, d)), n + " deterministic");
      byte[] z = new byte[Sign.rndlen(n)];
      ok(Arrays.equals(d1, Sign.sign(n, k.sk(), m, Sign.Opts.none().withRnd(z))), n + " rnd");
      int sl = 3 * z.length;
      if (n.endsWith("+Ed25519")) {
        sl = 64;
      } else if (n.startsWith("ML-DSA") || n.equals("Ed25519")) {
        sl = 32;
      }
      byte[] seed = new byte[sl];
      for (int i = 0; i < sl; i++) {
        seed[i] = (byte) i;
      }
      ok(Arrays.equals(Sign.keygen(n, seed).pk(), Sign.keygen(n, seed).pk()), n + " seeded");
      byte[] sh = Arrays.copyOf(seed, sl - 1);
      fails(() -> Sign.keygen(n, sh));
    }
  }

  static void signSlow() {
    String n = "SLH-DSA-SHAKE-128s";
    byte[] seed = new byte[48];
    Arrays.fill(seed, (byte) 7);
    Sign.KeyPair k = Sign.keygen(n, seed);
    byte[] s = Sign.sign(n, k.sk(), b("m"), Sign.Opts.none().withDeterministic());
    ok(Sign.verify(n, k.pk(), b("m"), s), n);
  }

  static void prehashAndErrors() {
    for (String n : List.of("ML-DSA-44", "SLH-DSA-SHA2-128f", "Ed25519")) {
      Sign.KeyPair k = Sign.keygen(n);
      for (String h : List.of("SHA-256", "SHA-512", "SHAKE128")) {
        Sign.Opts o = Sign.Opts.none().withPrehash(h);
        byte[] s;
        try {
          s = Sign.sign(n, k.sk(), b("m"), o);
        } catch (NoqtisException e) {
          // Ed25519ph is SHA-512 alone
          ok(n.equals("Ed25519") && !h.equals("SHA-512"), n + " " + h + ": " + e);
          continue;
        }
        ok(Sign.verify(n, k.pk(), b("m"), s, o), n + " " + h);
        ok(!Sign.verify(n, k.pk(), b("m"), s), n + " " + h + " pure");
      }
    }
    Sign.KeyPair k = Sign.keygen("ML-DSA-44");
    Sign.Opts lng = Sign.Opts.none().withCtx(new byte[256]);
    try {
      Sign.sign("ML-DSA-44", k.sk(), b("m"), lng);
      throw new AssertionError("a 256-byte context");
    } catch (NoqtisException e) {
      ok(e.code() == -1 && e.kind() == NoqtisException.Code.ARG, "code " + e.code());
      eq(e.nqerr(), NoqtisException.errmsg(-1), "nqerr");
    }
    byte[] pk1 = Arrays.copyOf(k.pk(), k.pk().length - 1);
    eq(fails(() -> Sign.verify("ML-DSA-44", pk1, b("m"), b("s"))), NoqtisException.Code.DECODE, "pk");
    eq(fails(() -> Sign.sign("ML-KEM-768", k.sk(), b("m"))), NoqtisException.Code.UNSUPPORTED, "kem");
    Sign.Opts both = Sign.Opts.none().withDeterministic().withRnd(new byte[32]);
    eq(fails(() -> Sign.sign("ML-DSA-44", k.sk(), b("m"), both)), NoqtisException.Code.ARG, "both");
  }

  static void kem() {
    // ACVP ML-KEM-keyGen-FIPS203, tcId 26 (digests of the expected keys)
    Sign.KeyPair k =
        Kem.keygen(
            "ML-KEM-768",
            HEX.parseHex(
                "e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a0"
                    + "1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0"));
    eq(sha256(k.pk()), "4158f6afb5e516c99f1da07da8c651348422b17c1f4e9a08ad73fb1f91249b3e", "ek");
    eq(sha256(k.sk()), "7aab35839207f72b310abe36e2daa1cc7ff6f7fa8941e439967cd47d9b437079", "dk");
    byte[] m = new byte[32];
    Arrays.fill(m, (byte) 1);
    Kem.Encap e1 = Kem.encap("ML-KEM-768", k.pk(), m), e2 = Kem.encap("ML-KEM-768", k.pk(), m);
    ok(Arrays.equals(e1.ct(), e2.ct()) && Arrays.equals(e1.ss(), e2.ss()), "seeded encap");
    ok(Arrays.equals(Kem.decap("ML-KEM-768", k.sk(), e1.ct()), e1.ss()), "seeded decap");
    for (Noqtis.Alg a : Noqtis.algs()) {
      if (!a.kind().equals("kem")) {
        continue;
      }
      String n = a.name();
      Sign.KeyPair p = Kem.keygen(n);
      Kem.Encap e = Kem.encap(n, p.pk());
      ok(e.ct().length == a.ct() && e.ss().length == a.ss(), n + " sizes");
      ok(Arrays.equals(Kem.decap(n, p.sk(), e.ct()), e.ss()), n + " round trip");
      byte[] bad = e.ct().clone();
      bad[0] ^= 1;
      byte[] r = Kem.decap(n, p.sk(), bad);
      ok(!Arrays.equals(r, e.ss()) && Arrays.equals(r, Kem.decap(n, p.sk(), bad)), n + " reject");
      byte[] ct1 = Arrays.copyOf(e.ct(), e.ct().length - 1);
      fails(() -> Kem.decap(n, p.sk(), ct1));
      byte[] pk1 = Arrays.copyOf(p.pk(), p.pk().length - 1);
      fails(() -> Kem.encap(n, pk1));
    }
  }

  static void golden() throws Exception {
    Path g = REPO.resolve("tests/vectors/cap/sample");
    if (!Files.isRegularFile(g.resolve("noqtis.sig"))) {
      System.out.println("  skipped: no tests/vectors/cap/sample here");
      return;
    }
    Path d = mk("nqgold");
    for (String f :
        List.of("a.txt", "empty", "data/b.csv", "data/deep/c.bin", "noqtis.json", "noqtis.sig")) {
      Files.createDirectories(d.resolve(f).getParent());
      Files.copy(g.resolve(f), d.resolve(f));
    }
    // tests/tcap.c: the ML-DSA-44 key from the seed 0, 1, ..., 31
    byte[] seed = new byte[32];
    for (int i = 0; i < 32; i++) {
      seed[i] = (byte) i;
    }
    byte[] pk = Sign.keygen("ML-DSA-44", seed).pk();
    Capsule.Opts o = Capsule.Opts.none().withTrust(pk);
    Capsule.Report r = Capsule.check(d, o);
    ok(r.ok(), r.toString());
    ok(r.toString().contains("data/deep/c.bin"), "file row");
    ok(Capsule.check(d).ok(), "the seal's own key");
    eq(
        HEX.formatHex(Capsule.capid(d)),
        "0b79bb292652444787adf22b993d9926f2a9fa29a2107a18e7a56941592ee25c",
        "capid");
    Capsule.Report i = Capsule.inspect(d);
    Map<String, String> want = new LinkedHashMap<>();
    want.put("info.alg", "ML-DSA-44");
    want.put("info.files", "4");
    want.put("info.format", "noqtis-capsule-1");
    for (var w : want.entrySet()) {
      eq(i.get(w.getKey()).orElseThrow().detail(), w.getValue(), w.getKey());
    }
    eq(
        Capsule.files(d).rows().stream().filter(x -> x.check().equals("info.file")).count(),
        4L,
        "info.file rows");
    Capsule.Report r2 = Capsule.check(d, Capsule.Opts.none().withTrust(Sign.keygen("ML-DSA-44").pk()));
    ok(!r2.ok() && r2.code() == -3, "another key");
    Files.writeString(d.resolve("a.txt"), "other\n");
    r = Capsule.check(d, o);
    ok(!r.ok() && r.failed().stream().anyMatch(x -> (x.check() + x.detail()).contains("a.txt")), "changed");
  }

  static void sealAndCheck() throws Exception {
    Path d = tmp();
    Sign.KeyPair k = Sign.keygen("ML-DSA-65");
    Capsule.seal(d, "ML-DSA-65", k.sk(), k.pk(), "{\"project\":\"java\"}");
    Capsule.Opts o = Capsule.Opts.none().withTrust(k.pk());
    ok(Capsule.check(d, o).ok(), "sealed");
    eq(Capsule.inspect(d).get("info.meta").orElseThrow().detail(), "{\"project\":\"java\"}", "meta");
    ok(Capsule.check(d, o.withOnly(List.of("a.txt"))).toString().contains("partial"), "only");
    Files.writeString(d.resolve("new.txt"), "x");
    ok(!Capsule.check(d, o).ok(), "an added file");
    fails(() -> Capsule.seal(d, "ML-DSA-65", k.sk(), k.pk(), "[1]"));
    eq(
        fails(() -> Capsule.seal(d, "ML-KEM-512", k.sk(), k.pk(), null)),
        NoqtisException.Code.UNSUPPORTED,
        "kem seal");
    try {
      ok(!Capsule.check(d.resolve("nope"), o).ok(), "a missing folder");
    } catch (NoqtisException e) {
      // no report at all is fine too
    }
  }

  static void seal2() throws Exception {
    Sign.KeyPair k = Sign.keygen("ML-DSA-44");
    Path a = tmp(), b = tmp(), c = tmp();
    Capsule.seal2(a, "ML-DSA-44", k.sk(), k.pk(), null, List.of());
    byte[] id = Capsule.capid(a);
    Capsule.seal2(b, "ML-DSA-44", k.sk(), k.pk(), "{\"step\":2}", List.of(new Capsule.Input(id, "raw")));
    Capsule.Report r = Capsule.check(b, Capsule.Opts.none().withTrust(k.pk()).withLineage(List.of(a)));
    ok(r.ok() && r.get("lineage").isPresent(), r.toString());
    eq(Capsule.inspect(b).get("info.format").orElseThrow().detail(), "noqtis-capsule-2", "format");
    byte[] pf = Capsule.prove(b, List.of("data/b.csv"));
    ok(pf.length > 0 && pf[0] == '{', "proof");
    Capsule.Opts o = Capsule.Opts.none().withTrust(k.pk());
    ok(Capsule.checkProof(pf, o, null).ok(), "proof alone");
    ok(Capsule.checkProof(pf, o, b).ok(), "proof with files");
    byte[] bad = pf.clone();
    bad[bad.length / 2] = (byte) (bad[bad.length / 2] == '0' ? '1' : '0');
    try {
      ok(!Capsule.checkProof(bad, o, null).ok(), "a changed proof");
    } catch (NoqtisException e) {
      // refused outright is fine too
    }
    Capsule.seal(c, "ML-DSA-44", k.sk(), k.pk(), null);
    eq(fails(() -> Capsule.prove(c, List.of("a.txt"))), NoqtisException.Code.UNSUPPORTED, "f1");
    eq(fails(() -> Capsule.prove(b, List.of("nope"))), NoqtisException.Code.IO, "unlisted");
  }

  static void keyFiles() throws Exception {
    Sign.KeyPair k = Sign.keygen("ML-DSA-44");
    String t = KeyFile.encode("ml-dsa-44", "pub", k.pk());
    ok(t.startsWith("noqtis-key-1 ML-DSA-44 pub\n"), "header");
    ok(t.lines().skip(1).allMatch(l -> l.length() <= 64), "64 per line");
    KeyFile.Key x = KeyFile.decode(b(t));
    ok(x.alg().equals("ML-DSA-44") && x.kind().equals("pub") && Arrays.equals(x.key(), k.pk()), "decode");
    ok(Arrays.equals(KeyFile.decode(b(t.replace("\n", "\r\n"))).key(), k.pk()), "CRLF");
    for (String bad :
        List.of(
            t.replace("noqtis-key-1", "noqtis-key-2"),
            t.replace(" pub\n", " pub \n"),
            t.replace(" pub\n", " both\n"),
            t.substring(0, t.length() - 10) + "\n",
            t.replaceFirst("A", " "),
            "")) {
      fails(() -> KeyFile.decode(b(bad)));
    }
    // a non-zero bit under the padding
    String et = KeyFile.encode("Ed25519", "pub", Sign.keygen("Ed25519").pk());
    String line = et.split("\n")[1];
    String al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int v = al.indexOf(line.charAt(line.length() - 2));
    ok(v % 4 == 0, line);
    String l2 = line.substring(0, line.length() - 2) + al.charAt(v + 1) + "=";
    fails(() -> KeyFile.decode(b(et.replace(line, l2))));
    eq(fails(() -> KeyFile.encode("ML-DSA-44", "pub", k.sk())), NoqtisException.Code.ARG, "size");
    eq(fails(() -> KeyFile.encode("nope", "pub", k.pk())), NoqtisException.Code.UNSUPPORTED, "alg");
    // a file the CLI wrote
    Path p = REPO.resolve("tests/vectors/interop/bl/mldsa.pub");
    if (Files.isRegularFile(p)) {
      KeyFile.Key c = KeyFile.read(p, "pub");
      eq(c.alg(), "ML-DSA-65", "CLI key alg");
      eq(KeyFile.encode(c.alg(), "pub", c.key()), Files.readString(p), "CLI key text");
      eq(fails(() -> KeyFile.read(p, "sec")), NoqtisException.Code.ARG, "kind");
    }
    Path d = mk("nqkeys");
    Path f = d.resolve("me");
    KeyFile.write(f, "ML-DSA-44", "sec", k.sk(), false);
    eq(fails(() -> KeyFile.write(f, "ML-DSA-44", "sec", k.sk(), false)), NoqtisException.Code.IO, "exists");
    KeyFile.write(f, "ML-DSA-44", "sec", k.sk(), true);
    ok(Arrays.equals(KeyFile.read(f, null).key(), k.sk()), "read back");
    if (f.getFileSystem().supportedFileAttributeViews().contains("posix")) {
      eq(PosixFilePermissions.toString(Files.getPosixFilePermissions(f)), "rw-------", "mode");
    }
    eq(fails(() -> KeyFile.read(d.resolve("nope"), null)), NoqtisException.Code.IO, "missing");
  }

  interface T {
    void run() throws Exception;
  }

  public static void main(String[] args) {
    Map<String, T> ts = new LinkedHashMap<>();
    ts.put("table", Tests::table);
    ts.put("hashes", Tests::hashes);
    ts.put("signKats", Tests::signKats);
    ts.put("signRoundTrips", Tests::signRoundTrips);
    ts.put("signSlow", Tests::signSlow);
    ts.put("prehashAndErrors", Tests::prehashAndErrors);
    ts.put("kem", Tests::kem);
    ts.put("golden", Tests::golden);
    ts.put("sealAndCheck", Tests::sealAndCheck);
    ts.put("seal2", Tests::seal2);
    ts.put("keyFiles", Tests::keyFiles);
    int bad = 0;
    for (var e : ts.entrySet()) {
      long t0 = System.nanoTime();
      try {
        e.getValue().run();
        System.out.printf("ok   %s (%d ms)%n", e.getKey(), (System.nanoTime() - t0) / 1000000);
      } catch (Throwable x) {
        bad++;
        System.out.printf("FAIL %s: %s%n", e.getKey(), x);
        x.printStackTrace(System.out);
      }
    }
    for (Path d : TMP) {
      try {
        rmtree(d);
      } catch (Exception x) {
        System.out.println("cannot remove " + d + ": " + x);
      }
    }
    System.out.printf("%d of %d passed%n", ts.size() - bad, ts.size());
    System.exit(bad == 0 ? 0 : 1);
  }
}
