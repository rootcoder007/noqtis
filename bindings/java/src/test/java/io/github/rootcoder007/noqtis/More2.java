// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
package io.github.rootcoder007.noqtis;

import static io.github.rootcoder007.noqtis.Tests.REPO;
import static io.github.rootcoder007.noqtis.Tests.b;
import static io.github.rootcoder007.noqtis.Tests.eq;
import static io.github.rootcoder007.noqtis.Tests.fails;
import static io.github.rootcoder007.noqtis.Tests.mk;
import static io.github.rootcoder007.noqtis.Tests.ok;

import io.github.rootcoder007.noqtis.NoqtisException.Code;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The rest of the capsule and data functions: sealWhy, the timestamp
 * requests, key statements, DSSE, bundles, chains, the environment,
 * commitments, citation, report, synthetic data, calibration and chunk
 * digests, on tests/vectors/nqd.
 */
final class More2 {
  private More2() {}

  static Path cap() throws Exception {
    Path v = REPO.resolve("tests/vectors/nqd/cap/data"), d = mk("nqjq").resolve("c");
    Files.createDirectories(d.resolve("data"));
    for (String f : new String[] {"a.csv", "b.csv"}) {
      Files.copy(v.resolve(f), d.resolve("data").resolve(f));
    }
    Data.add(d, List.of("data/a.csv", "data/b.csv"), Data.Src.none());
    return d;
  }

  static void capsule() throws Exception {
    Path d = mk("nqjwhy");
    Files.writeString(d.resolve("a"), "a");
    ok(Capsule.sealWhy(d).isEmpty(), "nothing in the way");
    Sign.KeyPair k = Sign.keygen("ML-DSA-44");
    if (!System.getProperty("os.name", "").startsWith("Windows")) {
      Files.createSymbolicLink(d.resolve("l"), Path.of("a"));
      eq(fails(() -> Capsule.seal(d, "ML-DSA-44", k.sk(), k.pk(), null)), Code.ARG, "a link");
      eq(Capsule.sealWhy(d).get(), new Capsule.Why("link", "l"), "why");
      Files.delete(d.resolve("l"));
    }
    Capsule.seal(d, "ML-DSA-44", k.sk(), k.pk(), null);
    byte[] q = Capsule.tsreq(d, new byte[] {1, 2});
    ok(q[0] == 0x30 && !Arrays.equals(q, Capsule.tsreq(d, null)), "tsreq");
    ok(Capsule.ersreq(d, null, null)[0] == 0x30, "ersreq");
    fails(() -> Capsule.tsput(d, new byte[] {0x30, 0}, null, null));
    fails(() -> Capsule.ersput(d, null, new byte[] {0x30, 0}, null, null));
    Sign.KeyPair n = Sign.keygen("ML-DSA-65");
    byte[] r = Capsule.rotate("ML-DSA-44", k.sk(), k.pk(), "ML-DSA-65", n.sk(), n.pk(), 1800000000L, "new key");
    ok(new String(r).contains("noqtis-keys-1"), "rotate");
    ok(new String(Capsule.revoke("ML-DSA-44", k.sk(), k.pk(), 1800000000L, null)).contains("noqtis-keys-1"), "revoke");
    eq(fails(() -> Capsule.revoke("ML-DSA-44", k.sk(), n.pk(), 0, null)), Code.ARG, "not a pair");
    ok(new String(Capsule.expire("ML-DSA-44", k.sk(), k.pk(), 1800000000L, "yearly")).contains("\"kind\":\"expire\""), "expire");
    eq(fails(() -> Capsule.expire("ML-DSA-44", k.sk(), n.pk(), 0, null)), Code.ARG, "expire, not a pair");
    byte[] e = Dsse.sign("ML-DSA-44", k.sk(), k.pk(), "text/plain", b("hello"));
    var p = Dsse.verify("ML-DSA-44", k.pk(), e).get();
    ok(p.type().equals("text/plain") && new String(p.payload()).equals("hello"), "dsse");
    ok(Dsse.verify("ML-DSA-44", Sign.keygen("ML-DSA-44").pk(), e).isEmpty(), "another key");
    eq(fails(() -> Dsse.verify("ML-DSA-44", k.pk(), b("{}"))), Code.DECODE, "not an envelope");
  }

  static void bundle() throws Exception {
    Path c = cap(), w = mk("nqjpack");
    Sign.KeyPair k = Sign.keygen("ML-DSA-44");
    Capsule.seal(c, "ML-DSA-44", k.sk(), k.pk(), null);
    Data.pack(c, w.resolve("a.nqb"), true);
    Data.pack(c, w.resolve("b.nqb"), true);
    ok(Arrays.equals(Files.readAllBytes(w.resolve("a.nqb")), Files.readAllBytes(w.resolve("b.nqb"))), "deterministic");
    Capsule.Opts o = Capsule.Opts.none().withTrust(k.pk());
    ok(Data.checkPack(w.resolve("a.nqb"), o).ok(), "checkPack");
    Data.unpack(w.resolve("a.nqb"), w.resolve("u"));
    ok(Capsule.check(w.resolve("u"), o).ok(), "unpacked");
    eq(fails(() -> Data.unpack(w.resolve("a.nqb"), w.resolve("u"))), Code.IO, "over a folder");
    byte[] x = Files.readAllBytes(w.resolve("a.nqb"));
    Files.write(w.resolve("cut"), Arrays.copyOf(x, x.length - 10));
    eq(fails(() -> Data.unpack(w.resolve("cut"), w.resolve("v"))), Code.DECODE, "cut");
    ok(!Files.exists(w.resolve("v")), "nothing left");
    List<Path> ds = new ArrayList<>();
    for (int i = 0; i < 3; i++) {
      Path d = w.resolve("l" + i);
      Files.createDirectories(d);
      Files.writeString(d.resolve("log.txt"), "entry " + i + "\n");
      List<Capsule.Input> in =
          ds.isEmpty() ? List.of() : List.of(new Capsule.Input(Capsule.capid(ds.get(ds.size() - 1)), "prev"));
      Capsule.seal2(d, "ML-DSA-44", k.sk(), k.pk(), null, in);
      ds.add(d);
    }
    Data.Chain ch = Data.chain(ds, k.pk());
    ok(ch.report().ok() && Arrays.equals(ch.head(), Capsule.capid(ds.get(2))), "chain " + ch.report());
    ok(Data.chain(List.of(ds.get(0), ds.get(2)), k.pk()).head() == null, "a gap");
  }

  static void record() throws Exception {
    Path c = cap();
    Files.writeString(c.resolve("uv.lock"), "lock\n");
    String e = Data.env(c, "SplittableRandom", "42", null, List.of(new Data.Pkg("z", "1", "x"), new Data.Pkg("a", "2", "x")));
    ok(e.contains("\"language\":\"java\"") && e.contains("\"path\":\"uv.lock\"") && e.contains("\"seed\":\"42\""), e);
    ok(Data.text(c).contains("\"packages\":[{\"name\":\"a\""), "sorted packages");
    Data.env(c, null, null, null, null);
    ok(Data.check(c).ok(), "record after env");
    eq(fails(() -> Data.env(c, null, null, List.of("none.lock"), null)), Code.ARG, "missing lock");
    if (!System.getProperty("os.name").startsWith("Windows")) {
      // a lock file is read inside the folder, never through a link
      Path o = Files.createTempFile("nqlk", ".lock");
      Files.delete(c.resolve("uv.lock"));
      Files.createSymbolicLink(c.resolve("uv.lock"), o);
      eq(fails(() -> Data.env(c, null, null, null, null)), Code.ARG, "a lock file through a link");
      Files.delete(c.resolve("uv.lock"));
      Files.delete(o);
      Files.writeString(c.resolve("uv.lock"), "lock\n");
    }
    byte[] plan = b("arm A: 1, 4\n");
    byte[] s = Data.commit(c, plan, "randomisation", "trial", null);
    eq(Data.reveal(c, plan, s), 0, "reveal");
    eq(Data.reveal(c, b("x"), s), -1, "another file");
    ok(Data.text(c).contains(Data.commitment(s, plan)), "digest");
    eq(fails(() -> Data.commitment(b("short"), plan)), Code.ARG, "short salt");
    eq(fails(() -> Data.cite(c, false)), Code.IO, "no cite");
    Data.put(c, "cite", "{\"title\":\"T\",\"authors\":[\"A. Author\"],\"year\":2026,\"doi\":\"10.1234/x\"}");
    ok(Data.cite(c, false).contains("title: \"T\"") && Data.cite(c, true).contains("doi = {10.1234/x}"), "cite");
    Sign.KeyPair k = Sign.keygen("ML-DSA-44");
    Capsule.seal(c, "ML-DSA-44", k.sk(), k.pk(), null);
    String md = Data.report(c, k.pk(), false);
    ok(md.startsWith("#") && md.contains("data/a.csv"), "report");
    ok(Data.report(c, null, true).contains("data/a.csv"), "text report");
  }

  static void more() throws Exception {
    Path v = REPO.resolve("tests/vectors/nqd"), d = mk("nqjsyn");
    Files.createDirectories(d.resolve("data"));
    Data.put(d, "schemas", Files.readString(v.resolve("syn/schema.json")));
    Data.synth(d, "data/s.csv", 7, 16);
    ok(Arrays.equals(Files.readAllBytes(d.resolve("data/s.csv")), Files.readAllBytes(v.resolve("syn/s7.csv"))), "s7");
    Path c = cap();
    String s = Data.schema(c, "data/a.csv", null);
    ok(Data.checkSchema(c, s).ok() && !Data.checkSchema(c, s.replaceFirst("\"int\"", "\"bool\"")).ok(), "checkSchema");
    Data.put(c, "schemas", s);
    eq(fails(() -> Data.synth(c, "data/a.csv", 1, 0)), Code.ARG, "real data");
    Data.pin(c, List.of("data/a.csv"), null);
    ok(Data.calibrate(c, "data/a.csv", List.of(c.resolve("data/a.csv")), null).contains("\"cal\""), "calibrate");
    byte[] big = new byte[5000];
    for (int i = 0; i < big.length; i++) {
      big[i] = (byte) (i % 253);
    }
    Files.write(c.resolve("big.bin"), big);
    ok(Data.chunks(c, "big.bin", 1024).contains("\"size\":5000"), "chunks");
    Path p = mk("nqjpc").resolve("piece");
    Files.write(p, Arrays.copyOfRange(big, 2048, 5000));
    ok(Data.piece(c, "big.bin", p, 2048).ok(), "piece");
    byte[] bad = Arrays.copyOfRange(big, 2048, 5000);
    bad[1100] ^= 1;
    Files.write(p, bad);
    Data.Report r = Data.piece(c, "big.bin", p, 2048);
    ok(!r.ok() && r.rows().get(0).check().equals("chunk"), "changed piece");
    eq(fails(() -> Data.chunks(c, "big.bin", 10)), Code.ARG, "small chunk");
  }
}
