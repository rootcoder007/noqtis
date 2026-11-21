// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
package io.github.rootcoder007.noqtis;

import static io.github.rootcoder007.noqtis.Tests.b;
import static io.github.rootcoder007.noqtis.Tests.eq;
import static io.github.rootcoder007.noqtis.Tests.fails;
import static io.github.rootcoder007.noqtis.Tests.mk;
import static io.github.rootcoder007.noqtis.Tests.ok;

import io.github.rootcoder007.noqtis.NoqtisException.Code;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

/**
 * Armor, certificates, CMS and S/MIME, OpenPGP, the key store, and (with
 * NQTOKPATH naming the software token of tests/p11) keys on a token.
 */
final class Extra {
  private Extra() {}

  static final Instant T0 = Instant.ofEpochSecond(1767225600L); // 2026-01-01T00:00:00Z
  static final Instant T1 = T0.plusSeconds(365L * 86400);

  static void armor() {
    byte[] data = b("some bytes \u0000\u0001 to carry as text");
    String a = Mail.armor("NOQTIS TEST", data);
    ok(a.startsWith("-----BEGIN NOQTIS TEST-----\n"), "armor begins");
    Mail.Armored r = Mail.dearmor(a);
    eq(r.label(), "NOQTIS TEST", "label");
    ok(Arrays.equals(r.data(), data), "data comes back");
    eq(fails(() -> Mail.dearmor("not armor")), Code.DECODE, "not armor");
    eq(fails(() -> Mail.armor("lower case", data)), Code.ARG, "a bad label");
  }

  static void mail() {
    Sign.KeyPair k = Sign.keygen("ML-DSA-44");
    byte[] cert =
        Mail.selfCert("ML-DSA-44", k.sk(), k.pk(), "Ada Example", "ada@example.org", T0, T1);
    Mail.Cert ci = Mail.readCert(cert);
    eq(ci.alg(), "ML-DSA-44", "cert alg");
    ok(!ci.kem() && ci.ca(), "a signature CA");
    eq(ci.name(), "Ada Example", "cert name");
    eq(ci.email(), "ada@example.org", "cert email");
    ok(Arrays.equals(ci.pk(), k.pk()), "cert key");
    eq(ci.notBefore(), T0, "cert from");
    Sign.KeyPair e = Kem.keygen("ML-KEM-768");
    byte[] kc = Mail.kemCert("ML-DSA-44", k.sk(), cert, "ML-KEM-768", e.pk(), T0, T1);
    Mail.Cert ki = Mail.readCert(kc);
    ok(ki.kem() && ki.alg().equals("ML-KEM-768") && ki.name().equals("Ada Example"), "KEM cert");
    byte[] msg = b("a message to sign and to seal");
    Instant at = T0.plusSeconds(3600);
    for (boolean det : new boolean[] {false, true}) {
      byte[] s = Mail.cmsSign("ML-DSA-44", k.sk(), cert, msg, det, at);
      byte[] m = det ? msg : null;
      Mail.Signed v = Mail.cmsVerify(s, m, List.of(cert), at);
      ok(Arrays.equals(v.content(), msg), "CMS content");
      eq(v.signer().name(), "Ada Example", "CMS signer");
      eq(fails(() -> Mail.cmsVerify(s, m, List.of(kc), at)), Code.VERIFY, "another anchor");
    }
    byte[] enc = Mail.cmsEncrypt(List.of(kc), msg);
    ok(Arrays.equals(Mail.cmsDecrypt("ML-KEM-768", e.sk(), kc, enc), msg), "CMS decrypt");
    Sign.KeyPair e2 = Kem.keygen("ML-KEM-768");
    eq(
        fails(() -> Mail.cmsDecrypt("ML-KEM-768", e2.sk(), null, enc)),
        Code.VERIFY,
        "another key");
    String ent = "Content-Type: text/plain\r\n\r\nhello, mail\r\n";
    String sm = Mail.smimeSign("ML-DSA-44", k.sk(), cert, ent, true, at);
    ok(sm.contains("multipart/signed") && sm.contains("hello, mail"), "S/MIME detached");
    Mail.SignedMail sv = Mail.smimeVerify(sm, List.of(cert), at);
    eq(sv.entity(), ent, "S/MIME entity");
    eq(sv.signer().email(), "ada@example.org", "S/MIME signer");
    String bad = sm.replaceFirst("hello", "jello");
    eq(fails(() -> Mail.smimeVerify(bad, List.of(cert), at)), Code.VERIFY, "a changed message");
    String se = Mail.smimeEncrypt(List.of(kc), ent);
    eq(Mail.smimeDecrypt("ML-KEM-768", e.sk(), kc, se), ent, "S/MIME decrypt");
  }

  static void pgp() {
    byte[] pw = b("a passphrase");
    Pgp.KeyPair k =
        Pgp.generate(Pgp.MLDSA65, Pgp.MLKEM768, "Ada Example <ada@example.org>", T0, pw);
    Pgp.Key f = Pgp.info(k.cert());
    ok(f.alg() == Pgp.MLDSA65 && f.encAlg() == Pgp.MLKEM768 && !f.secret(), "key algs");
    eq(f.userId(), "Ada Example <ada@example.org>", "user ID");
    eq(f.created(), T0, "created");
    ok(f.expires() == null && f.fingerprint().length() == 64, "no expiry");
    ok(f.encFingerprint() != null && f.encFingerprint().length() == 64, "subkey");
    Pgp.Key s = Pgp.info(k.secret());
    ok(s.secret() && s.locked(), "a locked secret key");
    String a = Pgp.armor(Pgp.PUBLICKEY, k.cert());
    ok(a.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"), "armor");
    Pgp.Armored d = Pgp.dearmor(a);
    ok(d.kind() == Pgp.PUBLICKEY && Arrays.equals(d.data(), k.cert()), "dearmor");
    byte[] msg = b("signed text\nof two lines\n");
    Instant at = T0.plusSeconds(60);
    for (int mode : new int[] {Pgp.INLINE, Pgp.DETACHED, Pgp.CLEAR}) {
      byte[] sig = Pgp.sign(k.secret(), pw, msg, mode, at);
      Pgp.Verified v = Pgp.verify(k.cert(), sig, mode == Pgp.DETACHED ? msg : null);
      eq(v.at(), at, "signature time");
      ok(mode == Pgp.CLEAR || Arrays.equals(v.data(), msg), "signed data");
    }
    eq(
        fails(() -> Pgp.sign(k.secret(), b("wrong"), msg, Pgp.INLINE, at)),
        Code.VERIFY,
        "a wrong passphrase");
    byte[] e = Pgp.encrypt(List.of(k.cert()), b("open sesame"), k.secret(), pw, msg, at);
    Pgp.Opened o = Pgp.decrypt(k.secret(), pw, k.cert(), e);
    ok(o.signed() && at.equals(o.at()) && Arrays.equals(o.data(), msg), "decrypt by key");
    o = Pgp.decrypt(null, b("open sesame"), null, e);
    ok(!o.signed() && o.at() == null && Arrays.equals(o.data(), msg), "decrypt by passphrase");
    eq(
        fails(() -> Pgp.decrypt(null, b("open sesam"), null, e)),
        Code.VERIFY,
        "a wrong message passphrase");
  }

  static void keystore() throws Exception {
    KeyStore ks = new KeyStore(mk("nqjks"));
    Sign.KeyPair me = Sign.keygen("ML-DSA-44");
    Sign.KeyPair mykem = Kem.keygen("ML-KEM-768");
    Sign.KeyPair bob = Kem.keygen("ML-KEM-768");
    byte[] card =
        IdCard.make(
            "ML-DSA-44",
            me.sk(),
            me.pk(),
            IdCard.Fields.of("Me Myself").withEmail("me@example.org"),
            T0);
    // my signature key by its card, my KEM key under the same name
    byte[] mine = ks.add("ML-DSA-44", me.pk(), null, null, card);
    byte[] own = ks.add("ML-KEM-768", mykem.pk(), "Me Myself", "me@example.org", null);
    byte[] his = ks.add("ML-KEM-768", bob.pk(), "Bob Other", "bob@example.org", null);
    ok(mine.length == 32 && ks.list(null).size() == 3, "three keys");
    List<KeyStore.Key> l = ks.list("bob@example.org");
    ok(l.size() == 1 && l.get(0).kem() && l.get(0).alg().equals("ML-KEM-768"), "found by address");
    eq(l.get(0).valid(), KeyStore.VALID_NONE, "not yet valid");
    KeyStore.Got g = ks.get(his);
    ok(g.alg().equals("ML-KEM-768") && Arrays.equals(g.pk(), bob.pk()), "get");
    ks.trust(mine, KeyStore.TRUST_ULTIMATE);
    ok(!ks.certify("ML-DSA-44", me.sk(), me.pk(), his, T0).isEmpty(), "certify");
    l = ks.list("bob@example.org");
    ok(l.get(0).valid() == KeyStore.VALID_FULL && l.get(0).certs() == 1, "valid once certified");
    ks.certify("ML-DSA-44", me.sk(), me.pk(), own, T0);
    // a bundle carries my card and my KEM key to another store
    String bundle = ks.export(mine);
    eq(fails(() -> ks.export(his)), Code.ARG, "a key without a card has no bundle");
    KeyStore other = new KeyStore(mk("nqjks2"));
    KeyStore.Imported im = other.imports(bundle, "me@example.org");
    ok(im.keys() == 2 && Arrays.equals(im.fingerprint(), mine), "import");
    ok(fails(() -> other.imports(bundle, "eve@example.org")) != null, "another address");
    ks.delete(his);
    eq(ks.list(null).size(), 2, "after delete");
    eq(fails(() -> ks.trust(new byte[5], KeyStore.TRUST_FULL)), Code.ARG, "a short fingerprint");
    ok(
        KeyStore.url("Ada@Example.org").startsWith("https://example.org/.well-known/noqtis/"),
        "url");
    eq(fails(() -> KeyStore.url("no address")), Code.ARG, "no address");
  }

  static void token() {
    eq(fails(() -> Token.open(Path.of("nqtok"))), Code.ARG, "a bare module name");
    eq(fails(() -> Token.open(Path.of("./no/such/module.so"))), Code.IO, "a missing module");
    String mod = System.getenv("NQTOKPATH");
    if (mod == null || mod.isEmpty()) {
      return; // the software token is not built
    }
    try (Token t = Token.open(Path.of(mod))) {
      List<Token.Info> ts = t.tokens();
      ok(ts.size() == 1 && ts.get(0).label().equals("noqtis test token"), "the token");
      ok(ts.get(0).login(), "needs the PIN");
      long slot = ts.get(0).slot();
      eq(fails(() -> t.login(slot, "0000")), Code.VERIFY, "a wrong PIN");
      t.login(slot, "1234");
      Token.Key k = t.generate("ML-DSA-65", "java-sig");
      ok(k.alg().equals("ML-DSA-65") && !k.kem() && k.label().equals("java-sig"), "a new key");
      byte[] pk = t.publicKey(k), msg = b("signed on the token");
      byte[] sig = t.sign(k, msg, b("ctx"));
      ok(Sign.verify("ML-DSA-65", pk, msg, sig, Sign.Opts.none().withCtx(b("ctx"))), "verifies");
      ok(!Sign.verify("ML-DSA-65", pk, msg, sig), "not without the context");
      Token.Key kk = t.generate("ML-KEM-768", "java-kem");
      Kem.Encap enc = Kem.encap("ML-KEM-768", t.publicKey(kk));
      ok(Arrays.equals(t.decap(kk, enc.ct()), enc.ss()), "decapsulates");
      eq(fails(() -> t.generate("HQC-128", "x")), Code.UNSUPPORTED, "no key type");
      ok(t.keys().size() >= 2, "lists its keys");
    }
  }
}
