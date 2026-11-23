// SPDX-License-Identifier: LGPL-3.0-or-later

package noqtis

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestArmor(t *testing.T) {
	data := []byte("some bytes \x00\x01\xff to carry as text")
	a, err := Armor("NOQTIS TEST", data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a, "-----BEGIN NOQTIS TEST-----\n") {
		t.Fatalf("armor: %q", a)
	}
	lab, back, err := Dearmor(a)
	if err != nil || lab != "NOQTIS TEST" || !bytes.Equal(back, data) {
		t.Fatalf("dearmor: %q %x %v", lab, back, err)
	}
	if _, _, err := Dearmor("not armor"); !errors.Is(err, ErrDecode) {
		t.Fatalf("not armor: %v", err)
	}
	if _, err := Armor("lower case", data); !errors.Is(err, ErrArg) {
		t.Fatalf("a bad label: %v", err)
	}
}

func TestCertCMSAndSMIME(t *testing.T) {
	pk, sk, err := SignKeyGen("ML-DSA-44", nil)
	if err != nil {
		t.Fatal(err)
	}
	na := t0.Add(365 * 24 * time.Hour)
	cert, err := SelfCert("ML-DSA-44", sk, pk, "Ada Example", "ada@example.org", t0, na)
	if err != nil {
		t.Fatal(err)
	}
	ci, err := ReadCert(cert)
	if err != nil || ci.Alg != "ML-DSA-44" || ci.KEM || !ci.CA || ci.Name != "Ada Example" ||
		ci.Email != "ada@example.org" || !bytes.Equal(ci.PK, pk) || !ci.NotBefore.Equal(t0) {
		t.Fatalf("ReadCert: %+v %v", ci, err)
	}
	kpk, ksk, err := KEMKeyGen("ML-KEM-768", nil)
	if err != nil {
		t.Fatal(err)
	}
	kc, err := KEMCert("ML-DSA-44", sk, cert, "ML-KEM-768", kpk, t0, na)
	if err != nil {
		t.Fatal(err)
	}
	if ki, err := ReadCert(kc); err != nil || !ki.KEM || ki.Alg != "ML-KEM-768" || ki.Name != "Ada Example" {
		t.Fatalf("KEMCert: %+v %v", ki, err)
	}
	msg := []byte("a message to sign and to seal")
	at := t0.Add(time.Hour)
	for _, det := range []bool{false, true} {
		s, err := CMSSign("ML-DSA-44", sk, cert, msg, det, at)
		if err != nil {
			t.Fatal(err)
		}
		var m []byte
		if det {
			m = msg
		}
		out, who, err := CMSVerify(s, m, [][]byte{cert}, at)
		if err != nil || !bytes.Equal(out, msg) || who.Name != "Ada Example" {
			t.Fatalf("CMSVerify detached=%v: %q %+v %v", det, out, who, err)
		}
		if _, _, err := CMSVerify(s, m, [][]byte{kc}, at); !errors.Is(err, ErrVerify) {
			t.Fatalf("another anchor: %v", err)
		}
	}
	e, err := CMSEncrypt([][]byte{kc}, msg)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := CMSDecrypt("ML-KEM-768", ksk, kc, e); err != nil || !bytes.Equal(out, msg) {
		t.Fatalf("CMSDecrypt: %q %v", out, err)
	}
	_, ksk2, _ := KEMKeyGen("ML-KEM-768", nil)
	if _, err := CMSDecrypt("ML-KEM-768", ksk2, nil, e); !errors.Is(err, ErrVerify) {
		t.Fatalf("another key: %v", err)
	}
	ent := "Content-Type: text/plain\r\n\r\nhello, mail\r\n"
	sm, err := SMIMESign("ML-DSA-44", sk, cert, ent, true, at)
	if err != nil || !strings.Contains(sm, "multipart/signed") || !strings.Contains(sm, "hello, mail") {
		t.Fatalf("SMIMESign: %v %q", err, sm)
	}
	back, who, err := SMIMEVerify(sm, [][]byte{cert}, at)
	if err != nil || back != ent || who.Email != "ada@example.org" {
		t.Fatalf("SMIMEVerify: %q %+v %v", back, who, err)
	}
	if _, _, err := SMIMEVerify(strings.Replace(sm, "hello", "jello", 1), [][]byte{cert}, at); !errors.Is(err, ErrVerify) {
		t.Fatalf("a changed message: %v", err)
	}
	se, err := SMIMEEncrypt([][]byte{kc}, ent)
	if err != nil {
		t.Fatal(err)
	}
	if back, err := SMIMEDecrypt("ML-KEM-768", ksk, kc, se); err != nil || back != ent {
		t.Fatalf("SMIMEDecrypt: %q %v", back, err)
	}
}

func TestPGP(t *testing.T) {
	pw := []byte("a passphrase")
	sec, pub, err := PGPGenerate(PGPMLDSA65, PGPMLKEM768, "Ada Example <ada@example.org>", t0, pw)
	if err != nil {
		t.Fatal(err)
	}
	k, err := PGPInfo(pub)
	if err != nil || k.Alg != PGPMLDSA65 || k.EncAlg != PGPMLKEM768 || k.Secret ||
		k.UserID != "Ada Example <ada@example.org>" || !k.Created.Equal(t0) || !k.Expires.IsZero() ||
		len(k.Fingerprint) != 64 || len(k.EncFingerprint) != 64 {
		t.Fatalf("PGPInfo: %+v %v", k, err)
	}
	if k, err := PGPInfo(sec); err != nil || !k.Secret || !k.Locked {
		t.Fatalf("PGPInfo of the secret key: %+v %v", k, err)
	}
	a, err := PGPArmor(PGPPublicKey, pub)
	if err != nil || !strings.HasPrefix(a, "-----BEGIN PGP PUBLIC KEY BLOCK-----\n") {
		t.Fatalf("PGPArmor: %v", err)
	}
	if kind, back, err := PGPDearmor(a); err != nil || kind != PGPPublicKey || !bytes.Equal(back, pub) {
		t.Fatalf("PGPDearmor: %d %v", kind, err)
	}
	msg := []byte("signed text\nof two lines\n")
	at := t0.Add(time.Minute)
	for _, mode := range []int{PGPInline, PGPDetached, PGPClear} {
		s, err := PGPSign(sec, pw, msg, mode, at)
		if err != nil {
			t.Fatal(err)
		}
		var m []byte
		if mode == PGPDetached {
			m = msg
		}
		out, when, err := PGPVerify(pub, s, m)
		if err != nil || !when.Equal(at) {
			t.Fatalf("PGPVerify mode %d: %v %v", mode, when, err)
		}
		if mode != PGPClear && !bytes.Equal(out, msg) {
			t.Fatalf("PGPVerify mode %d: %q", mode, out)
		}
	}
	if _, err := PGPSign(sec, []byte("wrong"), msg, PGPInline, at); !errors.Is(err, ErrVerify) {
		t.Fatalf("a wrong passphrase: %v", err)
	}
	e, err := PGPEncrypt([][]byte{pub}, []byte("open sesame"), sec, pw, msg, at)
	if err != nil {
		t.Fatal(err)
	}
	out, signed, when, err := PGPDecrypt(sec, pw, pub, e)
	if err != nil || !signed || !when.Equal(at) || !bytes.Equal(out, msg) {
		t.Fatalf("PGPDecrypt: %q %v %v %v", out, signed, when, err)
	}
	out, signed, _, err = PGPDecrypt(nil, []byte("open sesame"), nil, e)
	if err != nil || signed || !bytes.Equal(out, msg) {
		t.Fatalf("PGPDecrypt by passphrase: %q %v %v", out, signed, err)
	}
	if _, _, _, err := PGPDecrypt(nil, []byte("open sesam"), nil, e); !errors.Is(err, ErrVerify) {
		t.Fatalf("a wrong message passphrase: %v", err)
	}
}

func TestStore(t *testing.T) {
	dir := t.TempDir()
	pk, sk, err := SignKeyGen("ML-DSA-44", nil)
	if err != nil {
		t.Fatal(err)
	}
	kpk, _, err := KEMKeyGen("ML-KEM-768", nil)
	if err != nil {
		t.Fatal(err)
	}
	pk2, _, err := KEMKeyGen("ML-KEM-768", nil)
	if err != nil {
		t.Fatal(err)
	}
	card, err := MakeCard("ML-DSA-44", sk, pk, CardFields{Name: "Me Myself", Email: "me@example.org"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	// my signature key by its card, my KEM key under the same name
	me, err := StoreAdd(dir, "ML-DSA-44", pk, "", "", card)
	if err != nil || len(me) != 32 {
		t.Fatal(err)
	}
	own, err := StoreAdd(dir, "ML-KEM-768", kpk, "Me Myself", "me@example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := StoreAdd(dir, "ML-KEM-768", pk2, "Bob Other", "bob@example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := StoreList(dir, "")
	if err != nil || len(ks) != 3 {
		t.Fatalf("StoreList: %+v %v", ks, err)
	}
	ks, err = StoreList(dir, "bob@example.org")
	if err != nil || len(ks) != 1 || ks[0].Alg != "ML-KEM-768" || !ks[0].KEM || ks[0].Valid != ValidNone {
		t.Fatalf("StoreList by address: %+v %v", ks, err)
	}
	if alg, got, err := StoreGet(dir, bob); err != nil || alg != "ML-KEM-768" || !bytes.Equal(got, pk2) {
		t.Fatalf("StoreGet: %s %v", alg, err)
	}
	// my own key, trusted ultimately, certifies Bob's: it becomes valid
	if err := StoreTrust(dir, me, TrustUltimate); err != nil {
		t.Fatal(err)
	}
	c, err := StoreCertify(dir, "ML-DSA-44", sk, pk, bob, t0)
	if err != nil || c == "" {
		t.Fatalf("StoreCertify: %v", err)
	}
	ks, err = StoreList(dir, "bob@example.org")
	if err != nil || len(ks) != 1 || ks[0].Valid != ValidFull || ks[0].Certs != 1 {
		t.Fatalf("after certifying: %+v %v", ks, err)
	}
	if _, err := StoreCertify(dir, "ML-DSA-44", sk, pk, own, t0); err != nil {
		t.Fatal(err)
	}
	// a bundle carries my card and my KEM key to another store
	b, err := StoreExport(dir, me)
	if err != nil || b == "" {
		t.Fatalf("StoreExport: %v", err)
	}
	if _, err := StoreExport(dir, bob); !errors.Is(err, ErrArg) {
		t.Fatalf("a key without a card has no bundle: %v", err)
	}
	dir2 := t.TempDir()
	fp, n, err := StoreImport(dir2, b, "me@example.org")
	if err != nil || n != 2 || !bytes.Equal(fp, me) {
		t.Fatalf("StoreImport: %x %d %v", fp, n, err)
	}
	if _, _, err := StoreImport(dir2, b, "eve@example.org"); err == nil {
		t.Fatal("a bundle for another address came in")
	}
	if err := StoreDelete(dir, bob); err != nil {
		t.Fatal(err)
	}
	if ks, _ := StoreList(dir, ""); len(ks) != 2 {
		t.Fatalf("after delete: %+v", ks)
	}
	u, err := KeyURL("Ada@Example.org")
	if err != nil || !strings.HasPrefix(u, "https://example.org/.well-known/noqtis/") {
		t.Fatalf("KeyURL: %q %v", u, err)
	}
	if _, err := KeyURL("no address"); !errors.Is(err, ErrArg) {
		t.Fatalf("KeyURL of no address: %v", err)
	}
}

// With NQTOKPATH naming the software token of tests/p11 (built by
// CMake as nqtok), keys made on it sign and decapsulate.
func TestToken(t *testing.T) {
	if _, err := OpenToken("nqtok"); !errors.Is(err, ErrArg) {
		t.Fatalf("a bare module name: %v", err)
	}
	if _, err := OpenToken("./no/such/module.so"); !errors.Is(err, ErrIO) {
		t.Fatalf("a missing module: %v", err)
	}
	mod := os.Getenv("NQTOKPATH")
	if mod == "" {
		t.Skip("NQTOKPATH is not set")
	}
	tk, err := OpenToken(mod)
	if err != nil {
		t.Fatal(err)
	}
	defer tk.Close()
	ts, err := tk.Tokens()
	if err != nil || len(ts) != 1 || ts[0].Label != "noqtis test token" || !ts[0].Login {
		t.Fatalf("Tokens: %+v %v", ts, err)
	}
	if err := tk.Login(ts[0].Slot, "0000"); !errors.Is(err, ErrVerify) {
		t.Fatalf("a wrong PIN: %v", err)
	}
	if err := tk.Login(ts[0].Slot, "1234"); err != nil {
		t.Fatal(err)
	}
	k, err := tk.Generate("ML-DSA-65", "go-sig")
	if err != nil || k.Alg != "ML-DSA-65" || k.KEM || k.Label != "go-sig" {
		t.Fatalf("Generate: %+v %v", k, err)
	}
	pk, err := tk.PublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("signed on the token")
	sig, err := tk.Sign(k, msg, []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := Verify("ML-DSA-65", pk, msg, sig, &SignOpts{Ctx: []byte("ctx")}); err != nil || !ok {
		t.Fatalf("Verify of a token signature: %v %v", ok, err)
	}
	kk, err := tk.Generate("ML-KEM-768", "go-kem")
	if err != nil {
		t.Fatal(err)
	}
	kpk, err := tk.PublicKey(kk)
	if err != nil {
		t.Fatal(err)
	}
	ct, ss, err := Encap("ML-KEM-768", kpk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := tk.Decaps(kk, ct); err != nil || !bytes.Equal(got, ss) {
		t.Fatalf("Decaps on the token: %v", err)
	}
	if _, err := tk.Generate("HQC-128", "x"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("a key type tokens have not: %v", err)
	}
	ks, err := tk.Keys()
	if err != nil || len(ks) < 2 {
		t.Fatalf("Keys: %+v %v", ks, err)
	}
}
