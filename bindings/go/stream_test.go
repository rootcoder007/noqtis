// SPDX-License-Identifier: LGPL-3.0-or-later

// Passphrase key files, streaming signatures and hashes, messages and
// streams sealed to an ML-KEM key, external mu, BLAKE2b and Argon2id,
// against the known answers of tests/vectors (pwk, kseal, kstream,
// acvp/mu.txt, b2b, argon2) and the failures their formats name.
package noqtis

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// kv is the records of a key=value vector file under tests/vectors.
func kv(t *testing.T, name string) []map[string]string {
	b, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", name))
	if err != nil {
		t.Skipf("no %s here", name)
	}
	var out []map[string]string
	cur := map[string]string{}
	for _, l := range append(strings.Split(string(b), "\n"), "") {
		l = strings.TrimSuffix(l, "\r")
		if strings.HasPrefix(l, "#") {
			continue
		}
		if l == "" {
			if len(cur) > 0 {
				out = append(out, cur)
				cur = map[string]string{}
			}
			continue
		}
		k, v, _ := strings.Cut(l, "=")
		cur[k] = v
	}
	return out
}

func TestPWKeyFiles(t *testing.T) {
	v := kv(t, "pwk/kat.txt")
	for _, r := range v {
		if got := must(PWDec(unhex(r["pw"]), unhex(r["out"]), unhex(r["ad"]))); !bytes.Equal(got, unhex(r["sk"])) {
			t.Fatalf("pwk t=%s", r["t"])
		}
	}
	r := v[0]
	pw, ad, out := unhex(r["pw"]), unhex(r["ad"]), unhex(r["out"])
	if _, err := PWDec([]byte("wrong"), out, ad); code(err) != -3 {
		t.Fatal("wrong passphrase", err)
	}
	if _, err := PWDec(pw, out, []byte("x")); code(err) != -3 {
		t.Fatal("wrong ad", err)
	}
	if _, err := PWDec(pw, out[:40], ad); code(err) != -4 {
		t.Fatal("cut", err)
	}
	out[len(out)-1] ^= 1
	if _, err := PWDec(pw, out, ad); code(err) != -3 {
		t.Fatal("changed byte", err)
	}
	_, sk := pair(SignKeyGen("ML-DSA-44", nil))
	if _, err := PWEnc(pw, sk, nil, 1024, 1, 1); code(err) != -1 {
		t.Fatal("small memory", err)
	}
	// a signature secret key is written in the version 2 container, and
	// read back as it
	x := must(SxMake("ML-DSA-44", sk))
	txt := must(EncodeKeyPW("ML-DSA-44", "sec", sk, []byte("pass")))
	if !strings.HasPrefix(txt, "noqtis-key-2 ML-DSA-44 sec\n") {
		t.Fatal(txt[:30])
	}
	if !bytes.Equal(must(DecodeKeyPW([]byte(txt), []byte("pass"))).Key, x) {
		t.Fatal("round trip")
	}
	if _, err := DecodeKey([]byte(txt)); code(err) != -1 {
		t.Fatal("no passphrase", err)
	}
	_, err := DecodeKeyPW([]byte(txt), []byte("nope"))
	if code(err) != -3 || strings.Contains(err.Error(), "pass") || strings.Contains(err.Error(), "nope") {
		t.Fatal("wrong passphrase", err)
	}
	p := filepath.Join(t.TempDir(), "k")
	must(0, WriteKeyPW(p, "ML-DSA-44", "sec", sk, false, []byte("pw")))
	if !bytes.Equal(must(ReadKeyPW(p, "sec", []byte("pw"))).Key, x) {
		t.Fatal("file round trip")
	}
}

func pair[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

func TestStreamingSign(t *testing.T) {
	msg := make([]byte, 10000)
	for i := range msg {
		msg[i] = byte(i % 251)
	}
	for _, c := range []struct {
		alg, ph string
		seed    int
	}{{"ML-DSA-44", "", 32}, {"ML-DSA-65", "SHA-512", 32}, {"SLH-DSA-SHA2-128f", "SHA-256", 48},
		{"Ed25519", "SHA-512", 32}, {"ML-DSA-65+Ed25519", "SHA-512", 64}} {
		seed := make([]byte, c.seed)
		for i := range seed {
			seed[i] = byte(i)
		}
		pk, sk := pair(SignKeyGen(c.alg, seed))
		o := &SignOpts{Ctx: []byte("c"), Prehash: c.ph, Deterministic: true}
		want := must(Sign(c.alg, sk, msg, o))
		for _, n := range []int{1, 7, 4096, len(msg)} {
			s := must(NewSigner(c.alg, sk, o))
			for i := 0; i < len(msg); i += n {
				must(s.Write(msg[i:min(i+n, len(msg))]))
			}
			if !bytes.Equal(must(s.Sum(o)), want) {
				t.Fatalf("%s %d: not the one-call signature", c.alg, n)
			}
			if _, err := s.Write(nil); code(err) != -10 {
				t.Fatal("used twice", err)
			}
		}
		v := must(NewVerifier(c.alg, pk, o))
		must(io.Copy(v, bytes.NewReader(msg)))
		if !must(v.Check(want)) {
			t.Fatal(c.alg, "does not verify")
		}
		v = must(NewVerifier(c.alg, pk, o))
		must(v.Write(msg[1:]))
		if must(v.Check(want)) {
			t.Fatal(c.alg, "verifies another message")
		}
	}
	_, sk := pair(SignKeyGen("SLH-DSA-SHA2-128f", nil))
	if _, err := NewSigner("SLH-DSA-SHA2-128f", sk, nil); code(err) != -8 {
		t.Fatal("pure SLH-DSA", err)
	}
}

func TestHasher(t *testing.T) {
	msg := bytes.Repeat([]byte{7}, 5000)
	for _, a := range []string{"SHA-256", "SHA3-384", "SHA-512/224"} {
		h := must(NewHasher(a))
		must(io.Copy(h, bytes.NewReader(msg)))
		if !bytes.Equal(must(h.Sum(0)), must(Hash(a, msg))) {
			t.Fatal(a)
		}
	}
	h := must(NewHasher("SHAKE128"))
	must(h.Write(msg))
	got := append(must(h.Sum(5)), must(h.Sum(27))...)
	if !bytes.Equal(got, must(HashN("SHAKE128", msg, 32))) {
		t.Fatal("SHAKE squeeze")
	}
}

func TestKSeal(t *testing.T) {
	v := kv(t, "kseal/kat.txt")
	for _, r := range v {
		_, sk := pair(KEMKeyGen(r["alg"], unhex(r["kseed"])))
		if !bytes.Equal(must(KOpen(r["alg"], sk, unhex(r["out"]), unhex(r["ctx"]))), unhex(r["msg"])) {
			t.Fatal("kseal", r["alg"])
		}
	}
	r := v[len(v)-1]
	pk, sk := pair(KEMKeyGen(r["alg"], unhex(r["kseed"])))
	out := unhex(r["out"])
	out[30] ^= 1
	if _, err := KOpen(r["alg"], sk, out, unhex(r["ctx"])); code(err) != -3 {
		t.Fatal("changed byte", err)
	}
	if _, err := KOpen(r["alg"], sk, out[:10], nil); code(err) != -4 {
		t.Fatal("short", err)
	}
	c := must(KSeal(r["alg"], pk, []byte("round"), []byte("x")))
	if string(must(KOpen(r["alg"], sk, c, []byte("x")))) != "round" {
		t.Fatal("round trip")
	}
	if _, err := KOpen(r["alg"], sk, c, []byte("y")); code(err) != -3 {
		t.Fatal("other ctx", err)
	}
}

func unboxed(r map[string]string, data []byte) ([]byte, error) {
	_, sk := pair(KEMKeyGen(r["alg"], unhex(r["kseed"])))
	var o bytes.Buffer
	err := Unbox(r["alg"], sk, bytes.NewReader(data), &o, unhex(r["ctx"]))
	return o.Bytes(), err
}

func TestKStream(t *testing.T) {
	v := kv(t, "kstream/kat.txt")
	var big map[string]string
	for _, r := range v {
		if !bytes.Equal(must(unboxed(r, unhex(r["out"]))), unhex(r["msg"])) {
			t.Fatal("kstream", r["alg"], r["chunk"])
		}
		if big == nil || len(r["out"]) > len(big["out"]) {
			big = r
		}
	}
	a := must(find(big["alg"], "kem"))
	out := unhex(big["out"])
	h, n := 17+a.CT, must(strconv.Atoi(big["chunk"]))+16
	var cs [][]byte
	for i := h; i < len(out); i += n {
		cs = append(cs, out[i:min(i+n, len(out))])
	}
	join := func(p [][]byte) []byte { return append(append([]byte{}, out[:h]...), bytes.Join(p, nil)...) }
	bad := map[string][]byte{
		"cut at a chunk": join(cs[:len(cs)-1]),
		"cut inside":     out[:len(out)-3],
		"swapped":        join(append([][]byte{cs[1], cs[0]}, cs[2:]...)),
		"extended":       append(append([]byte{}, out...), 0),
	}
	ch := append([]byte{}, out...)
	ch[h+5] ^= 1
	bad["changed"] = ch
	for k, b := range bad {
		if _, err := unboxed(big, b); code(err) != -3 {
			t.Fatal(k, err)
		}
	}
	pk, sk := pair(KEMKeyGen("ML-KEM-768", nil))
	for _, n := range []int{0, 1, 1023, 1024, 1025, 4096, 5000} {
		m := make([]byte, n)
		for i := range m {
			m[i] = byte(i % 251)
		}
		var e, o bytes.Buffer
		must(0, Box("ML-KEM-768", pk, bytes.NewReader(m), &e, []byte("ctx"), 1024))
		must(0, Unbox("ML-KEM-768", sk, &e, &o, []byte("ctx")))
		if !bytes.Equal(o.Bytes(), m) {
			t.Fatal("round trip", n)
		}
	}
	if _, err := NewBoxer("ML-KEM-768", pk, nil, 100); code(err) != -1 {
		t.Fatal("small chunk", err)
	}
}

func TestExternalMu(t *testing.T) {
	for _, r := range kv(t, "acvp/mu.txt") {
		k, mu, sig := unhex(r["key"]), unhex(r["mu"]), unhex(r["sig"])
		if r["kind"] == "gen" {
			if !bytes.Equal(must(SignMu(r["alg"], k, mu, &SignOpts{Rnd: unhex(r["rnd"])})), sig) {
				t.Fatal("sigGen", r["alg"])
			}
		} else if must(VerifyMu(r["alg"], k, mu, sig)) != (r["ok"] == "1") {
			t.Fatal("sigVer", r["alg"], r["ok"])
		}
	}
	pk, sk := pair(SignKeyGen("ML-DSA-65", nil))
	o := &SignOpts{Ctx: []byte("c"), Deterministic: true}
	mu := must(Mu("ML-DSA-65", pk, []byte("msg"), o))
	if !bytes.Equal(must(SignMu("ML-DSA-65", sk, mu, o)), must(Sign("ML-DSA-65", sk, []byte("msg"), o))) {
		t.Fatal("SignMu is not Sign")
	}
	if _, err := Mu("Ed25519", make([]byte, 32), nil, nil); code(err) != -8 {
		t.Fatal("Ed25519 mu", err)
	}
}

func TestPBKDF2(t *testing.T) {
	// RFC 7914 section 11: "passwd", "salt", 1 iteration, 64 bytes
	want := unhex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" +
		"49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
	if !bytes.Equal(must(PBKDF2("SHA-256", []byte("passwd"), []byte("salt"), 1, 64)), want) {
		t.Fatal("pbkdf2")
	}
	if _, err := PBKDF2("SHA-256", []byte("passwd"), []byte("salt"), 0, 64); code(err) != -1 {
		t.Fatal("no iterations", err)
	}
	if _, err := PBKDF2("SHA-256", nil, nil, 1, 0); code(err) != -1 {
		t.Fatal("no output", err)
	}
}

func TestKeyV2(t *testing.T) {
	for _, alg := range []string{"ML-DSA-44", "Ed25519", "ML-DSA-44+Ed25519", "SLH-DSA-SHA2-128f"} {
		pk, sk := pair(SignKeyGen(alg, nil))
		n := must(SxSize(alg))
		x := must(SxMake(alg, sk))
		if len(x) != n || SxCheck(alg, x) != nil || !errors.Is(SxCheck(alg, sk), ErrUnsupported) {
			t.Fatal(alg, "container")
		}
		// a key file of a signature key is version 2, read back as X
		txt := must(EncodeKey(alg, "sec", sk))
		if !strings.HasPrefix(txt, KeyMagic2+" "+alg+" sec\n") {
			t.Fatal(alg, txt[:30])
		}
		k := must(DecodeKey([]byte(txt)))
		if !bytes.Equal(k.Key, x) {
			t.Fatal(alg, "X")
		}
		sig := must(Sign(alg, k.Key, []byte("m"), nil))
		if ok, _ := Verify(alg, pk, []byte("m"), sig, nil); !ok {
			t.Fatal(alg, "sign with X")
		}
		// under a passphrase too
		k2 := must(DecodeKeyPW([]byte(must(EncodeKeyPW(alg, "sec", x, []byte("p")))), []byte("p")))
		if !bytes.Equal(k2.Key, x) {
			t.Fatal(alg, "X under a passphrase")
		}
		// one changed byte: the file is refused
		y := append([]byte(nil), x...)
		y[len(y)/2] ^= 1
		bad := KeyMagic2 + " " + alg + " sec\n" + string(b64e(y)) + "\n"
		if _, err := DecodeKey([]byte(bad)); err == nil {
			t.Fatal(alg, "a damaged key read")
		}
		// a version 1 file is still read, as S
		old := KeyMagic + " " + alg + " sec\n" + string(b64e(sk)) + "\n"
		if k := must(DecodeKey([]byte(old))); !bytes.Equal(k.Key, sk) {
			t.Fatal(alg, "version 1")
		}
	}
	// a KEM key file stays version 1, and has no container
	_, ksk := pair(KEMKeyGen("ML-KEM-768", nil))
	if txt := must(EncodeKey("ML-KEM-768", "sec", ksk)); !strings.HasPrefix(txt, KeyMagic+" ") {
		t.Fatal("KEM key file", txt[:20])
	}
	if _, err := SxSize("ML-KEM-768"); err == nil {
		t.Fatal("a KEM container")
	}
}

func TestPWEnc2(t *testing.T) {
	// a secret key file under PBKDF2, written by hand as keygen
	// --kdf pbkdf2 writes it, opens with DecodeKeyPW
	_, sk := pair(SignKeyGen("ML-DSA-44", nil))
	a := must(kalg("ML-DSA-44"))
	pw := []byte("pass")
	// (a version 1 file, as noqtis before 0.3.0 wrote it: still read)
	e := must(PWEnc2(KDFPBKDF2, pw, sk, keyad(a, KeyMagic), 0, 100000, 0))
	if e[5] != KDFPBKDF2 {
		t.Fatal("the KDF byte", e[5])
	}
	txt := string(keyad(a, KeyMagic)) + "\n" + string(b64e(e)) + "\n"
	if !bytes.Equal(must(DecodeKeyPW([]byte(txt), pw)).Key, sk) {
		t.Fatal("round trip")
	}
	if _, err := DecodeKeyPW([]byte(txt), []byte("wrong")); code(err) != -3 {
		t.Fatal("wrong passphrase", err)
	}
	if _, err := PWEnc2(KDFPBKDF2, pw, sk, nil, 0, 99999, 0); code(err) != -1 {
		t.Fatal("too few iterations", err)
	}
	if _, err := PWEnc2(3, pw, sk, nil, 0, 0, 0); code(err) != -1 {
		t.Fatal("another kdf", err)
	}
}

func TestBlake2bArgon2id(t *testing.T) {
	for _, r := range kv(t, "b2b/kat.txt") {
		h := unhex(r["hash"])
		if !bytes.Equal(must(Blake2b(unhex(r["in"]), unhex(r["key"]), len(h))), h) {
			t.Fatal("blake2b")
		}
	}
	if _, err := Blake2b(nil, nil, 65); code(err) != -1 {
		t.Fatal(err)
	}
	for _, r := range append(kv(t, "argon2/rfc9106.txt"), kv(t, "argon2/ossl.txt")...) {
		if r["y"] != "2" {
			continue
		}
		tg := unhex(r["tag"])
		atoi := func(s string) uint32 { return uint32(must(strconv.Atoi(s))) }
		c := Argon2Cost{T: atoi(r["t"]), M: atoi(r["m"]), P: atoi(r["p"])}
		if !bytes.Equal(must(Argon2id(unhex(r["pw"]), unhex(r["salt"]), c, len(tg), unhex(r["key"]), unhex(r["ad"]))), tg) {
			t.Fatal("argon2id")
		}
	}
	if !CTEq([]byte("abc"), []byte("abc")) || CTEq([]byte("abc"), []byte("abd")) || CTEq([]byte("a"), []byte("ab")) {
		t.Fatal("CTEq")
	}
	w := []byte{1, 2, 3}
	Wipe(w)
	if !bytes.Equal(w, []byte{0, 0, 0}) {
		t.Fatal("Wipe")
	}
}
