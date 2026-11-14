// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// Passphrase key files, streaming signatures and hashes, messages and
// streams sealed to an ML-KEM key, external mu, BLAKE2b and Argon2id,
// against the known answers of tests/vectors (pwk, kseal, kstream,
// acvp/mu.txt, b2b, argon2) and the failures their formats name.
package noqtis

import (
	"bytes"
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
	txt := must(EncodeKeyPW("ML-DSA-44", "sec", sk, []byte("pass")))
	if !strings.HasPrefix(txt, "noqtis-key-1 ML-DSA-44 sec\n") {
		t.Fatal(txt[:30])
	}
	if !bytes.Equal(must(DecodeKeyPW([]byte(txt), []byte("pass"))).Key, sk) {
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
	if !bytes.Equal(must(ReadKeyPW(p, "sec", []byte("pw"))).Key, sk) {
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
