// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// The binding against known answers (NIST ACVP, RFC 8032, RFC 4231, the
// repository's golden capsule) and round trips of every algorithm.
package noqtis

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func sha256hex(t *testing.T, b []byte) string {
	d, err := Hash("SHA-256", b)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(d)
}

// must is v, or a panic (a failed test) on err
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func code(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}

const repo = "../.."

var nodet = &SignOpts{Deterministic: true}

func TestVersionAndTable(t *testing.T) {
	if Version() != "0.1.2" {
		t.Fatalf("version %q", Version())
	}
	ns, nk := 0, 0
	for _, a := range Algs() {
		if a.Kind == "sign" {
			ns++
		} else {
			nk++
		}
	}
	if ns != 19 || nk != 6 {
		t.Fatalf("%d signature and %d KEM algorithms", ns, nk)
	}
	a := must(Find("ml-dsa-44"))
	if a.Name != "ML-DSA-44" || a.PK != 1312 || a.SK != 2560 || a.Sig != 2420 {
		t.Fatal(a)
	}
	k := must(Find("ML-KEM-768"))
	if k.PK != 1184 || k.SK != 2400 || k.CT != 1088 || k.SS != 32 {
		t.Fatal(k)
	}
	if len(Hashes()) != 12 {
		t.Fatal(Hashes())
	}
	if _, err := Find("nope"); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestHashes(t *testing.T) {
	for _, c := range []struct{ alg, in, want string }{
		{"SHA-256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"sha256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"SHA3-256", "abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
		{"SHAKE128", "", "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"},
	} {
		if got := hex.EncodeToString(must(Hash(c.alg, []byte(c.in)))); got != c.want {
			t.Errorf("%s: %s", c.alg, got)
		}
	}
	if len(must(HashN("shake_256", []byte("x"), 100))) != 100 {
		t.Fatal("SHAKE256 length")
	}
	if _, err := HashN("SHA-256", nil, 5); code(err) != -1 {
		t.Fatal(err)
	}
	// RFC 4231 test case 2
	m := must(HMAC("SHA-256", []byte("Jefe"), []byte("what do ya want for nothing?")))
	if hex.EncodeToString(m) != "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" {
		t.Fatal(hex.EncodeToString(m))
	}
	if _, err := Hash("MD5", nil); code(err) != -8 {
		t.Fatal(err)
	}
	r := must(Random(32))
	if len(r) != 32 || bytes.Equal(r, must(Random(32))) {
		t.Fatal("random")
	}
}

func TestSignKATs(t *testing.T) {
	// ACVP ML-DSA-keyGen-FIPS204, tcId 1 (digests of the expected keys)
	pk, sk, err := SignKeyGen("ML-DSA-44", unhex("7194b13c95231010afd2c909992bd2003ba6f437c3886bdbe3f6b867a14ba161"))
	if err != nil {
		t.Fatal(err)
	}
	if sha256hex(t, pk) != "838b88b6ac41e2c60698173e08ca173d0b0d2839205806e56a8a3d53195f3a03" ||
		sha256hex(t, sk) != "1c911d163cd0a5563e06f22403f7e16334fee17c2abb66f11ddf39ca6307ec58" {
		t.Fatal("ML-DSA-44 keyGen")
	}
	// ACVP SLH-DSA-keyGen-FIPS205, tcId 21
	pk, _, err = SignKeyGen("SLH-DSA-SHA2-128f", unhex("c42bcb3b5a6f331f5cce899253c6d9e29ff2b7ead7a04bab1794db8cc659c3b4a868f1bd5debc12d4c9fad66aabd0a94"))
	if err != nil || hex.EncodeToString(pk) != "a868f1bd5debc12d4c9fad66aabd0a94b546df247be4c457f3d467cdfcfabd39" {
		t.Fatal("SLH-DSA keyGen", err)
	}
	// RFC 8032 section 7.1, test 1
	pk, sk, err = SignKeyGen("Ed25519", unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
	if err != nil || hex.EncodeToString(pk) != "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" {
		t.Fatal("Ed25519 keygen", err)
	}
	s := must(Sign("Ed25519", sk, nil, nil))
	want := "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
	if hex.EncodeToString(s) != want {
		t.Fatal(hex.EncodeToString(s))
	}
	if !must(Verify("Ed25519", pk, nil, s, nil)) {
		t.Fatal("Ed25519 verify")
	}
}

func TestSignRoundTrips(t *testing.T) {
	for _, a := range Algs() {
		if a.Kind != "sign" || strings.HasSuffix(a.Name, "s") {
			continue // SLH-DSA "s" signs slowly; see TestSignSlow
		}
		n := a.Name
		t.Run(n, func(t *testing.T) {
			pk, sk, err := SignKeyGen(n, nil)
			if err != nil || len(pk) != a.PK || len(sk) != a.SK {
				t.Fatal(err)
			}
			o := &SignOpts{Ctx: []byte("c")}
			m := []byte("noqtis go " + n)
			s := must(Sign(n, sk, m, o))
			if len(s) != a.Sig || !must(Verify(n, pk, m, s, o)) {
				t.Fatal("round trip")
			}
			if must(Verify(n, pk, []byte("other"), s, o)) || must(Verify(n, pk, m, s, nil)) {
				t.Fatal("verified another message or context")
			}
			bad := append([]byte(nil), s...)
			bad[len(bad)/2] ^= 1
			if must(Verify(n, pk, m, bad, o)) || must(Verify(n, pk, m, s[:len(s)-1], o)) {
				t.Fatal("verified a bad signature")
			}
			d1 := must(Sign(n, sk, m, nodet))
			if !bytes.Equal(d1, must(Sign(n, sk, m, nodet))) {
				t.Fatal("deterministic")
			}
			z := make([]byte, must(RndLen(n)))
			if !bytes.Equal(d1, must(Sign(n, sk, m, &SignOpts{Rnd: z}))) {
				t.Fatal("explicit zero rnd")
			}
			sl := 3 * len(z)
			if strings.HasSuffix(n, "+Ed25519") {
				sl = 64
			} else if strings.HasPrefix(n, "ML-DSA") || n == "Ed25519" {
				sl = 32
			}
			seed := make([]byte, sl)
			for i := range seed {
				seed[i] = byte(i)
			}
			p1, _, _ := SignKeyGen(n, seed)
			p2, _, _ := SignKeyGen(n, seed)
			if !bytes.Equal(p1, p2) {
				t.Fatal("seeded keygen")
			}
			if _, _, err := SignKeyGen(n, seed[1:]); err == nil {
				t.Fatal("short seed")
			}
		})
	}
}

func TestSignSlow(t *testing.T) {
	n := "SLH-DSA-SHAKE-128s"
	pk, sk := must2(t)(SignKeyGen(n, bytes.Repeat([]byte{7}, 48)))
	s := must(Sign(n, sk, []byte("m"), nodet))
	if !must(Verify(n, pk, []byte("m"), s, nil)) {
		t.Fatal(n)
	}
}

func must2(t *testing.T) func(a, b []byte, err error) ([]byte, []byte) {
	return func(a, b []byte, err error) ([]byte, []byte) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return a, b
	}
}

func TestPrehashAndErrors(t *testing.T) {
	for _, n := range []string{"ML-DSA-44", "SLH-DSA-SHA2-128f", "Ed25519"} {
		pk, sk := must2(t)(SignKeyGen(n, nil))
		for _, h := range []string{"SHA-256", "SHA-512", "SHAKE128"} {
			o := &SignOpts{Prehash: h}
			s, err := Sign(n, sk, []byte("m"), o)
			if err != nil {
				// Ed25519ph is SHA-512 alone
				if n != "Ed25519" || h == "SHA-512" {
					t.Fatal(n, h, err)
				}
				continue
			}
			if !must(Verify(n, pk, []byte("m"), s, o)) || must(Verify(n, pk, []byte("m"), s, nil)) {
				t.Fatal(n, h)
			}
		}
	}
	pk, sk := must2(t)(SignKeyGen("ML-DSA-44", nil))
	_, err := Sign("ML-DSA-44", sk, []byte("m"), &SignOpts{Ctx: make([]byte, 256)})
	var e *Error
	if !errors.As(err, &e) || e.Code != -1 || e.Msg == "" || !errors.Is(err, ErrArg) ||
		!strings.HasPrefix(err.Error(), "noqtis: ") {
		t.Fatal(err)
	}
	if _, err := Verify("ML-DSA-44", pk[1:], nil, nil, nil); !errors.Is(err, ErrDecode) {
		t.Fatal(err)
	}
	if _, err := Sign("ML-KEM-768", sk, nil, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := Sign("ML-DSA-44", sk, nil, &SignOpts{Deterministic: true, Rnd: make([]byte, 32)}); !errors.Is(err, ErrArg) {
		t.Fatal(err)
	}
}

func TestKEM(t *testing.T) {
	// ACVP ML-KEM-keyGen-FIPS203, tcId 26 (digests of the expected keys)
	ek, dk := must2(t)(KEMKeyGen("ML-KEM-768", unhex("e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a01cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0")))
	if sha256hex(t, ek) != "4158f6afb5e516c99f1da07da8c651348422b17c1f4e9a08ad73fb1f91249b3e" ||
		sha256hex(t, dk) != "7aab35839207f72b310abe36e2daa1cc7ff6f7fa8941e439967cd47d9b437079" {
		t.Fatal("ML-KEM-768 keyGen")
	}
	c1, s1 := must2(t)(Encap("ML-KEM-768", ek, bytes.Repeat([]byte{1}, 32)))
	c2, s2 := must2(t)(Encap("ML-KEM-768", ek, bytes.Repeat([]byte{1}, 32)))
	if !bytes.Equal(c1, c2) || !bytes.Equal(s1, s2) || !bytes.Equal(must(Decap("ML-KEM-768", dk, c1)), s1) {
		t.Fatal("seeded encap")
	}
	for _, a := range Algs() {
		if a.Kind != "kem" {
			continue
		}
		n := a.Name
		pk, sk := must2(t)(KEMKeyGen(n, nil))
		ct, ss := must2(t)(Encap(n, pk, nil))
		if len(ct) != a.CT || len(ss) != a.SS || !bytes.Equal(must(Decap(n, sk, ct)), ss) {
			t.Fatal(n)
		}
		bad := append([]byte(nil), ct...)
		bad[0] ^= 1
		r := must(Decap(n, sk, bad))
		if bytes.Equal(r, ss) || !bytes.Equal(r, must(Decap(n, sk, bad))) {
			t.Fatal(n, "implicit rejection")
		}
		if _, err := Decap(n, sk, ct[1:]); err == nil {
			t.Fatal(n, "short ciphertext")
		}
		if _, _, err := Encap(n, pk[1:], nil); err == nil {
			t.Fatal(n, "short key")
		}
	}
}

func mkfiles(t *testing.T) string {
	d := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(d, "a.txt"), []byte("hello\n"), 0o644)
	os.WriteFile(filepath.Join(d, "data", "b.csv"), []byte("x,y\n1,2\n"), 0o644)
	return d
}

// the golden capsule (tests/vectors/cap/sample), copied, so a test may
// change it
func gold(t *testing.T) string {
	g := filepath.Join(repo, "tests", "vectors", "cap", "sample")
	if _, err := os.Stat(filepath.Join(g, "noqtis.sig")); err != nil {
		t.Skip("no tests/vectors/cap/sample here")
	}
	d := t.TempDir()
	for _, f := range []string{"a.txt", "empty", "data/b.csv", "data/deep/c.bin", "noqtis.json", "noqtis.sig"} {
		b, err := os.ReadFile(filepath.Join(g, f))
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, filepath.FromSlash(f))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestGoldenCapsule(t *testing.T) {
	g := gold(t)
	// tests/tcap.c: the ML-DSA-44 key from the seed 0, 1, ..., 31
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	pk, _ := must2(t)(SignKeyGen("ML-DSA-44", seed))
	o := &CheckOpts{Trust: pk}
	r := must(Check(g, o))
	if !r.OK() {
		t.Fatal(r)
	}
	if !strings.Contains(r.String(), "data/deep/c.bin") || !must(Check(g, nil)).OK() {
		t.Fatal(r)
	}
	id := must(CapID(g))
	if hex.EncodeToString(id[:]) != "0b79bb292652444787adf22b993d9926f2a9fa29a2107a18e7a56941592ee25c" {
		t.Fatal(hex.EncodeToString(id[:]))
	}
	i := must(Inspect(g))
	for k, v := range map[string]string{"info.alg": "ML-DSA-44", "info.files": "4", "info.format": "noqtis-capsule-1"} {
		if x, ok := i.Get(k); !ok || x.Detail != v {
			t.Fatal(k, x)
		}
	}
	nf := 0
	for _, x := range must(Files(g)).Rows {
		if x.Check == "info.file" {
			nf++
		}
	}
	if nf != 4 {
		t.Fatal(nf)
	}
	other, _ := must2(t)(SignKeyGen("ML-DSA-44", nil))
	if r := must(Check(g, &CheckOpts{Trust: other})); r.OK() || r.Code != -3 {
		t.Fatal(r)
	}
	os.WriteFile(filepath.Join(g, "a.txt"), []byte("other\n"), 0o644)
	r = must(Check(g, o))
	if r.OK() || len(r.Failed()) == 0 || !strings.Contains(r.Failed()[0].Detail+r.Failed()[0].Check, "a.txt") {
		t.Fatal(r)
	}
}

func TestSealAndCheck(t *testing.T) {
	d := mkfiles(t)
	pk, sk := must2(t)(SignKeyGen("ML-DSA-65", nil))
	if err := Seal(d, "ML-DSA-65", sk, pk, `{"project":"go"}`); err != nil {
		t.Fatal(err)
	}
	o := &CheckOpts{Trust: pk}
	if r := must(Check(d, o)); !r.OK() {
		t.Fatal(r)
	}
	if x, _ := must(Inspect(d)).Get("info.meta"); x.Detail != `{"project":"go"}` {
		t.Fatal(x)
	}
	r := must(Check(d, &CheckOpts{Trust: pk, Only: []string{"a.txt"}}))
	if !strings.Contains(r.String(), "partial") {
		t.Fatal(r)
	}
	os.WriteFile(filepath.Join(d, "new.txt"), []byte("x"), 0o644)
	if must(Check(d, o)).OK() {
		t.Fatal("an added file passed")
	}
	if err := Seal(d, "ML-DSA-65", sk, pk, "[1]"); err == nil {
		t.Fatal("meta not an object")
	}
	if r, err := Check(filepath.Join(d, "nope"), o); err == nil && r.OK() {
		t.Fatal("a missing folder passed")
	}
	if err := Seal(d, "ML-KEM-512", sk, pk, ""); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if err := Seal(d+"\x00x", "ML-DSA-65", sk, pk, ""); !errors.Is(err, ErrArg) {
		t.Fatal(err)
	}
}

func TestSeal2ProveLineage(t *testing.T) {
	pk, sk := must2(t)(SignKeyGen("ML-DSA-44", nil))
	a := mkfiles(t)
	if err := Seal2(a, "ML-DSA-44", sk, pk, "", nil); err != nil {
		t.Fatal(err)
	}
	id := must(CapID(a))
	b := mkfiles(t)
	if err := Seal2(b, "ML-DSA-44", sk, pk, `{"step":2}`, []Input{{ID: id, Name: "raw"}}); err != nil {
		t.Fatal(err)
	}
	r := must(Check(b, &CheckOpts{Trust: pk, Lineage: []string{a}}))
	if _, ok := r.Get("lineage"); !r.OK() || !ok {
		t.Fatal(r)
	}
	if x, _ := must(Inspect(b)).Get("info.format"); x.Detail != "noqtis-capsule-2" {
		t.Fatal(x)
	}
	pf := must(Prove(b, []string{"data/b.csv"}))
	if len(pf) == 0 || pf[0] != '{' {
		t.Fatal(string(pf))
	}
	o := &CheckOpts{Trust: pk}
	if r := must(CheckProof(pf, o, "")); !r.OK() {
		t.Fatal(r)
	}
	if r := must(CheckProof(pf, o, b)); !r.OK() {
		t.Fatal(r)
	}
	bad := append([]byte(nil), pf...)
	if bad[len(bad)/2] == '0' {
		bad[len(bad)/2] = '1'
	} else {
		bad[len(bad)/2] = '0'
	}
	if r, err := CheckProof(bad, o, ""); err == nil && r.OK() {
		t.Fatal("a changed proof passed")
	}
	c := mkfiles(t)
	if err := Seal(c, "ML-DSA-44", sk, pk, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Prove(c, []string{"a.txt"}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := Prove(b, []string{"nope"}); !errors.Is(err, ErrIO) {
		t.Fatal(err)
	}
}

func TestKeyFiles(t *testing.T) {
	pk, sk := must2(t)(SignKeyGen("ML-DSA-44", nil))
	s := must(EncodeKey("ml-dsa-44", "pub", pk))
	if !strings.HasPrefix(s, "noqtis-key-1 ML-DSA-44 pub\n") {
		t.Fatal(s[:40])
	}
	for _, l := range strings.Split(s, "\n") {
		if len(l) > 64 && !strings.HasPrefix(l, "noqtis") {
			t.Fatal("line over 64")
		}
	}
	k := must(DecodeKey([]byte(s)))
	if k.Alg != "ML-DSA-44" || k.Kind != "pub" || !bytes.Equal(k.Key, pk) {
		t.Fatal(k)
	}
	if !bytes.Equal(must(DecodeKey([]byte(strings.ReplaceAll(s, "\n", "\r\n")))).Key, pk) {
		t.Fatal("CRLF")
	}
	for _, bad := range []string{
		strings.Replace(s, "noqtis-key-1", "noqtis-key-2", 1),
		strings.Replace(s, " pub\n", " pub \n", 1),
		strings.Replace(s, " pub\n", " both\n", 1),
		s[:len(s)-10] + "\n",
		strings.Replace(s, "A", " ", 1),
		"",
	} {
		if _, err := DecodeKey([]byte(bad)); err == nil {
			t.Fatalf("decoded %q", bad)
		}
	}
	// a non-zero bit under the padding
	ep, _ := must2(t)(SignKeyGen("Ed25519", nil))
	es := must(EncodeKey("Ed25519", "pub", ep))
	line := strings.Split(es, "\n")[1]
	al := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	v := strings.IndexByte(al, line[len(line)-2])
	if v%4 != 0 {
		t.Fatal(line)
	}
	l2 := line[:len(line)-2] + string(al[v+1]) + "="
	if _, err := DecodeKey([]byte(strings.Replace(es, line, l2, 1))); err == nil {
		t.Fatal("decoded non-canonical base64")
	}
	if _, err := EncodeKey("ML-DSA-44", "pub", sk); !errors.Is(err, ErrArg) {
		t.Fatal(err)
	}
	if _, err := EncodeKey("nope", "pub", pk); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	// a file the CLI wrote
	p := filepath.Join(repo, "tests", "vectors", "interop", "bl", "mldsa.pub")
	if raw, err := os.ReadFile(p); err == nil {
		k := must(ReadKey(p, "pub"))
		if k.Alg != "ML-DSA-65" || must(EncodeKey(k.Alg, "pub", k.Key)) != string(raw) {
			t.Fatal("CLI key file")
		}
		if _, err := ReadKey(p, "sec"); !errors.Is(err, ErrArg) {
			t.Fatal(err)
		}
	}
	d := t.TempDir()
	f := filepath.Join(d, "me")
	if err := WriteKey(f, "ML-DSA-44", "sec", sk, false); err != nil {
		t.Fatal(err)
	}
	if err := WriteKey(f, "ML-DSA-44", "sec", sk, false); !errors.Is(err, ErrIO) {
		t.Fatal(err)
	}
	if err := WriteKey(f, "ML-DSA-44", "sec", sk, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(must(ReadKey(f, "")).Key, sk) {
		t.Fatal("read back")
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(f); st.Mode().Perm() != 0o600 {
			t.Fatal(st.Mode())
		}
	}
	if _, err := ReadKey(filepath.Join(d, "nope"), ""); !errors.Is(err, ErrIO) {
		t.Fatal(err)
	}
}
