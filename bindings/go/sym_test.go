// SPDX-License-Identifier: LGPL-3.0-or-later

package noqtis

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func ptn(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func hx(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestKangarooTwelve(t *testing.T) {
	for _, c := range []struct {
		m, cu []byte
		want  string
	}{
		{nil, nil, "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5"},
		{ptn(17), nil, "6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888"},
		{[]byte{0xff}, ptn(41), "d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4"},
	} {
		if got := hex.EncodeToString(must(KT128(c.m, c.cu, 32))); got != c.want {
			t.Errorf("KT128: %s", got)
		}
	}
	if got := hex.EncodeToString(must(KT256(nil, nil, 32))); got != "b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404" {
		t.Errorf("KT256: %s", got)
	}
	big := ptn(20000)
	if !bytes.Equal(must(KT128(big, nil, 100))[:32], must(KT128(big, nil, 32))) {
		t.Fatal("a shorter output is not the start of a longer one")
	}
	if bytes.Equal(must(KT128(big, []byte("a"), 32)), must(KT128(big, nil, 32))) {
		t.Fatal("the customization string changed nothing")
	}
	if _, err := KT128(nil, nil, 0); code(err) != -1 {
		t.Fatal(err)
	}
}

func TestChaCha20(t *testing.T) {
	want := "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7" +
		"da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
	if got := hex.EncodeToString(must(ChaCha20(make([]byte, 32), make([]byte, 12), 0, make([]byte, 64)))); got != want {
		t.Errorf("ChaCha20: %s", got)
	}
	k, n, m := ptn(32), ptn(12), ptn(300)
	c := must(ChaCha20(k, n, 7, m))
	if bytes.Equal(c, m) || !bytes.Equal(must(ChaCha20(k, n, 7, c)), m) {
		t.Fatal("round trip")
	}
	if !bytes.Equal(must(ChaCha20(k, n, 8, m[64:])), c[64:]) {
		t.Fatal("a later block is not the same stream")
	}
	if len(must(ChaCha20(k, n, 0, nil))) != 0 {
		t.Fatal("empty")
	}
	if _, err := ChaCha20(k, n, 0xffffffff, m); code(err) != -9 {
		t.Fatal(err)
	}
	if _, err := ChaCha20(k[:16], n, 0, m); code(err) != -1 {
		t.Fatal(err)
	}
}

func TestSIV(t *testing.T) {
	key := hx("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	ad := hx("101112131415161718191a1b1c1d1e1f2021222324252627")
	pt := hx("112233445566778899aabbccddee")
	out := hx("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c")
	if !bytes.Equal(must(SIVEncrypt(key, [][]byte{ad}, pt)), out) {
		t.Fatal("RFC 5297 A.1")
	}
	if !bytes.Equal(must(SIVDecrypt(key, [][]byte{ad}, out)), pt) {
		t.Fatal("decrypt")
	}
	if bytes.Equal(must(SIVEncrypt(key, nil, pt)), out) || bytes.Equal(must(SIVEncrypt(key, [][]byte{ad, nil}, pt)), out) {
		t.Fatal("the associated strings changed nothing")
	}
	for _, k := range [][]byte{ptn(48), ptn(64)} {
		c := must(SIVEncrypt(k, [][]byte{ad, []byte("n")}, pt))
		if !bytes.Equal(must(SIVDecrypt(k, [][]byte{ad, []byte("n")}, c)), pt) {
			t.Fatal("round trip")
		}
	}
	if len(must(SIVDecrypt(key, nil, must(SIVEncrypt(key, nil, nil))))) != 0 {
		t.Fatal("empty")
	}
	bad := append([]byte(nil), out...)
	bad[20] ^= 1
	for _, e := range []error{
		func() error { _, e := SIVDecrypt(key, [][]byte{ad}, bad); return e }(),
		func() error { _, e := SIVDecrypt(key, nil, out); return e }(),
		func() error { _, e := SIVDecrypt(ptn(32), [][]byte{ad}, out); return e }(),
	} {
		if code(e) != -3 {
			t.Fatal(e)
		}
	}
	if _, err := SIVEncrypt(ptn(40), nil, pt); code(err) != -1 {
		t.Fatal(err)
	}
	if _, err := SIVDecrypt(key, nil, []byte("short")); code(err) != -1 {
		t.Fatal(err)
	}
	if _, err := SIVEncrypt(key, make([][]byte, 127), pt); code(err) != -1 {
		t.Fatal(err)
	}
}

func TestGCMSIV(t *testing.T) {
	key := hx("01000000000000000000000000000000")
	nonce := hx("030000000000000000000000")
	pt := hx("0100000000000000")
	out := hx("b5d839330ac7b786578782fff6013b815b287c22493a364c")
	if !bytes.Equal(must(GCMSIVEncrypt(key, nonce, nil, pt)), out) {
		t.Fatal("RFC 8452 C.1")
	}
	if !bytes.Equal(must(GCMSIVDecrypt(key, nonce, nil, out)), pt) {
		t.Fatal("decrypt")
	}
	k2 := ptn(32)
	c := must(GCMSIVEncrypt(k2, nonce, []byte("header"), pt))
	if !bytes.Equal(must(GCMSIVDecrypt(k2, nonce, []byte("header"), c)), pt) {
		t.Fatal("round trip")
	}
	bad := append([]byte(nil), c...)
	bad[len(bad)-1] ^= 0x80
	for _, e := range []error{
		func() error { _, e := GCMSIVDecrypt(k2, nonce, []byte("header"), bad); return e }(),
		func() error { _, e := GCMSIVDecrypt(k2, nonce, []byte("other"), c); return e }(),
		func() error { _, e := GCMSIVDecrypt(k2, ptn(12), []byte("header"), c); return e }(),
	} {
		if code(e) != -3 {
			t.Fatal(e)
		}
	}
	if _, err := GCMSIVEncrypt(ptn(24), nonce, nil, pt); code(err) != -1 {
		t.Fatal(err)
	}
	if _, err := GCMSIVDecrypt(key, nonce, nil, []byte("xyz")); code(err) != -1 {
		t.Fatal(err)
	}
}
