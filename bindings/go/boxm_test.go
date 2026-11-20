// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

package noqtis

import (
	"bytes"
	"testing"
)

// a stream to several recipients, signed or not: each recipient opens it,
// another key does not, and the sender's key decides
func TestBoxTo(t *testing.T) {
	type kp struct {
		alg    string
		pk, sk []byte
	}
	var ks []kp
	for _, a := range []string{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"} {
		pk, sk := pair(KEMKeyGen(a, nil))
		ks = append(ks, kp{a, pk, sk})
	}
	_, xsk := pair(KEMKeyGen("ML-KEM-768", nil))
	spk, ssk := pair(SignKeyGen("ML-DSA-44", nil))
	opk, _ := pair(SignKeyGen("ML-DSA-44", nil))
	rcps := []Rcp{{ks[0].alg, ks[0].pk}, {ks[1].alg, ks[1].pk}, {ks[2].alg, ks[2].pk}}
	ctx := []byte("ctx")
	for _, n := range []int{0, 1, 1024, 1025, 5000} {
		m := make([]byte, n)
		for i := range m {
			m[i] = byte(i % 249)
		}
		for _, sig := range []*Sender{nil, {"ML-DSA-44", ssk}} {
			var e bytes.Buffer
			must(0, BoxTo(rcps, sig, bytes.NewReader(m), &e, ctx, 1024))
			if !bytes.HasPrefix(e.Bytes(), []byte("NQKM")) {
				t.Fatal("format")
			}
			for _, k := range ks {
				var o bytes.Buffer
				var snd []byte
				if sig != nil {
					snd = spk
				}
				name, err := UnboxFrom(k.alg, k.sk, snd, bytes.NewReader(e.Bytes()), &o, ctx)
				if err != nil || !bytes.Equal(o.Bytes(), m) {
					t.Fatal("round trip", n, k.alg, err)
				}
				if (name == "ML-DSA-44") != (sig != nil) {
					t.Fatal("signature algorithm", name)
				}
			}
			var o bytes.Buffer
			if _, err := UnboxFrom("ML-KEM-768", xsk, nil, bytes.NewReader(e.Bytes()), &o, ctx); code(err) != -3 {
				t.Fatal("not a recipient", err)
			}
			if _, err := UnboxFrom(ks[0].alg, ks[0].sk, nil, bytes.NewReader(e.Bytes()), &o, nil); code(err) != -3 {
				t.Fatal("another context", err)
			}
			// another sender's key; a key asked of a stream that is not signed
			if _, err := UnboxFrom(ks[1].alg, ks[1].sk, opk, bytes.NewReader(e.Bytes()), &o, ctx); code(err) != -3 {
				t.Fatal("another sender", err)
			}
			// a signed stream opens without asking who sent it
			if _, err := UnboxFrom(ks[2].alg, ks[2].sk, nil, bytes.NewReader(e.Bytes()), &o, ctx); err != nil {
				t.Fatal("no sender asked", err)
			}
			b := append([]byte(nil), e.Bytes()...)
			b[len(b)-3] ^= 1
			if _, err := UnboxFrom(ks[0].alg, ks[0].sk, nil, bytes.NewReader(b), &o, ctx); code(err) != -3 {
				t.Fatal("changed", err)
			}
		}
	}
	var e bytes.Buffer
	if err := BoxTo(nil, nil, bytes.NewReader(nil), &e, nil, 0); code(err) != -1 {
		t.Fatal("no recipient", err)
	}
	if err := BoxTo(rcps, &Sender{"ML-DSA-44", nil}, bytes.NewReader(nil), &e, nil, 0); code(err) != -1 {
		t.Fatal("no signing key", err)
	}
	if err := BoxTo(rcps, nil, bytes.NewReader(nil), &e, nil, 100); code(err) != -1 {
		t.Fatal("small chunk", err)
	}
	if err := BoxTo([]Rcp{{"ML-DSA-44", spk}}, nil, bytes.NewReader(nil), &e, nil, 0); err == nil {
		t.Fatal("a signature key as a recipient")
	}
	if _, err := UnboxFrom("ML-KEM-768", xsk, nil, bytes.NewReader([]byte("NQKM")), &e, nil); code(err) != -4 {
		t.Fatal("cut short", err)
	}
	if _, err := UnboxFrom("ML-KEM-768", xsk, nil, bytes.NewReader(make([]byte, 40)), &e, nil); code(err) != -4 {
		t.Fatal("not a stream", err)
	}
}
