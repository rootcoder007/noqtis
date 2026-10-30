// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

package noqtis

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Unix(1767225600, 0) // 2026-01-01T00:00:00Z

func TestCardRoundTrip(t *testing.T) {
	pk, sk, err := SignKeyGen("ML-DSA-44", nil)
	if err != nil {
		t.Fatal(err)
	}
	f := CardFields{Name: "Ada Lovelace", ORCID: "https://orcid.org/0000-0002-1694-233x",
		Email: "ada@example.org", URL: "https://example.org/ada", Affil: "AES"}
	c, err := MakeCard("ML-DSA-44", sk, pk, f, t0)
	if err != nil {
		t.Fatal(err)
	}
	var j map[string]any
	if err := json.Unmarshal(c, &j); err != nil {
		t.Fatal(err)
	}
	if j["format"] != "noqtis-idcard-1" || j["orcid"] != "0000-0002-1694-233X" {
		t.Fatalf("card %s", c)
	}
	v, err := VerifyCard(c, nil)
	if err != nil || v == nil {
		t.Fatalf("verify: %v %v", v, err)
	}
	want := Card{Name: "Ada Lovelace", ORCID: "0000-0002-1694-233X", Email: "ada@example.org",
		URL: "https://example.org/ada", Affil: "AES", Created: "2026-01-01T00:00:00Z",
		Alg: "ML-DSA-44", PK: pk, KeySHA256: sha256hex(t, pk)}
	if v.Name != want.Name || v.ORCID != want.ORCID || v.Email != want.Email || v.URL != want.URL ||
		v.Affil != want.Affil || v.Created != want.Created || v.Alg != want.Alg ||
		!bytes.Equal(v.PK, pk) || v.KeySHA256 != want.KeySHA256 {
		t.Fatalf("got %+v", v)
	}
	if v2, err := VerifyCard(c, pk); err != nil || v2 == nil {
		t.Fatalf("pinned: %v %v", v2, err)
	}
	m, err := MakeCard("ML-DSA-44", sk, pk, CardFields{Name: "Adéle"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if v, err := VerifyCard(m, nil); err != nil || v.Name != "Adéle" || v.ORCID != "" {
		t.Fatalf("name only: %v %v", v, err)
	}
}

func TestCardRefusals(t *testing.T) {
	pk, sk, _ := SignKeyGen("ML-DSA-44", nil)
	for _, f := range []CardFields{
		{Name: "A", ORCID: "0000-0002-1825-0098"}, {Name: "A", Email: "ada"},
		{Name: "A", URL: "http://example.org"}, {Name: " A"}, {Name: "A\nB"},
		{Name: "A\u009bB"}, {Name: ""}, {Name: strings.Repeat("x", 256)}, {Name: "A\x00B"},
		{Name: "A", Affil: " U"},
	} {
		if _, err := MakeCard("ML-DSA-44", sk, pk, f, t0); !errors.Is(err, ErrArg) {
			t.Errorf("%+v: %v", f, err)
		}
	}
	if _, err := MakeCard("ML-DSA-44", sk, pk, CardFields{Name: strings.Repeat("x", 255)}, t0); err != nil {
		t.Error(err)
	}
	pk2, sk2, _ := SignKeyGen("ML-DSA-44", nil)
	if _, err := MakeCard("ML-DSA-44", sk2, pk, CardFields{Name: "A"}, t0); !errors.Is(err, ErrArg) {
		t.Errorf("not a pair: %v", err)
	}
	pe, se, _ := SignKeyGen("Ed25519", nil)
	if _, err := MakeCard("Ed25519", se, pe, CardFields{Name: "A"}, t0); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Ed25519: %v", err)
	}
	_ = pk2
}

func TestCardChanged(t *testing.T) {
	pk, sk, _ := SignKeyGen("ML-DSA-44", nil)
	pk2, _, _ := SignKeyGen("ML-DSA-44", nil)
	c, err := MakeCard("ML-DSA-44", sk, pk, CardFields{Name: "Ada Lovelace"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := VerifyCard(bytes.Replace(c, []byte("Ada Lovelace"), []byte("Ada Lovelacf"), 1), nil); v != nil || err != nil {
		t.Errorf("changed: %v %v", v, err)
	}
	if v, err := VerifyCard(c, pk2); v != nil || err != nil {
		t.Errorf("other key: %v %v", v, err)
	}
	for _, b := range [][]byte{append([]byte(" "), c...), []byte("{}"), {}} {
		if _, err := VerifyCard(b, nil); !errors.Is(err, ErrDecode) {
			t.Errorf("%q: %v", b, err)
		}
	}
	if _, err := VerifyCard(bytes.Repeat([]byte("["), 256*1024+1), nil); !errors.Is(err, ErrLimit) {
		t.Errorf("oversized: %v", err)
	}
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "a.txt"), []byte("a\n"), 0o644)
	if err := Seal(d, "ML-DSA-44", sk, pk, ""); err != nil {
		t.Fatal(err)
	}
	s, _ := os.ReadFile(filepath.Join(d, "noqtis.sig"))
	if _, err := VerifyCard(s, nil); !errors.Is(err, ErrDecode) {
		t.Errorf("a seal: %v", err)
	}
	os.WriteFile(filepath.Join(d, "noqtis.sig"), c, 0o644)
	if r, err := Check(d, &CheckOpts{Trust: pk}); err != nil || r.OK() {
		t.Errorf("a card as a seal: %v %v", r, err)
	}
}
