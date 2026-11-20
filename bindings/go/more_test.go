// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// The rest of the capsule and data functions: SealWhy, the timestamp
// requests, key statements, DSSE, bundles, chains, the environment,
// commitments, citation, report, synthetic data, calibration and chunk
// digests, on tests/vectors/nqd.
package noqtis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func q10cap(t *testing.T) string {
	d := nqdcap(t, nqdvec(t), false)
	must(0, DataAdd(d, []string{"data/a.csv", "data/b.csv"}, nil))
	return d
}

func TestSealWhyTimestamps(t *testing.T) {
	d := t.TempDir()
	must(0, os.WriteFile(filepath.Join(d, "a"), []byte("a"), 0o644))
	if w, _ := pair(SealWhy(d)); w != 0 {
		t.Fatal("why", w)
	}
	pk, sk := pair(SignKeyGen("ML-DSA-44", nil))
	if runtime.GOOS != "windows" {
		must(0, os.Symlink("a", filepath.Join(d, "l")))
		if err := Seal(d, "ML-DSA-44", sk, pk, ""); code(err) != -1 {
			t.Fatal("seal over a link", err)
		}
		if w, p := pair(SealWhy(d)); w != WhyLink || p != "l" {
			t.Fatal("why", w, p)
		}
		must(0, os.Remove(filepath.Join(d, "l")))
	}
	must(0, Seal(d, "ML-DSA-44", sk, pk, ""))
	q := must(TSReq(d, []byte{1, 2}))
	if q[0] != 0x30 || bytes.Equal(q, must(TSReq(d, nil))) {
		t.Fatal("TSReq")
	}
	if must(ERSReq(d, "", nil))[0] != 0x30 {
		t.Fatal("ERSReq")
	}
	if _, err := TSPut(d, []byte{0x30, 0}, nil, nil); err == nil {
		t.Fatal("TSPut took a bad reply")
	}
	if _, _, err := ERSPut(d, "", []byte{0x30, 0}, nil, nil); err == nil {
		t.Fatal("ERSPut took a bad reply")
	}
}

func TestStatementsDSSE(t *testing.T) {
	pk, sk := pair(SignKeyGen("ML-DSA-44", nil))
	npk, nsk := pair(SignKeyGen("ML-DSA-65", nil))
	r := must(Rotate("ML-DSA-44", sk, pk, "ML-DSA-65", nsk, npk, 1800000000, "new key"))
	v := must(Revoke("ML-DSA-44", sk, pk, 1800000000, ""))
	if !bytes.Contains(r, []byte("noqtis-keys-1")) || !bytes.Contains(v, []byte("noqtis-keys-1")) {
		t.Fatal("statements")
	}
	if _, err := Revoke("ML-DSA-44", sk, npk, 0, ""); code(err) != -1 {
		t.Fatal("not a pair", err)
	}
	x := must(Expire("ML-DSA-44", sk, pk, 1800000000, "yearly"))
	if !bytes.Contains(x, []byte(`"kind":"expire"`)) {
		t.Fatal("expire")
	}
	if _, err := Expire("ML-DSA-44", sk, npk, 0, ""); code(err) != -1 {
		t.Fatal("expire, not a pair", err)
	}
	e := must(DSSE("ML-DSA-44", sk, pk, "text/plain", []byte("hello")))
	typ, p, ok, err := DSSEVerify("ML-DSA-44", pk, e)
	if err != nil || !ok || typ != "text/plain" || string(p) != "hello" {
		t.Fatal("DSSE", typ, string(p), ok, err)
	}
	opk, _ := pair(SignKeyGen("ML-DSA-44", nil))
	if _, _, ok, err := DSSEVerify("ML-DSA-44", opk, e); ok || err != nil {
		t.Fatal("another key", err)
	}
	if _, _, _, err := DSSEVerify("ML-DSA-44", pk, []byte("{}")); code(err) != -4 {
		t.Fatal("not an envelope", err)
	}
}

func TestBundlesChains(t *testing.T) {
	c := q10cap(t)
	pk, sk := pair(SignKeyGen("ML-DSA-44", nil))
	must(0, Seal(c, "ML-DSA-44", sk, pk, ""))
	w := t.TempDir()
	a, b := filepath.Join(w, "a.nqb"), filepath.Join(w, "b.nqb")
	must(0, Pack(c, a, true))
	must(0, Pack(c, b, true))
	if !bytes.Equal(must(os.ReadFile(a)), must(os.ReadFile(b))) {
		t.Fatal("not deterministic")
	}
	o := &CheckOpts{Trust: pk}
	if !must(CheckPack(a, o)).OK() {
		t.Fatal("CheckPack")
	}
	must(0, Unpack(a, filepath.Join(w, "u")))
	if !must(Check(filepath.Join(w, "u"), o)).OK() {
		t.Fatal("unpacked")
	}
	if err := Unpack(a, filepath.Join(w, "u")); code(err) != -7 {
		t.Fatal("over a folder", err)
	}
	x := must(os.ReadFile(a))
	must(0, os.WriteFile(filepath.Join(w, "cut"), x[:len(x)-10], 0o644))
	if err := Unpack(filepath.Join(w, "cut"), filepath.Join(w, "v")); code(err) != -4 {
		t.Fatal("cut", err)
	}
	if exists(filepath.Join(w, "v")) {
		t.Fatal("left behind")
	}
	var ds []string
	for i := 0; i < 3; i++ {
		d := filepath.Join(w, fmt.Sprintf("l%d", i))
		must(0, os.MkdirAll(d, 0o755))
		must(0, os.WriteFile(filepath.Join(d, "log.txt"), []byte(fmt.Sprintf("entry %d\n", i)), 0o644))
		var in []Input
		if len(ds) > 0 {
			in = []Input{{ID: must(CapID(ds[len(ds)-1])), Name: "prev"}}
		}
		must(0, Seal2(d, "ML-DSA-44", sk, pk, "", in))
		ds = append(ds, d)
	}
	r, h, ok, err := Chain(ds, o)
	if err != nil || !ok || !r.OK() || h != must(CapID(ds[2])) {
		t.Fatal("chain", err, r)
	}
	if _, _, ok, _ := Chain([]string{ds[0], ds[2]}, o); ok {
		t.Fatal("a gap passed")
	}
}

func TestEnvCommitCiteReport(t *testing.T) {
	c := q10cap(t)
	must(0, os.WriteFile(filepath.Join(c, "go.sum"), []byte("x v1.0.0 h1:abc=\n"), 0o644))
	e := must(Env(c, &EnvOpts{Rng: "PCG", Seed: "42", Pkgs: []Pkg{{"b", "1", "go"}, {"a", "2", "go"}}}))
	var m map[string]any
	must(0, json.Unmarshal([]byte(e), &m))
	rt := m["runtime"].(map[string]any)
	if rt["language"] != "go" || rt["version"] != runtime.Version() {
		t.Fatal("runtime", rt)
	}
	if !strings.Contains(must(DataText(c)), `"packages":[{"name":"a","source":"go","version":"2"},{"name":"b"`) {
		t.Fatal("packages sorted", must(DataText(c)))
	}
	if !strings.Contains(e, `"path":"go.sum"`) || !strings.Contains(e, `"seed":"42"`) {
		t.Fatal("locks and rng", e)
	}
	must(Env(c, nil))
	if !must(DataCheck(c)).OK() {
		t.Fatal("record after Env")
	}
	if _, err := Env(c, &EnvOpts{Locks: []string{"none.lock"}}); code(err) != -1 {
		t.Fatal("missing lock", err)
	}
	if runtime.GOOS != "windows" {
		// a lock file is read inside the folder, never through a link
		o := filepath.Join(t.TempDir(), "go.sum")
		must(0, os.Rename(filepath.Join(c, "go.sum"), o))
		must(0, os.Symlink(o, filepath.Join(c, "go.sum")))
		if _, err := Env(c, nil); code(err) != -1 || !strings.Contains(err.Error(), "refused") {
			t.Fatal("a lock file through a link", err)
		}
		must(0, os.Remove(filepath.Join(c, "go.sum")))
		must(0, os.Rename(o, filepath.Join(c, "go.sum")))
	}
	plan := []byte("arm A: 1, 4\n")
	s := must(Commit(c, plan, &CommitOpts{Kind: "randomisation", Label: "trial"}))
	if i, ok := pair(Reveal(c, plan, s)); !ok || i != 0 {
		t.Fatal("reveal")
	}
	if _, ok := pair(Reveal(c, []byte("x"), s)); ok {
		t.Fatal("revealed another file")
	}
	if !strings.Contains(must(DataText(c)), must(Commitment(s, plan))) {
		t.Fatal("digest")
	}
	if _, err := Commitment([]byte("short"), plan); code(err) != -1 {
		t.Fatal(err)
	}
	if _, err := Cite(c, false); code(err) != -7 {
		t.Fatal("no cite", err)
	}
	must(0, DataPut(c, "cite", `{"title":"T","authors":["A. Author"],"year":2026,"doi":"10.1234/x"}`))
	if !strings.Contains(must(Cite(c, false)), `title: "T"`) || !strings.Contains(must(Cite(c, true)), "doi = {10.1234/x}") {
		t.Fatal("cite")
	}
	pk, sk := pair(SignKeyGen("ML-DSA-44", nil))
	must(0, Seal(c, "ML-DSA-44", sk, pk, ""))
	md := must(DataReport(c, pk, false))
	if !strings.HasPrefix(md, "#") || !strings.Contains(md, "data/a.csv") {
		t.Fatal("report", md[:40])
	}
	if !strings.Contains(must(DataReport(c, nil, true)), "data/a.csv") {
		t.Fatal("text report")
	}
}

func TestSynthCalibrateChunks(t *testing.T) {
	v := nqdvec(t)
	d := t.TempDir()
	must(0, os.MkdirAll(filepath.Join(d, "data"), 0o755))
	must(0, DataPut(d, "schemas", string(must(os.ReadFile(filepath.Join(v, "syn", "schema.json"))))))
	must(0, Synth(d, "data/s.csv", 7, 16))
	if !bytes.Equal(must(os.ReadFile(filepath.Join(d, "data", "s.csv"))), must(os.ReadFile(filepath.Join(v, "syn", "s7.csv")))) {
		t.Fatal("not s7.csv")
	}
	c := q10cap(t)
	s := must(Schema(c, "data/a.csv", nil))
	if !must(SchemaCheckElem(c, s)).OK() || must(SchemaCheckElem(c, strings.Replace(s, `"int"`, `"bool"`, 1))).OK() {
		t.Fatal("SchemaCheckElem")
	}
	must(0, DataPut(c, "schemas", s))
	if err := Synth(c, "data/a.csv", 1, 0); code(err) != -1 {
		t.Fatal("replaced real data", err)
	}
	must(0, Pin(c, []string{"data/a.csv"}, nil))
	if !strings.Contains(must(Calibrate(c, "data/a.csv", []string{filepath.Join(c, "data", "a.csv")}, nil)), `"cal"`) {
		t.Fatal("calibrate")
	}
	big := make([]byte, 5000)
	for i := range big {
		big[i] = byte(i % 253)
	}
	must(0, os.WriteFile(filepath.Join(c, "big.bin"), big, 0o644))
	if !strings.Contains(must(Chunks(c, "big.bin", 1024)), `"size":5000`) {
		t.Fatal("chunks")
	}
	p := filepath.Join(t.TempDir(), "piece")
	must(0, os.WriteFile(p, big[2048:], 0o644))
	if !must(Piece(c, "big.bin", p, 2048)).OK() {
		t.Fatal("piece")
	}
	b := append([]byte{}, big[2048:]...)
	b[1100] ^= 1
	must(0, os.WriteFile(p, b, 0o644))
	if r := must(Piece(c, "big.bin", p, 2048)); r.OK() || r.Rows[0].Check != "chunk" {
		t.Fatal("changed piece passed")
	}
	if _, err := Chunks(c, "big.bin", 10); code(err) != -1 {
		t.Fatal("small chunk", err)
	}
}
