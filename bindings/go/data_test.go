// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// The data layer against the values the C tests check
// (tests/nqd/tdrec.c, tdcsv.c, tddft.c on tests/vectors/nqd): a record
// made here is the one the library made there, byte for byte.
package noqtis

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func nqdvec(t *testing.T) string {
	v := filepath.Join("..", "..", "tests", "vectors", "nqd")
	if _, err := os.Stat(filepath.Join(v, "full.json")); err != nil {
		t.Skip("no tests/vectors/nqd here")
	}
	return v
}

// a copy of vectors/nqd/cap (with its record when rec)
func nqdcap(t *testing.T, v string, rec bool) string {
	d := t.TempDir()
	fs := []string{"data/a.csv", "data/b.csv"}
	if rec {
		fs = append(fs, "noqtis.data.json")
	}
	must(0, os.MkdirAll(filepath.Join(d, "data"), 0o755))
	for _, f := range fs {
		b := must(os.ReadFile(filepath.Join(v, "cap", f)))
		must(0, os.WriteFile(filepath.Join(d, f), b, 0o644))
	}
	return d
}

// the number after "key": in the JSON text j
func jnum(t *testing.T, j, key string) float64 {
	k := "\"" + key + "\":"
	i := strings.Index(j, k)
	if i < 0 {
		t.Fatalf("no %s in %s", key, j)
	}
	s := j[i+len(k):]
	return must(strconv.ParseFloat(s[:strings.IndexAny(s, ",}")], 64))
}

// the value of key in vectors/nqd/drift/expect.txt (written by drift.R)
func dexp(t *testing.T, v, key string) float64 {
	for _, l := range strings.Split(string(must(os.ReadFile(filepath.Join(v, "drift", "expect.txt")))), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == key {
			return must(strconv.ParseFloat(f[1], 64))
		}
	}
	t.Fatalf("no %s in expect.txt", key)
	return 0
}

func near(t *testing.T, a, b, tol float64, what string) {
	t.Helper()
	d := 1.0
	if math.Abs(b) > 1e-300 {
		d = math.Abs(b)
	}
	if math.Abs(a-b)/d > tol {
		t.Errorf("%s: %g, expected %g", what, a, b)
	}
}

func TestDataRecord(t *testing.T) {
	v := nqdvec(t)
	full := string(must(os.ReadFile(filepath.Join(v, "full.json"))))
	c := must(DataCanon(full))
	if must(DataCanon(c)) != c {
		t.Error("full.json: the canonical form does not read back to itself")
	}
	if _, err := DataCanon(`{"format":"x"}`); !errors.Is(err, ErrDecode) {
		t.Errorf("a record of another format: %v", err)
	}
	d := nqdcap(t, v, true)
	if must(DataText(d)) != string(must(os.ReadFile(filepath.Join(d, "noqtis.data.json")))) {
		t.Error("DataText is not the record's bytes")
	}
	if r := must(DataCheck(d)); !r.OK() || len(r.Rows) < 3 {
		t.Errorf("check: %+v", r)
	}
	// the same source element, made here
	n := nqdcap(t, v, false)
	must(0, DataAdd(n, []string{"data/a.csv"}, &Src{URL: "https://example.org/a.csv",
		Publisher: "City of Example", Licence: "OGL-Canada-2.0",
		Retrieved: "2026-01-01T00:00:00Z"}))
	e, ok, err := DataKey(n, "sources", "data/a.csv")
	w, _, _ := DataKey(d, "sources", "data/a.csv")
	if err != nil || !ok || e != w {
		t.Errorf("source: %s, expected %s (%v)", e, w, err)
	}
	if !strings.Contains(e, `"sha256":"7a1668480cde19db0b76c7a36e6fee9a82afd9937f5d03cec3dae1705ce173e2","size":89`) {
		t.Errorf("source: %s", e)
	}
	if err := DataAdd(n, []string{"../x"}, nil); !errors.Is(err, ErrArg) {
		t.Errorf("../x: %v", err)
	}
	// put, key and del
	must(0, DataPut(n, "checks", `{"name":"x","status":"fail"}`))
	if must(DataCheck(n)).OK() {
		t.Error("a check recorded as failed passed")
	}
	if err := DataPut(n, "checks", `{"name":"x","status":"maybe"}`); err == nil {
		t.Error("status maybe was taken")
	}
	must(0, DataDel(n, "checks", "x"))
	if _, ok, _ := DataKey(n, "checks", "x"); ok {
		t.Error("the check is still there")
	}
	if !must(DataCheck(n)).OK() {
		t.Error("check after del")
	}
	if _, err := DataText(filepath.Join(v, "drift")); !errors.Is(err, ErrIO) {
		t.Errorf("no record: %v", err)
	}
}

func TestDataSchema(t *testing.T) {
	v := nqdvec(t)
	d := nqdcap(t, v, true)
	want := `{"columns":[{"name":"id","nulls":false,"type":"int"},` +
		`{"name":"name","nulls":true,"type":"text"},` +
		`{"name":"score","nulls":true,"type":"real"},` +
		`{"name":"when","nulls":false,"type":"date"}],` +
		`"kind":"csv","path":"data/a.csv","rows":{"max":3,"min":3}}`
	if s := must(Schema(d, "data/a.csv", nil)); s != want {
		t.Errorf("schema: %s", s)
	}
	s := must(Schema(d, "data/a.csv", &CSVOpts{Ranges: true}))
	if !strings.Contains(s, `"max":4,"min":3.5`) || !strings.Contains(s, `"max":"2024-03-01","min":"2024-01-02"`) {
		t.Errorf("ranges: %s", s)
	}
	must(0, DataPut(d, "schemas", s))
	if r := must(SchemaCheck(d, nil)); !r.OK() {
		t.Errorf("schema check: %+v", r)
	}
	must(0, os.WriteFile(filepath.Join(d, "data", "a.csv"), []byte("id,name,score,when\n1,ann,9.5,2024-01-02\n"), 0o644))
	if r := must(SchemaCheck(d, []string{"data/a.csv"})); r.OK() || len(r.Rows) == 0 {
		t.Errorf("a value out of range passed: %+v", r)
	}
	if _, err := Schema(d, "nope.csv", nil); !errors.Is(err, ErrIO) {
		t.Errorf("nope.csv: %v", err)
	}
}

func TestDataDrift(t *testing.T) {
	v := nqdvec(t)
	d := t.TempDir()
	must(0, os.WriteFile(filepath.Join(d, "ref.csv"), must(os.ReadFile(filepath.Join(v, "drift", "ref.csv"))), 0o644))
	must(0, Pin(d, []string{"ref.csv"}, nil))
	if r := must(Drift(d, nil, nil, nil, nil)); r.Level() != "ok" {
		t.Errorf("the same file drifted: %+v", r)
	}
	r := must(Drift(d, []string{"ref.csv"}, []string{filepath.Join(v, "drift", "cur.csv")}, nil, nil))
	// fewer than 1,000 values: PSI warns, never fails
	if r.Level() != "warn" {
		t.Errorf("level %s: %+v", r.Level(), r)
	}
	col := func(n string) string {
		for _, x := range r.Rows {
			if strings.Contains(x.Stats, `"name":"`+n+`"`) {
				return x.Stats
			}
		}
		t.Fatalf("no row of column %s", n)
		return ""
	}
	x := col("x")
	near(t, jnum(t, x, "ksd"), dexp(t, v, "ks.d"), 1e-14, "ks.d")
	near(t, jnum(t, x, "ksp"), dexp(t, v, "ks.p"), 1e-9, "ks.p")
	near(t, jnum(t, x, "psi"), dexp(t, v, "psi"), 1e-12, "psi")
	near(t, jnum(t, x, "js"), dexp(t, v, "js"), 1e-12, "js")
	c := col("c")
	near(t, jnum(t, c, "chisq"), dexp(t, v, "chi.x2"), 1e-12, "chi.x2")
	near(t, jnum(t, c, "df"), dexp(t, v, "chi.df"), 0, "chi.df")
	near(t, jnum(t, c, "chisqp"), dexp(t, v, "chi.p"), 1e-10, "chi.p")
	near(t, jnum(t, c, "psi"), dexp(t, v, "cat.psi"), 1e-12, "cat.psi")
	if _, err := Drift(d, []string{"cur.csv"}, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "no summary of cur.csv") {
		t.Errorf("no summary: %v", err)
	}
}

func TestDataDiff(t *testing.T) {
	v := nqdvec(t)
	a, b := nqdcap(t, v, true), nqdcap(t, v, true)
	// unsealed: one passing "manifest" row says the files were not compared
	if r := must(Diff(a, b)); !r.Same() || len(r.Failed()) != 0 {
		t.Errorf("two copies differ: %+v", r)
	}
	must(0, DataAdd(b, []string{"data/a.csv"}, &Src{URL: "https://example.org/a2.csv"}))
	r := must(Diff(a, b))
	found := false
	for _, x := range r.Rows {
		found = found || (x.Check == "source" && !x.OK && strings.Contains(x.Detail, "url"))
	}
	if r.Same() || !found {
		t.Errorf("a changed url: %+v", r)
	}
}

func TestDataSources(t *testing.T) {
	v := nqdvec(t)
	d := nqdcap(t, v, false)
	if err := DataAdd(d, []string{"data/a.csv"}, &Src{URL: "https://example.org/a.csv"}); err != nil {
		t.Fatal(err)
	}
	e, _, err := DataKey(d, "sources", "data/a.csv")
	if err != nil {
		t.Fatal(err)
	}
	e = e[:len(e)-1] + `,"mirrors":["https://m.example.net/a.csv"],"resolver":{"base":"https://data.example.org","id":"abcd-1234","kind":"socrata"}}`
	if err := DataPut(d, "sources", e); err != nil {
		t.Fatal(err)
	}
	a, err := DataAddrs(d, "data/a.csv")
	if err != nil || len(a) != 3 || a[0].Kind != "url" || a[1].Kind != "portal" ||
		a[2].Kind != "mirror" || a[1].URL != "https://data.example.org/api/views/abcd-1234.json" {
		t.Fatalf("addrs %v %v", a, err)
	}
	b, _ := os.ReadFile(filepath.Join(d, "data", "a.csv"))
	if ok, err := DataVerify(d, "data/a.csv", b); !ok || err != nil {
		t.Fatalf("verify %v %v", ok, err)
	}
	if ok, _ := DataVerify(d, "data/a.csv", b[1:]); ok {
		t.Fatal("other bytes verified")
	}
	if s, ok, _ := DataField(d, "sources", 0, "url"); !ok || s != "https://example.org/a.csv" {
		t.Fatalf("field %q", s)
	}
	if _, ok, _ := DataField(d, "sources", 0, "title"); ok {
		t.Fatal("a missing field")
	}
	if _, err := DataAddrs(d, "none.csv"); err == nil {
		t.Fatal("no such source")
	}
	wb := `{"base":"https://example.org/a.csv","kind":"wayback"}`
	r, _ := os.ReadFile(filepath.Join(v, "src", "wb.json"))
	u, tm, err := DataReply(wb, r)
	if err != nil || u != "https://web.archive.org/web/20240102030405id_/https://example.org/a.csv" ||
		tm != "2024-01-02T03:04:05Z" {
		t.Fatalf("reply %q %q %v", u, tm, err)
	}
	r, _ = os.ReadFile(filepath.Join(v, "src", "wb-none.json"))
	if _, _, err := DataReply(wb, r); err == nil {
		t.Fatal("no copy accepted")
	}
	if _, err := DataRequest(`{"base":"https://x.org/a","kind":"direct"}`); err == nil {
		t.Fatal("a direct resolver")
	}
	if s, _ := DataWayback("http://web.archive.org/web/2024/https://x.org/a"); s != "https://web.archive.org/web/2024id_/https://x.org/a" {
		t.Fatalf("wayback %q", s)
	}
}
