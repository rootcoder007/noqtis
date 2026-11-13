// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

package noqtis

/*
#include <stdlib.h>
#include "nqd.h"
*/
import "C"

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

// The data record of a capsule (noqtis.data.json, noqtis-data-1) says
// where each data file came from, the schema of its CSV files, summaries
// that show drift later, and the steps and checks made with it. It is a
// file of the capsule like any other: seal the folder after changing it,
// and the seal covers it. Elements go in and come out as JSON text, and
// the library writes the record in canonical form, the same bytes the
// noqtis command and every other binding write.

// DRow is one row of a data check: its name ("record", "source",
// "schema", "rule", "drift", "drift.warn", "file", ...), whether it
// passed, why, and for a drift row its numbers as JSON text ("" when it
// has none).
type DRow struct {
	Check  string
	OK     bool
	Detail string
	Stats  string
}

// DReport is what a data check found: every row, and the library's
// return code (0, or -3 when a row failed).
type DReport struct {
	Code int
	Rows []DRow
}

// OK reports whether the library passed it as a whole (and there was a
// row). A diff with no difference has no row: see Same.
func (r *DReport) OK() bool {
	if r.Code != 0 || len(r.Rows) == 0 {
		return false
	}
	for _, x := range r.Rows {
		if !x.OK {
			return false
		}
	}
	return true
}

// Failed lists the rows that did not pass.
func (r *DReport) Failed() []DRow {
	var out []DRow
	for _, x := range r.Rows {
		if !x.OK {
			out = append(out, x)
		}
	}
	return out
}

// Same reports, for Diff, that nothing differs.
func (r *DReport) Same() bool { return r.Code == 0 }

// Level is "ok", "warn" (a "drift.warn" row and none failed) or "fail".
func (r *DReport) Level() string {
	if !r.OK() {
		return "fail"
	}
	for _, x := range r.Rows {
		if x.Check == "drift.warn" {
			return "warn"
		}
	}
	return "ok"
}

// Src says where a source file came from, for DataAdd; every member may
// be empty. Retrieved is "now" (SOURCE_DATE_EPOCH when set, else the
// clock) or a UTC time YYYY-MM-DDTHH:MM:SSZ.
type Src struct {
	URL, Title, Publisher, Licence, Retrieved string
	Synthetic                                 bool
}

// CSVOpts say how a CSV file is read; nil is a header line and ','.
// Delim is one ASCII byte (0 for ','); NoHeader when the first line is
// data; Ranges makes Schema pin number and date ranges too.
type CSVOpts struct {
	Delim    byte
	NoHeader bool
	Ranges   bool
}

// DriftOpts say when Drift calls a column drifted (noqtis-drift(1));
// nil is the defaults: PSIWarn 0.1, PSIFail 0.25, Alpha 0.001, MinN
// 1000, no Benford test.
type DriftOpts struct {
	PSIWarn, PSIFail, Alpha, MinN float64
	Benford                       bool
}

func dfail(c C.int, w *C.char) error {
	if s := C.GoString(w); s != "" {
		return why(int(c), "%s", s)
	}
	return cerr(int(c))
}

// grow is the text a call writes to (out, cap), its length to *n: tried
// with 64 KiB, then once more with room for all of it (NQEBUF).
func grow(f func(out *C.char, cp C.size_t, n *C.size_t) C.int) (string, C.int) {
	cp := C.size_t(1 << 16)
	for {
		b := (*C.char)(C.malloc(cp))
		var n C.size_t
		c := f(b, cp, &n)
		if c == -2 && n+1 > cp {
			C.free(unsafe.Pointer(b))
			cp = n + 1
			continue
		}
		s := ""
		if c == 0 {
			s = C.GoStringN(b, C.int(n))
		}
		C.free(unsafe.Pointer(b))
		return s, c
	}
}

// drec is the record of dir; with mk, a new one when there is none.
func drec(d *C.char, mk bool) (*C.nqdrec, error) {
	var r *C.nqdrec
	var w [600]C.char
	c := C.nqdload(d, &r, &w[0], 600)
	if c == -7 && mk {
		c = C.nqdnew(&r)
	}
	if c != 0 {
		return nil, dfail(c, &w[0])
	}
	return r, nil
}

func djson(r *C.nqdrec) (string, error) {
	s, c := grow(func(o *C.char, cp C.size_t, n *C.size_t) C.int { return C.nqdjson(r, o, cp, n) })
	if c != 0 {
		return "", cerr(int(c))
	}
	return s, nil
}

func dput(m *cmem, r *C.nqdrec, member, js string) error {
	mc, err := m.str(member)
	if err != nil {
		return err
	}
	jc, err := m.str(js)
	if err != nil {
		return err
	}
	var w [600]C.char
	if c := C.nqdput(r, mc, jc, C.size_t(len(js)), &w[0], 600); c != 0 {
		return dfail(c, &w[0])
	}
	return nil
}

func dkey(m *cmem, r *C.nqdrec, member, key string) (string, bool, error) {
	mc, err := m.str(member)
	if err != nil {
		return "", false, err
	}
	kc, err := m.str(key)
	if err != nil {
		return "", false, err
	}
	s, c := grow(func(o *C.char, cp C.size_t, n *C.size_t) C.int { return C.nqdkey(r, mc, kc, o, cp, n) })
	if c == -7 {
		return "", false, nil
	}
	if c != 0 {
		return "", false, cerr(int(c))
	}
	return s, true, nil
}

// dreport reads and frees the library's report, or is the error when it
// made none.
func dreport(c C.int, r *C.nqdrep) (*DReport, error) {
	if r == nil {
		if c == 0 {
			c = -10
		}
		return nil, cerr(int(c))
	}
	defer C.nqdrepfree(r)
	out := &DReport{Code: int(c)}
	for i := C.size_t(0); i < C.nqdrepn(r); i++ {
		var ck, d *C.char
		var ok C.int
		if C.nqdrepi(r, i, &ck, &ok, &d) != 0 {
			break
		}
		x := DRow{Check: C.GoString(ck), OK: ok != 0, Detail: C.GoString(d)}
		if j := C.nqdrepj(r, i); j != nil {
			x.Stats = C.GoString(j)
		}
		out.Rows = append(out.Rows, x)
	}
	return out, nil
}

func (m *cmem) csvopt(o *CSVOpts) (*C.nqdcsvopt, error) {
	x := (*C.nqdcsvopt)(m.alloc(1, unsafe.Sizeof(C.nqdcsvopt{})))
	if o == nil {
		return x, nil
	}
	if o.Delim > 127 {
		return nil, why(-1, "Delim must be one ASCII character")
	}
	x.delim = C.char(o.Delim)
	if o.NoHeader {
		x.noheader = 1
	}
	if o.Ranges {
		x.ranges = 1
	}
	return x, nil
}

// DataText is the record in dir as its canonical JSON text.
func DataText(dir string) (string, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return "", err
	}
	r, err := drec(d, false)
	if err != nil {
		return "", err
	}
	defer C.nqdrfree(r)
	return djson(r)
}

// DataCanon is the JSON text of a record in canonical form, after
// checking it as the library checks a record it reads (the bytes
// DataText gives for it).
func DataCanon(js string) (string, error) {
	var m cmem
	defer m.free()
	j, err := m.str(js)
	if err != nil {
		return "", err
	}
	var r *C.nqdrec
	var w [600]C.char
	if c := C.nqdparse(j, C.size_t(len(js)), &r, &w[0], 600); c != 0 {
		return "", dfail(c, &w[0])
	}
	defer C.nqdrfree(r)
	return djson(r)
}

func now() string {
	t := time.Now()
	if e := os.Getenv("SOURCE_DATE_EPOCH"); e != "" {
		if s, err := strconv.ParseInt(e, 10, 64); err == nil {
			t = time.Unix(s, 0)
		}
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// DataAdd records each file's SHA-256 and size (paths relative to dir,
// '/' between folders) as a source, keeping what the record already
// says of it, with where it came from (s, may be nil). It makes the
// record when there is none.
func DataAdd(dir string, files []string, s *Src) error {
	if s == nil {
		s = &Src{}
	}
	if s.URL != "" && len(files) > 1 {
		return why(-1, "URL describes one file: add the files one at a time")
	}
	ret := s.Retrieved
	if ret == "now" {
		ret = now()
	}
	var f [][2]string
	for _, kv := range [][2]string{{"url", s.URL}, {"title", s.Title},
		{"publisher", s.Publisher}, {"licence", s.Licence}, {"retrieved", ret}} {
		if kv[1] != "" {
			b, _ := json.Marshal(kv[1])
			f = append(f, [2]string{kv[0], string(b)})
		}
	}
	if s.Synthetic {
		f = append(f, [2]string{"synthetic", "true"})
	}
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return err
	}
	r, err := drec(d, true)
	if err != nil {
		return err
	}
	defer C.nqdrfree(r)
	src, _ := m.str("sources")
	var w [600]C.char
	for _, p := range files {
		pc, err := m.str(p)
		if err != nil {
			return err
		}
		if c := C.nqdsrc(r, d, pc, &w[0], 600); c != 0 {
			return dfail(c, &w[0])
		}
		for _, kv := range f {
			k, _ := m.str(kv[0])
			v, err := m.str(kv[1])
			if err != nil {
				return err
			}
			if c := C.nqdset(r, src, pc, k, v, C.size_t(len(kv[1])), &w[0], 600); c != 0 {
				return dfail(c, &w[0])
			}
		}
	}
	if c := C.nqdsave(r, d); c != 0 {
		return cerr(int(c))
	}
	return nil
}

// DataPut adds an element (JSON text) to a member: "sources", "schemas",
// "stats", "chunks" (the one with the same path is replaced), "checks"
// (the same name), "steps", "commits" (appended), or sets "env" or
// "cite". It makes the record when there is none.
func DataPut(dir, member, js string) error {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return err
	}
	r, err := drec(d, true)
	if err != nil {
		return err
	}
	defer C.nqdrfree(r)
	if err := dput(&m, r, member, js); err != nil {
		return err
	}
	if c := C.nqdsave(r, d); c != 0 {
		return cerr(int(c))
	}
	return nil
}

// DataDel removes the element of member with path or name key, or the
// whole member when key is "".
func DataDel(dir, member, key string) error {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return err
	}
	mc, err := m.str(member)
	if err != nil {
		return err
	}
	var kc *C.char
	if key != "" {
		if kc, err = m.str(key); err != nil {
			return err
		}
	}
	r, err := drec(d, false)
	if err != nil {
		return err
	}
	defer C.nqdrfree(r)
	if c := C.nqddel(r, mc, kc); c != 0 {
		return cerr(int(c))
	}
	if c := C.nqdsave(r, d); c != 0 {
		return cerr(int(c))
	}
	return nil
}

// DataKey is the element of a keyed member ("sources", "schemas",
// "stats", "chunks" by path, "checks" by name) with key; false when
// there is none.
func DataKey(dir, member, key string) (string, bool, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return "", false, err
	}
	r, err := drec(d, false)
	if err != nil {
		return "", false, err
	}
	defer C.nqdrfree(r)
	return dkey(&m, r, member, key)
}

// DataCheck checks the record and every file it lists: each source's
// SHA-256 and size, each schema and its rules, and the checks recorded
// as failed.
func DataCheck(dir string) (*DReport, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return nil, err
	}
	var r *C.nqdrep
	c := C.nqdchk(d, &r)
	return dreport(c, r)
}

// Schema is the schema of the CSV file in dir as a "schemas" element:
// its columns with the narrowest type of each, missing values, rows
// (with o.Ranges, number and date ranges too). DataPut records it.
func Schema(dir, file string, o *CSVOpts) (string, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return "", err
	}
	f, err := m.str(file)
	if err != nil {
		return "", err
	}
	co, err := m.csvopt(o)
	if err != nil {
		return "", err
	}
	w := (*C.char)(m.alloc(600, 1))
	s, c := grow(func(out *C.char, cp C.size_t, n *C.size_t) C.int {
		return C.nqdinfer(d, f, co, out, cp, n, w, 600)
	})
	if c != 0 {
		return "", dfail(c, w)
	}
	return s, nil
}

// SchemaCheck is the "schema" and "rule" rows of DataCheck, of the files
// named only when files is not empty.
func SchemaCheck(dir string, files []string) (*DReport, error) {
	r, err := DataCheck(dir)
	if err != nil {
		return nil, err
	}
	out := &DReport{Code: -3}
	for _, x := range r.Rows {
		if x.Check != "schema" && x.Check != "rule" {
			continue
		}
		p := strings.TrimSuffix(strings.SplitN(x.Detail, ":", 2)[0], " [synthetic]")
		keep := len(files) == 0
		for _, f := range files {
			keep = keep || f == p
		}
		if keep {
			out.Rows = append(out.Rows, x)
		}
	}
	if len(out.Rows) > 0 {
		out.Code = 0
		for _, x := range out.Rows {
			if !x.OK {
				out.Code = -3
			}
		}
	}
	return out, nil
}

// Pin records each CSV file's summaries (a "stats" element,
// noqtis-drift(1)) in the record, which Drift later compares a file with.
func Pin(dir string, files []string, o *CSVOpts) error {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return err
	}
	co, err := m.csvopt(o)
	if err != nil {
		return err
	}
	r, err := drec(d, true)
	if err != nil {
		return err
	}
	defer C.nqdrfree(r)
	w := (*C.char)(m.alloc(600, 1))
	for _, p := range files {
		f, err := m.str(p)
		if err != nil {
			return err
		}
		s, c := grow(func(out *C.char, cp C.size_t, n *C.size_t) C.int {
			return C.nqdstats(d, f, co, out, cp, n, w, 600)
		})
		if c != 0 {
			return dfail(c, w)
		}
		if err := dput(&m, r, "stats", s); err != nil {
			return err
		}
	}
	if c := C.nqdsave(r, d); c != 0 {
		return cerr(int(c))
	}
	return nil
}

// Drift compares each summarised file (or the file of current in its
// place) with its summary: Kolmogorov-Smirnov, PSI and Jensen-Shannon,
// chi-square of homogeneity, Benford (noqtis-drift(1)). files empty:
// every file the record summarises; current empty: the files
// themselves, else one path per file.
func Drift(dir string, files, current []string, o *CSVOpts, do *DriftOpts) (*DReport, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return nil, err
	}
	r, err := drec(d, false)
	if err != nil {
		return nil, err
	}
	defer C.nqdrfree(r)
	if len(files) == 0 {
		var rec struct {
			Stats []struct{ Path string } `json:"stats"`
		}
		js, err := djson(r)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(js), &rec); err != nil {
			return nil, why(-4, "%v", err)
		}
		for _, s := range rec.Stats {
			files = append(files, s.Path)
		}
	}
	if len(files) == 0 {
		return nil, why(-1, "the record has no summaries: pin some first")
	}
	if len(current) != 0 && len(current) != len(files) {
		return nil, why(-1, "current needs one path per file")
	}
	co, err := m.csvopt(o)
	if err != nil {
		return nil, err
	}
	if do == nil {
		do = &DriftOpts{0.1, 0.25, 0.001, 1000, false}
	}
	dop := (*C.nqddopt)(m.alloc(1, unsafe.Sizeof(C.nqddopt{})))
	dop.psiwarn, dop.psifail = C.double(do.PSIWarn), C.double(do.PSIFail)
	dop.alpha, dop.minn = C.double(do.Alpha), C.double(do.MinN)
	if do.Benford {
		dop.benford = 1
	}
	out := &DReport{}
	for i, f := range files {
		s, ok, err := dkey(&m, r, "stats", f)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, why(-1, "no summary of %s: pin one first", f)
		}
		p := filepath.Join(dir, filepath.FromSlash(f))
		if len(current) != 0 {
			p = current[i]
		}
		pc, err := m.str(p)
		if err != nil {
			return nil, err
		}
		sc, _ := m.str(s)
		var rp *C.nqdrep
		c := C.nqddrift(sc, C.size_t(len(s)), pc, co, dop, &rp)
		x, err := dreport(c, rp)
		if err != nil {
			return nil, err
		}
		if out.Code == 0 {
			out.Code = x.Code
		}
		out.Rows = append(out.Rows, x.Rows...)
	}
	return out, nil
}

// Diff is what changed from capsule a to capsule b: one failed row per
// difference (files, sources, schemas, summaries, env, ...); Same when
// nothing differs.
func Diff(a, b string) (*DReport, error) {
	var m cmem
	defer m.free()
	ac, err := m.str(a)
	if err != nil {
		return nil, err
	}
	bc, err := m.str(b)
	if err != nil {
		return nil, err
	}
	var r *C.nqdrep
	c := C.nqddiff(ac, bc, &r)
	return dreport(c, r)
}
