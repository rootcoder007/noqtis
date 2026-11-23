// SPDX-License-Identifier: LGPL-3.0-or-later

package noqtis

/*
#include <stdlib.h>
#include <string.h>
#include "noqtis.h"
*/
import "C"

import (
	"fmt"
	"strings"
	"unsafe"
)

// Row is one check of a capsule: its name, whether it passed, and what
// was found.
type Row struct {
	Check  string // "manifest.digest", "file", "key", "info.alg", ...
	OK     bool
	Detail string
}

// Report is what a check (or Inspect) found: every row, and the
// library's return code (0, or a negative NQE* code such as -3 when a
// check failed).
type Report struct {
	Code int
	Rows []Row
}

// OK reports whether every check made passed. With Partial true those
// checks left files out (Only, a proof), and OK says nothing of the
// others: the capsule passed as a whole only when OK() && !Partial().
func (r *Report) OK() bool {
	if r.Code != 0 {
		return false
	}
	for _, x := range r.Rows {
		if !x.OK {
			return false
		}
	}
	return true
}

// Partial reports whether only some files were checked (a "partial"
// row says which were left out).
func (r *Report) Partial() bool {
	_, p := r.Get("partial")
	return p
}

// Failed lists the rows that did not pass.
func (r *Report) Failed() []Row {
	var out []Row
	for _, x := range r.Rows {
		if !x.OK {
			out = append(out, x)
		}
	}
	return out
}

// Get is the first row of that name ("info.alg", "key", ...).
func (r *Report) Get(check string) (Row, bool) {
	for _, x := range r.Rows {
		if x.Check == check {
			return x, true
		}
	}
	return Row{}, false
}

func (r *Report) String() string {
	var b strings.Builder
	for _, x := range r.Rows {
		s := "ok"
		if !x.OK {
			s = "FAIL"
		}
		fmt.Fprintf(&b, "%-4s %s: %s\n", s, x.Check, x.Detail)
	}
	return b.String()
}

// CheckOpts are what Check and CheckProof check beyond the seal itself;
// a nil *CheckOpts, or any member left empty, is none.
type CheckOpts struct {
	// Trust is the public key the seal must carry; nil accepts the key
	// in the seal (the "key" row then says so).
	Trust []byte
	// Anchors are TSA trust anchors (DER certificates, at most 32): the
	// seal must then carry an RFC 3161 timestamp that verifies under one.
	Anchors [][]byte
	// Only makes a partial check of these paths ('/' separated).
	Only []string
	// Lineage lists capsule folders to find a format 2 capsule's inputs in.
	Lineage []string
	// Stmts are key statements (noqtis-keys-1), at most 32; they need Trust.
	Stmts [][]byte
}

// Input is an input of a format 2 capsule: the input capsule's id
// (CapID) and a short name for it (1 to 255 bytes of UTF-8).
type Input struct {
	ID   [32]byte
	Name string
}

// cmem holds C copies of Go data for one call; free releases them.
type cmem struct{ ps []unsafe.Pointer }

func (m *cmem) put(p unsafe.Pointer) unsafe.Pointer {
	m.ps = append(m.ps, p)
	return p
}

func (m *cmem) str(s string) (*C.char, error) {
	if strings.IndexByte(s, 0) >= 0 {
		return nil, why(-1, "a NUL byte in %q", s)
	}
	return (*C.char)(m.put(unsafe.Pointer(C.CString(s)))), nil
}

func (m *cmem) bytes(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return (*C.uint8_t)(m.put(C.calloc(1, 1)))
	}
	return (*C.uint8_t)(m.put(C.CBytes(b)))
}

func (m *cmem) alloc(n, size uintptr) unsafe.Pointer {
	return m.put(C.calloc(C.size_t(n), C.size_t(size)))
}

func (m *cmem) free() {
	for _, p := range m.ps {
		C.free(p)
	}
	m.ps = nil
}

// strs is a C array of C strings, or nil when ss is empty.
func (m *cmem) strs(ss []string) (**C.char, error) {
	if len(ss) == 0 {
		return nil, nil
	}
	a := unsafe.Slice((**C.char)(m.alloc(uintptr(len(ss)), unsafe.Sizeof((*C.char)(nil)))), len(ss))
	for i, s := range ss {
		c, err := m.str(s)
		if err != nil {
			return nil, err
		}
		a[i] = c
	}
	return &a[0], nil
}

// blobs is a C array of byte buffers and one of their lengths.
func (m *cmem) blobs(bs [][]byte) (**C.uint8_t, *C.size_t) {
	if len(bs) == 0 {
		return nil, nil
	}
	a := unsafe.Slice((**C.uint8_t)(m.alloc(uintptr(len(bs)), unsafe.Sizeof((*C.uint8_t)(nil)))), len(bs))
	l := unsafe.Slice((*C.size_t)(m.alloc(uintptr(len(bs)), unsafe.Sizeof(C.size_t(0)))), len(bs))
	for i, b := range bs {
		a[i] = m.bytes(b)
		l[i] = C.size_t(len(b))
	}
	return &a[0], &l[0]
}

// copt is the C view of o, in C memory.
func (m *cmem) copt(o *CheckOpts) (*C.nqcopt, error) {
	x := (*C.nqcopt)(m.alloc(1, unsafe.Sizeof(C.nqcopt{})))
	if o == nil {
		return x, nil
	}
	if o.Trust != nil {
		x.trust = m.bytes(o.Trust)
		x.trustlen = C.size_t(len(o.Trust))
	}
	a, al := m.blobs(o.Anchors)
	x.anc = (**C.uint8_t)(unsafe.Pointer(a))
	x.anclen = al
	x.nanc = C.size_t(len(o.Anchors))
	var err error
	if x.only, err = m.strs(o.Only); err != nil {
		return nil, err
	}
	x.nonly = C.size_t(len(o.Only))
	if x.lin, err = m.strs(o.Lineage); err != nil {
		return nil, err
	}
	x.nlin = C.size_t(len(o.Lineage))
	s, sl := m.blobs(o.Stmts)
	x.stmt = (**C.char)(unsafe.Pointer(s))
	x.stmtlen = sl
	x.nstmt = C.size_t(len(o.Stmts))
	return x, nil
}

// report reads and frees the library's report, or is the error when it
// made none.
func report(c C.int, r *C.nqrep) (*Report, error) {
	if r == nil {
		if c == 0 {
			c = -10
		}
		return nil, cerr(int(c))
	}
	defer C.nqrepfree(r)
	out := &Report{Code: int(c)}
	n := C.nqrepn(r)
	for i := C.size_t(0); i < n; i++ {
		var ck, d *C.char
		var ok C.int
		if C.nqrepi(r, i, &ck, &ok, &d) != 0 {
			break
		}
		x := Row{OK: ok != 0}
		if ck != nil {
			x.Check = C.GoString(ck)
		}
		if d != nil {
			x.Detail = C.GoString(d)
		}
		out.Rows = append(out.Rows, x)
	}
	return out, nil
}

func seal(dir, alg string, sk, pk []byte, meta string, in []Input, ver int, skey []byte) error {
	a, err := find(alg, "sign")
	if err != nil {
		return err
	}
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return err
	}
	var mt *C.char
	if meta != "" {
		if mt, err = m.str(meta); err != nil {
			return err
		}
	}
	csk, cpk := m.bytes(sk), m.bytes(pk)
	if ver == 1 {
		return rc(C.nqseal(d, C.nqsalg(a.ID), csk, sz(sk), cpk, sz(pk), mt, nil))
	}
	var ci *C.nqcin
	if len(in) > 0 {
		ci = (*C.nqcin)(m.alloc(uintptr(len(in)), unsafe.Sizeof(C.nqcin{})))
		cs := unsafe.Slice(ci, len(in))
		for i, x := range in {
			for j := range x.ID {
				cs[i].id[j] = C.uint8_t(x.ID[j])
			}
			if cs[i].name, err = m.str(x.Name); err != nil {
				return err
			}
		}
	}
	if ver == 3 {
		var ck *C.uint8_t
		if len(skey) > 0 {
			ck = m.bytes(skey)
		}
		return rc(C.nqseal3(d, C.nqsalg(a.ID), csk, sz(sk), cpk, sz(pk), mt, ci, C.size_t(len(in)), ck, sz(skey)))
	}
	return rc(C.nqseal2(d, C.nqsalg(a.ID), csk, sz(sk), cpk, sz(pk), mt, ci, C.size_t(len(in))))
}

// Seal writes noqtis.json and noqtis.sig into dir, covering every
// regular file in it, in format 3 (Seal3 with no inputs and fresh salts,
// so two seals of the same files differ; Seal3 with a salt key gives a
// reproducible capsule). meta is JSON text (an object) kept in the
// manifest, or "" for none. The creation time is SOURCE_DATE_EPOCH when
// set, else the clock. Seal1 and Seal2 write the formats readers older
// than 0.3.0 read.
func Seal(dir, alg string, sk, pk []byte, meta string) error {
	return seal(dir, alg, sk, pk, meta, nil, 3, nil)
}

// Seal1 is Seal in format 1: the manifest is a flat list of the files,
// signed whole, with no Merkle tree (no proofs). It was Seal's format
// before 0.3.0.
func Seal1(dir, alg string, sk, pk []byte, meta string) error {
	return seal(dir, alg, sk, pk, meta, nil, 1, nil)
}

// Seal2 is Seal1 in format 2: the manifest also carries a Merkle tree
// over its entries, so that Prove can show single files without the
// rest's names, sizes or digests, and the capsules it was made from (at
// most 1024 inputs). Its leaves are unsalted: anyone who can guess a
// file not shown can confirm the guess from a proof. Seal3 salts them.
func Seal2(dir, alg string, sk, pk []byte, meta string, in []Input) error {
	return seal(dir, alg, sk, pk, meta, in, 2, nil)
}

// Seal3 is Seal2 in format 3: each entry also carries a secret 32-byte
// salt in its Merkle leaf, so that a proof lets no one confirm a guess of
// the files it does not show. saltKey nil draws fresh salts; else it is
// the 32-byte salt key they are derived from, for a reproducible
// capsule, to keep secret.
func Seal3(dir, alg string, sk, pk []byte, meta string, in []Input, saltKey []byte) error {
	if saltKey != nil && len(saltKey) != 32 {
		return ErrArg
	}
	return seal(dir, alg, sk, pk, meta, in, 3, saltKey)
}

// CapID is the id of the capsule in dir: the SHA-256 of the bytes its
// seal signs. Nothing else is checked: check the capsule first.
func CapID(dir string) ([32]byte, error) {
	var id [32]byte
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return id, err
	}
	b := (*C.uint8_t)(m.alloc(32, 1))
	if err := rc(C.nqcapid(d, b)); err != nil {
		return id, err
	}
	copy(id[:], C.GoBytes(unsafe.Pointer(b), 32))
	return id, nil
}

// Check checks dir against its seal, with the options of o. The report
// lists every check; Report.OK is true only when all passed. A failed
// check is a report, not an error.
func Check(dir string, o *CheckOpts) (*Report, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return nil, err
	}
	x, err := m.copt(o)
	if err != nil {
		return nil, err
	}
	var r *C.nqrep
	c := C.nqchkx(d, x, &r)
	return report(c, r)
}

// Inspect is what the capsule in dir says, with nothing checked: the
// report ends with info.format, info.alg, info.key, info.created,
// info.files, info.bytes, info.timestamp and, when there is one,
// info.meta.
func Inspect(dir string) (*Report, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return nil, err
	}
	var r *C.nqrep
	c := C.nqinsp(d, &r)
	return report(c, r)
}

// Files is Inspect with one "info.file" row per listed file first: its
// size, SHA-256 and path, with a space between.
func Files(dir string) (*Report, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return nil, err
	}
	var r *C.nqrep
	c := C.nqfiles(d, &r)
	return report(c, r)
}

// Prove is a proof (noqtis-proof-1, JSON) that the files paths are in
// the format 2 capsule in dir, which shows nothing of the other files.
// Check the capsule first.
func Prove(dir string, paths []string) ([]byte, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return nil, err
	}
	ps, err := m.strs(paths)
	if err != nil {
		return nil, err
	}
	var n C.size_t
	c := C.nqprove(d, ps, C.size_t(len(paths)), nil, 0, &n)
	if c != C.NQEBUF {
		if err := rc(c); err != nil {
			return nil, err
		}
	}
	out := (*C.char)(m.alloc(uintptr(n)+1, 1))
	if err := rc(C.nqprove(d, ps, C.size_t(len(paths)), out, n, &n)); err != nil {
		return nil, err
	}
	return C.GoBytes(unsafe.Pointer(out), C.int(n)), nil
}

// CheckProof checks a proof from Prove: its seal (with o's trusted key
// and TSA anchors; its other members are not used) and each entry's
// audit path; with dir (or ""), each proven file there against its
// entry.
func CheckProof(proof []byte, o *CheckOpts, dir string) (*Report, error) {
	var m cmem
	defer m.free()
	var d *C.char
	var err error
	if dir != "" {
		if d, err = m.str(dir); err != nil {
			return nil, err
		}
	}
	x, err := m.copt(o)
	if err != nil {
		return nil, err
	}
	p := (*C.char)(unsafe.Pointer(m.bytes(proof)))
	var r *C.nqrep
	c := C.nqchkp(p, C.size_t(len(proof)), x, d, &r)
	return report(c, r)
}
