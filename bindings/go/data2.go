// SPDX-License-Identifier: LGPL-3.0-or-later

package noqtis

/*
#include <stdlib.h>
#include "nqd.h"
*/
import "C"

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"unsafe"
)

// SchemaCheckElem checks the CSV file of the "schemas" element schema
// (JSON text) in dir against it: header, types, missing values, ranges,
// sets, rows and rules.
func SchemaCheckElem(dir, schema string) (*DReport, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return nil, err
	}
	s, err := m.str(schema)
	if err != nil {
		return nil, err
	}
	var r *C.nqdrep
	c := C.nqdschk(d, s, C.size_t(len(schema)), &r)
	return dreport(c, r)
}

// withrec runs f on the record of dir and saves it when f succeeds.
func withrec(dir string, mk bool, f func(m *cmem, d *C.char, r *C.nqdrec) error) error {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return err
	}
	r, err := drec(d, mk)
	if err != nil {
		return err
	}
	defer C.nqdrfree(r)
	if err := f(&m, d, r); err != nil {
		return err
	}
	return rc(C.nqdsave(r, d))
}

// Synth writes a synthetic stand-in for the CSV file from its recorded
// schema (rows rows, 0: the schema's minimum, else 100; the same bytes
// for the same seed) and records it as a synthetic source. Real data is
// never replaced (ErrArg).
func Synth(dir, file string, seed, rows uint64) error {
	return withrec(dir, false, func(m *cmem, d *C.char, r *C.nqdrec) error {
		f, err := m.str(file)
		if err != nil {
			return err
		}
		var w [600]C.char
		if c := C.nqdsyn(r, d, f, C.uint64_t(seed), C.uint64_t(rows), &w[0], 600); c != 0 {
			return dfail(c, &w[0])
		}
		return nil
	})
}

// wtext is the text a call writes, with its sentence on failure.
func wtext(f func(o *C.char, cp C.size_t, n *C.size_t, w *C.char) C.int) (string, error) {
	w := (*C.char)(C.calloc(600, 1))
	defer C.free(unsafe.Pointer(w))
	s, c := grow(func(o *C.char, cp C.size_t, n *C.size_t) C.int { return f(o, cp, n, w) })
	if c != 0 {
		return "", dfail(c, w)
	}
	return s, nil
}

// Calibrate calibrates the drift warnings of file's summary on files,
// CSV files known not to have drifted from it, and records the result:
// Drift then warns only beyond what they showed. The element.
func Calibrate(dir, file string, files []string, o *CSVOpts) (string, error) {
	var e string
	err := withrec(dir, false, func(m *cmem, d *C.char, r *C.nqdrec) error {
		s, ok, err := dkey(m, r, "stats", file)
		if err != nil {
			return err
		}
		if !ok {
			return why(-7, "no summary of %s: pin one first", file)
		}
		fs, err := m.strs(files)
		if err != nil {
			return err
		}
		co, err := m.csvopt(o)
		if err != nil {
			return err
		}
		sc, err := m.str(s)
		if err != nil {
			return err
		}
		e, err = wtext(func(out *C.char, cp C.size_t, n *C.size_t, w *C.char) C.int {
			return C.nqddcal(sc, C.size_t(len(s)), fs, C.size_t(len(files)), co, out, cp, n, w, 600)
		})
		if err != nil {
			return err
		}
		return dput(m, r, "stats", e)
	})
	return e, err
}

// Chunks records the SHA-256 of each chunk bytes (1,024 to 2^30) of the
// large file, so that a piece of it can be checked alone (Piece). The
// element.
func Chunks(dir, file string, chunk uint64) (string, error) {
	var e string
	err := withrec(dir, true, func(m *cmem, d *C.char, r *C.nqdrec) error {
		f, err := m.str(file)
		if err != nil {
			return err
		}
		e, err = wtext(func(out *C.char, cp C.size_t, n *C.size_t, w *C.char) C.int {
			return C.nqdchunk(d, f, C.uint64_t(chunk), out, cp, n, w, 600)
		})
		if err != nil {
			return err
		}
		return dput(m, r, "chunks", e)
	})
	return e, err
}

// Piece checks the file piece, the bytes of file from byte off on (a
// multiple of its chunk), against its recorded chunk digests.
func Piece(dir, file, piece string, off uint64) (*DReport, error) {
	e, ok, err := DataKey(dir, "chunks", file)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, why(-7, "no chunk digests of %s: record them first", file)
	}
	var m cmem
	defer m.free()
	ec, err := m.str(e)
	if err != nil {
		return nil, err
	}
	p, err := m.str(piece)
	if err != nil {
		return nil, err
	}
	var r *C.nqdrep
	c := C.nqdpiece(ec, C.size_t(len(e)), p, C.uint64_t(off), &r)
	return dreport(c, r)
}

// Commitment is the commitment to msg under salt (16 to 1,024 bytes): 64
// hex digits of SHA3-256 (nqdcommit(3)).
func Commitment(salt, msg []byte) (string, error) {
	var hx [65]C.char
	if err := rc(C.nqdcommit(u8(salt), sz(salt), u8(msg), sz(msg), &hx[0])); err != nil {
		return "", err
	}
	return C.GoString(&hx[0]), nil
}

// CommitOpts are what Commit records besides the digest: Kind
// "randomisation", "preregistration" or "other" ("" is "other"), a
// Label, and After, a UTC time YYYY-MM-DDTHH:MM:SSZ before which it is
// not to be revealed.
type CommitOpts struct{ Kind, Label, After string }

// Commit commits to msg (a randomisation list, an analysis plan) in the
// record as noqtis commit does, and returns the 32-byte secret salt:
// keep it outside the capsule until the reveal, and Wipe it.
func Commit(dir string, msg []byte, o *CommitOpts) ([]byte, error) {
	if o == nil {
		o = &CommitOpts{}
	}
	salt := make([]byte, 32)
	if err := rc(C.nqrand(u8(salt), 32)); err != nil {
		return nil, err
	}
	h, err := Commitment(salt, msg)
	if err != nil {
		return nil, err
	}
	k := o.Kind
	if k == "" {
		k = "other"
	}
	e := map[string]string{"kind": k, "created": now(), "alg": "sha3-256", "digest": h}
	if o.Label != "" {
		e["label"] = o.Label
	}
	if o.After != "" {
		e["after"] = o.After
	}
	b, _ := json.Marshal(e)
	if err := DataPut(dir, "commits", string(b)); err != nil {
		return nil, err
	}
	return salt, nil
}

// Reveal is the index in "commits" of the commitment to msg under salt;
// ok is false when the record has none (every digest compared in
// constant time).
func Reveal(dir string, msg, salt []byte) (int, bool, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return 0, false, err
	}
	r, err := drec(d, false)
	if err != nil {
		return 0, false, err
	}
	defer C.nqdrfree(r)
	var i C.size_t
	switch c := C.nqdreveal(r, u8(salt), sz(salt), u8(msg), sz(msg), &i); c {
	case 0:
		return int(i), true, nil
	case -3:
		return 0, false, nil
	default:
		return 0, false, cerr(int(c))
	}
}

// Cite is how to cite the data, from the record's "cite": a CITATION.cff
// (bib false) or a BibTeX entry.
func Cite(dir string, bib bool) (string, error) {
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
	f := C.int(1)
	if bib {
		f = 2
	}
	s, c := grow(func(o *C.char, cp C.size_t, n *C.size_t) C.int { return C.nqdcite(r, f, o, cp, n) })
	return s, rc(c)
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// DataReport is a report of the capsule, as noqtis report writes it:
// whether every check passed, the capsule's check (with pk the seal
// must be by that key), what the data record says and its check;
// Markdown, or plain text with txt.
func DataReport(dir string, pk []byte, txt bool) (string, error) {
	sealed := exists(filepath.Join(dir, "noqtis.sig"))
	hasrec := exists(filepath.Join(dir, "noqtis.data.json"))
	if !sealed && !hasrec {
		return "", why(-7, "%s holds neither a seal nor a data record", dir)
	}
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return "", err
	}
	o, err := m.copt(&CheckOpts{Trust: pk})
	if err != nil {
		return "", err
	}
	var cr *C.nqrep
	var dr *C.nqdrep
	if sealed {
		if c := C.nqchkx(d, o, &cr); cr == nil {
			return "", cerr(int(c))
		}
		defer C.nqrepfree(cr)
	}
	if hasrec {
		if c := C.nqdchk(d, &dr); dr == nil {
			return "", cerr(int(c))
		}
		defer C.nqdrepfree(dr)
	}
	f := C.int(1)
	if txt {
		f = 2
	}
	s, c := grow(func(out *C.char, cp C.size_t, n *C.size_t) C.int { return C.nqdrpt(d, cr, dr, f, out, cp, n) })
	return s, rc(c)
}

// Pack writes the capsule in dir as one file (noqtis-bundle-1), as
// noqtis pack does: its seal, manifest, evidence record and every listed
// file (files false: only its data record). file must not exist. Check
// the capsule first.
func Pack(dir, file string, files bool) error {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return err
	}
	f, err := m.str(file)
	if err != nil {
		return err
	}
	fl := C.int(0)
	if files {
		fl = 1
	}
	return rc(C.nqdpack(d, fl, f))
}

func unpack(file, dir string, rm bool) error {
	var m cmem
	defer m.free()
	f, err := m.str(file)
	if err != nil {
		return err
	}
	d, err := m.str(dir)
	if err != nil {
		return err
	}
	r := C.int(0)
	if rm {
		r = 1
	}
	var w [600]C.char
	if c := C.nqdunpack(f, d, r, &w[0], 600); c != 0 {
		return dfail(c, &w[0])
	}
	return nil
}

// Unpack reads a bundle into the new folder dir, refusing it whole
// (ErrDecode with what is wrong) when any path or size is not one a
// capsule holds. Check dir after.
func Unpack(file, dir string) error { return unpack(file, dir, false) }

// CheckPack is Check of the capsule in the bundle file, read in place:
// unpacked to a new temporary folder, checked and removed.
func CheckPack(file string, o *CheckOpts) (*Report, error) {
	t, err := os.MkdirTemp("", "noqtis-")
	if err != nil {
		return nil, why(-7, "%v", err)
	}
	defer os.RemoveAll(t)
	d := filepath.Join(t, "c")
	if err := unpack(file, d, false); err != nil {
		return nil, err
	}
	r, err := Check(d, o)
	if e := unpack(file, d, true); e != nil && err == nil {
		err = e
	}
	return r, err
}

// Chain checks an append-only chain of capsules, oldest first (each
// sealed in format 2 with the one before as its only input, all by the
// first one's key): the report ("link", "key" and "head" rows) and the
// last capsule's id; ok is false unless every row passed. o's Trust and
// Anchors are used.
func Chain(dirs []string, o *CheckOpts) (*DReport, [32]byte, bool, error) {
	var head [32]byte
	var m cmem
	defer m.free()
	ds, err := m.strs(dirs)
	if err != nil {
		return nil, head, false, err
	}
	co, err := m.copt(o)
	if err != nil {
		return nil, head, false, err
	}
	co.only, co.nonly, co.lin, co.nlin = nil, 0, nil, 0
	h := (*C.uint8_t)(m.alloc(32, 1))
	var r *C.nqdrep
	c := C.nqdchain(ds, C.size_t(len(dirs)), co, h, &r)
	rep, err := dreport(c, r)
	if err != nil {
		return nil, head, false, err
	}
	copy(head[:], C.GoBytes(unsafe.Pointer(h), 32))
	return rep, head, rep.OK(), nil
}

// Pkg is one package of the record's runtime.
type Pkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"`
}

// Packages are the modules the running program was built with, from its
// build information (no network): the main module and every dependency,
// with the source "go" (a replaced module's source is its replacement's
// path), sorted by name.
func Packages() []Pkg {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	var out []Pkg
	add := func(x *debug.Module) {
		if x == nil || x.Path == "" {
			return
		}
		s := "go"
		if x.Replace != nil {
			s = x.Replace.Path
		}
		out = append(out, Pkg{Name: x.Path, Version: x.Version, Source: s})
	}
	add(&bi.Main)
	for _, d := range bi.Deps {
		add(d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// EnvOpts are what Env records besides the platform: Rng and Seed, the
// random number generator and its seed; Locks, the lock files to record
// (nil: the known ones at the top of dir); Pkgs, the packages (nil:
// Packages()).
type EnvOpts struct {
	Rng, Seed string
	Locks     []string
	Pkgs      []Pkg
}

// Locks are the lock files Env records when they are at the top of the
// folder.
var Locks = []string{"renv.lock", "uv.lock", "poetry.lock", "Pipfile.lock",
	"requirements.txt", "Cargo.lock", "go.sum", "package-lock.json",
	"pnpm-lock.yaml", "yarn.lock", "environment.yml", "Manifest.toml"}

func osname() string {
	switch runtime.GOOS {
	case "windows", "linux", "freebsd", "openbsd", "netbsd":
		return runtime.GOOS
	case "darwin":
		return "macos"
	}
	return "other"
}

func archname() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "386":
		return "i686"
	case "arm", "s390x":
		return runtime.GOARCH
	case "riscv64":
		return "riscv"
	case "wasm":
		return "wasm32"
	}
	return "other"
}

// dsha is the SHA-256 of the file f in dir, opened from dir without
// following a link (nqdsha), and the library's code
func dsha(dir, f string) ([]byte, C.int, error) {
	var m cmem
	defer m.free()
	dc, err := m.str(dir)
	if err != nil {
		return nil, -1, err
	}
	fc, err := m.str(f)
	if err != nil {
		return nil, -1, err
	}
	h := make([]byte, 32)
	c := C.nqdsha(dc, fc, (*C.uint8_t)(unsafe.Pointer(&h[0])), nil)
	switch c {
	case 0:
		return h, 0, nil
	case -1:
		return nil, c, why(-1, "%s: a link or not a plain file, refused", f)
	}
	return nil, c, why(int(c), "%s: cannot be read", f)
}

// Env records the environment in the record's "env", as noqtis env does
// (os, arch, noqtis, locale, tz, the lock files at the top of dir with
// their SHA-256, the rng and its seed), with the Go runtime: its version
// and the packages. The element.
func Env(dir string, o *EnvOpts) (string, error) {
	if o == nil {
		o = &EnvOpts{}
	}
	if o.Seed != "" && o.Rng == "" {
		return "", why(-1, "Seed needs Rng, the generator it seeds")
	}
	e := map[string]any{"os": osname(), "arch": archname(), "noqtis": Version()}
	if l := os.Getenv("LC_ALL"); l != "" {
		e["locale"] = l
	} else if l := os.Getenv("LANG"); l != "" {
		e["locale"] = l
	}
	if t := os.Getenv("TZ"); t != "" {
		e["tz"] = t
	}
	p := o.Pkgs
	if p == nil {
		p = Packages()
	}
	if p == nil {
		p = []Pkg{}
	}
	sort.Slice(p, func(i, j int) bool { return p[i].Name < p[j].Name })
	e["runtime"] = map[string]any{"language": "go", "version": runtime.Version(), "packages": p}
	want := o.Locks
	if want == nil {
		want = Locks
	}
	var lk []map[string]string
	for _, f := range want {
		h, c, err := dsha(dir, f)
		if c == -7 && o.Locks == nil {
			continue
		}
		if c == -7 {
			return "", why(-1, "%s: not a file in %s", f, dir)
		}
		if err != nil {
			return "", err
		}
		lk = append(lk, map[string]string{"path": f, "sha256": hex.EncodeToString(h)})
	}
	sort.Slice(lk, func(i, j int) bool { return lk[i]["path"] < lk[j]["path"] })
	if lk != nil {
		e["locks"] = lk
	}
	if o.Rng != "" {
		g := map[string]string{"kind": o.Rng}
		if o.Seed != "" {
			g["seed"] = o.Seed
		}
		e["rng"] = g
	}
	b, err := json.Marshal(e)
	if err != nil {
		return "", why(-1, "%v", err)
	}
	if err := DataPut(dir, "env", string(b)); err != nil {
		return "", err
	}
	return string(b), nil
}
