// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// Package noqtis is the Go binding of the noqtis C library: post-quantum
// signatures (ML-DSA, SLH-DSA, and Ed25519 with the ML-DSA hybrids), key
// encapsulation (ML-KEM, HQC), SHA-2 and SHA-3 hashes and HMAC, sealed
// file capsules, and the CLI's key files.
//
// The library is compiled into the package with cgo, from the copy in
// csrc/ (tools/vendor.sh makes it); a C11 compiler is all it needs.
// Algorithms are named as `noqtis algs` lists them ("ML-DSA-65",
// "ML-KEM-768", ...), in any case. Every error is an *Error carrying the
// library's NQE* code and its message.
package noqtis

/*
#cgo CFLAGS: -std=c11 -DNQBUILD -I${SRCDIR}/csrc/include -I${SRCDIR}/csrc/src
#cgo windows LDFLAGS: -lbcrypt
#include <stdlib.h>
#include "noqtis.h"
*/
import "C"

import (
	"fmt"
	"strings"
	"sync"
	"unsafe"
)

// Error is a failed noqtis call: Code is the library's NQE* code (-1
// for NQEARG, ...), Msg its message (nqerr), and Why, when set, what this
// package found wrong.
type Error struct {
	Code int
	Msg  string
	Why  string
}

func (e *Error) Error() string {
	if e.Why == "" {
		return "noqtis: " + e.Msg
	}
	return "noqtis: " + e.Msg + ": " + e.Why
}

// Is matches any *Error of the same code, so errors.Is(err, ErrVerify)
// works.
func (e *Error) Is(t error) bool {
	x, ok := t.(*Error)
	return ok && x.Code == e.Code
}

// One error per NQE* code of noqtis.h, for errors.Is.
var (
	ErrArg         = cerr(-1)
	ErrBuf         = cerr(-2)
	ErrVerify      = cerr(-3)
	ErrDecode      = cerr(-4)
	ErrRand        = cerr(-5)
	ErrMem         = cerr(-6)
	ErrIO          = cerr(-7)
	ErrUnsupported = cerr(-8)
	ErrLimit       = cerr(-9)
	ErrState       = cerr(-10)
)

// ErrMsg is the library's message for an NQE* code (nqerr).
func ErrMsg(code int) string {
	return C.GoString(C.nqerr(C.int(code)))
}

func cerr(code int) *Error {
	return &Error{Code: code, Msg: ErrMsg(code)}
}

func why(code int, f string, a ...any) *Error {
	e := cerr(code)
	e.Why = fmt.Sprintf(f, a...)
	return e
}

func rc(c C.int) error {
	if c == 0 {
		return nil
	}
	return cerr(int(c))
}

// u8 is the C view of b; nil when b is empty.
func u8(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func sz(b []byte) C.size_t { return C.size_t(len(b)) }

// Version is the library's version, "0.1.3".
func Version() string { return C.GoString(C.nqver()) }

// Alg is one algorithm and its sizes in bytes: Sig is 0 for a KEM, CT
// and SS are 0 for a signature algorithm.
type Alg struct {
	Name string // "ML-DSA-65", "ML-KEM-768", ...
	Kind string // "sign" or "kem"
	ID   int    // the library's nqsalg or nqkalg value
	PK   int
	SK   int
	Sig  int
	CT   int
	SS   int
}

var table = sync.OnceValue(func() []Alg {
	var out []Alg
	for i := 1; i < 64; i++ {
		var z C.nqssz
		if C.nqssize(C.nqsalg(i), &z) == 0 {
			out = append(out, Alg{Name: C.GoString(C.nqsname(C.nqsalg(i))),
				Kind: "sign", ID: i, PK: int(z.pk), SK: int(z.sk), Sig: int(z.sig)})
		}
	}
	for i := 1; i < 64; i++ {
		var z C.nqksz
		if C.nqksize(C.nqkalg(i), &z) == 0 {
			out = append(out, Alg{Name: C.GoString(C.nqkname(C.nqkalg(i))),
				Kind: "kem", ID: i, PK: int(z.pk), SK: int(z.sk), CT: int(z.ct), SS: int(z.ss)})
		}
	}
	return out
})

// Algs lists every algorithm with its sizes, the signature algorithms
// first.
func Algs() []Alg { return append([]Alg(nil), table()...) }

// Find is the algorithm of a name, in any case.
func Find(name string) (Alg, error) {
	for _, a := range table() {
		if strings.EqualFold(a.Name, name) {
			return a, nil
		}
	}
	return Alg{}, why(-8, "unknown algorithm %q", name)
}

func find(name, kind string) (Alg, error) {
	a, err := Find(name)
	if err != nil {
		return a, err
	}
	if a.Kind != kind {
		w := "signature"
		if kind == "kem" {
			w = "KEM"
		}
		return a, why(-8, "%s is not a %s algorithm", a.Name, w)
	}
	return a, nil
}

var hnames = []string{"SHA-224", "SHA-256", "SHA-384", "SHA-512",
	"SHA-512/224", "SHA-512/256", "SHA3-224", "SHA3-256", "SHA3-384",
	"SHA3-512", "SHAKE128", "SHAKE256"}

// Hashes lists the hash names Hash, HMAC and SignOpts.Prehash take.
func Hashes() []string { return append([]string(nil), hnames...) }

func hkey(s string) string {
	return strings.ToLower(strings.NewReplacer("-", "", "/", "", "_", "").Replace(s))
}

// hid is the nqhalg of a hash name: "SHA-256", "sha256", "sha3_256", ...
func hid(name string) (int, error) {
	k := hkey(name)
	for i, n := range hnames {
		if hkey(n) == k {
			return i + 1, nil
		}
	}
	return 0, why(-8, "unknown hash %q", name)
}

func hash(alg string, data []byte, n int) ([]byte, error) {
	i, err := hid(alg)
	if err != nil {
		return nil, err
	}
	d := int(C.nqhlen(C.nqhalg(i)))
	if n >= 0 {
		if i < 11 {
			return nil, why(-1, "%s has a fixed length; n is for SHAKE", alg)
		}
		d = n
	}
	out := make([]byte, d)
	if err := rc(C.nqhash(C.nqhalg(i), u8(data), sz(data), u8(out), sz(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// Hash is the digest of data: alg is "SHA-256", "SHA3-512", ...; for
// SHAKE128 and SHAKE256, 32 and 64 bytes of output.
func Hash(alg string, data []byte) ([]byte, error) { return hash(alg, data, -1) }

// HashN is n bytes of SHAKE128 or SHAKE256 output.
func HashN(alg string, data []byte, n int) ([]byte, error) {
	if n < 0 {
		return nil, why(-1, "n: a length in bytes")
	}
	return hash(alg, data, n)
}

// HMAC of data under key with a SHA-2 or SHA-3 hash.
func HMAC(alg string, key, data []byte) ([]byte, error) {
	i, err := hid(alg)
	if err != nil {
		return nil, err
	}
	out := make([]byte, int(C.nqhlen(C.nqhalg(i))))
	if err := rc(C.nqhmac(C.nqhalg(i), u8(key), sz(key), u8(data), sz(data), u8(out), sz(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// Random is n bytes from the operating system's CSPRNG.
func Random(n int) ([]byte, error) {
	if n < 0 {
		return nil, why(-1, "n: a length in bytes")
	}
	out := make([]byte, n)
	if n == 0 {
		return out, nil
	}
	if err := rc(C.nqrand(u8(out), sz(out))); err != nil {
		return nil, err
	}
	return out, nil
}
