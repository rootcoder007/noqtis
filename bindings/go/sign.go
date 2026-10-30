// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

package noqtis

/*
#include "noqtis.h"
*/
import "C"

import "strings"

// SignOpts are the options of Sign and Verify; a nil *SignOpts is all
// defaults.
type SignOpts struct {
	// Ctx is the context string, at most 255 bytes.
	Ctx []byte
	// Deterministic uses all-zero per-signature randomness: the
	// standard's deterministic variant (Sign only).
	Deterministic bool
	// Prehash names a hash ("SHA-512", "SHAKE256", ...) for HashML-DSA /
	// HashSLH-DSA (Ed25519ph for Ed25519); the message is still the
	// message, hashed inside.
	Prehash string
	// Rnd is the per-signature randomness, explicitly (Sign only).
	Rnd []byte
}

func (o *SignOpts) ph() (int, error) {
	if o == nil || o.Prehash == "" {
		return 0, nil
	}
	return hid(o.Prehash)
}

// RndLen is the bytes of per-signature randomness: 32 for ML-DSA and the
// hybrids, n for SLH-DSA, 0 for Ed25519.
func RndLen(alg string) (int, error) {
	a, err := find(alg, "sign")
	if err != nil {
		return 0, err
	}
	switch {
	case a.Name == "Ed25519":
		return 0, nil
	case strings.HasPrefix(a.Name, "ML-DSA"):
		return 32, nil
	}
	return a.PK / 2, nil
}

// SignKeyGen makes a key pair. With a seed (xi for ML-DSA, 32 bytes;
// SK.seed || SK.prf || PK.seed for SLH-DSA, 3n bytes; the private key
// for Ed25519; xi || the Ed25519 key for a hybrid) the pair is the
// standard's deterministic one; with nil, it comes from the OS CSPRNG.
func SignKeyGen(alg string, seed []byte) (pk, sk []byte, err error) {
	a, err := find(alg, "sign")
	if err != nil {
		return nil, nil, err
	}
	pk, sk = make([]byte, a.PK), make([]byte, a.SK)
	var c C.int
	if seed == nil {
		c = C.nqskg(C.nqsalg(a.ID), u8(pk), sz(pk), u8(sk), sz(sk))
	} else {
		c = C.nqskgd(C.nqsalg(a.ID), u8(seed), sz(seed), u8(pk), sz(pk), u8(sk), sz(sk))
	}
	if err := rc(c); err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}

// Sign is the signature of msg under sk.
func Sign(alg string, sk, msg []byte, o *SignOpts) ([]byte, error) {
	a, err := find(alg, "sign")
	if err != nil {
		return nil, err
	}
	if o == nil {
		o = &SignOpts{}
	}
	if o.Deterministic && o.Rnd != nil {
		return nil, why(-1, "Deterministic and Rnd exclude each other")
	}
	ph, err := o.ph()
	if err != nil {
		return nil, err
	}
	r := o.Rnd
	if o.Deterministic {
		n, _ := RndLen(alg)
		r = make([]byte, n)
	}
	sig := make([]byte, a.Sig)
	var n C.size_t
	var c C.int
	if r == nil {
		c = C.nqsign(C.nqsalg(a.ID), u8(sk), sz(sk), u8(msg), sz(msg), u8(o.Ctx), sz(o.Ctx),
			C.int(ph), u8(sig), sz(sig), &n)
	} else {
		c = C.nqsignd(C.nqsalg(a.ID), u8(sk), sz(sk), u8(msg), sz(msg), u8(o.Ctx), sz(o.Ctx),
			C.int(ph), u8(r), sz(r), u8(sig), sz(sig), &n)
	}
	if err := rc(c); err != nil {
		return nil, err
	}
	return sig[:n], nil
}

// Verify reports whether sig is a valid signature of msg under pk (with
// the same context and pre-hash): false when it does not verify or is
// not a well-formed signature. Bad arguments (a context over 255 bytes,
// a public key of the wrong size) are an error.
func Verify(alg string, pk, msg, sig []byte, o *SignOpts) (bool, error) {
	a, err := find(alg, "sign")
	if err != nil {
		return false, err
	}
	if len(pk) != a.PK {
		return false, why(-4, "%s public keys are %d bytes, not %d", a.Name, a.PK, len(pk))
	}
	if o == nil {
		o = &SignOpts{}
	}
	ph, err := o.ph()
	if err != nil {
		return false, err
	}
	c := C.nqvrfy(C.nqsalg(a.ID), u8(pk), sz(pk), u8(msg), sz(msg), u8(o.Ctx), sz(o.Ctx),
		C.int(ph), u8(sig), sz(sig))
	switch c {
	case 0:
		return true, nil
	case C.NQEVRFY, C.NQEDEC:
		return false, nil
	}
	return false, cerr(int(c))
}
