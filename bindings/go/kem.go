// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

package noqtis

/*
#include "noqtis.h"
*/
import "C"

// KEMKeyGen makes a KEM key pair; with a seed (d || z for ML-KEM) the
// standard's deterministic one, with nil a random one.
func KEMKeyGen(alg string, seed []byte) (pk, sk []byte, err error) {
	a, err := find(alg, "kem")
	if err != nil {
		return nil, nil, err
	}
	pk, sk = make([]byte, a.PK), make([]byte, a.SK)
	var c C.int
	if seed == nil {
		c = C.nqkkg(C.nqkalg(a.ID), u8(pk), sz(pk), u8(sk), sz(sk))
	} else {
		c = C.nqkkgd(C.nqkalg(a.ID), u8(seed), sz(seed), u8(pk), sz(pk), u8(sk), sz(sk))
	}
	if err := rc(c); err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}

// Encap is a ciphertext and shared secret for pk; a seed (m for ML-KEM)
// makes it deterministic, for test vectors.
func Encap(alg string, pk, seed []byte) (ct, ss []byte, err error) {
	a, err := find(alg, "kem")
	if err != nil {
		return nil, nil, err
	}
	ct, ss = make([]byte, a.CT), make([]byte, a.SS)
	var c C.int
	if seed == nil {
		c = C.nqenc(C.nqkalg(a.ID), u8(pk), sz(pk), u8(ct), sz(ct), u8(ss), sz(ss))
	} else {
		c = C.nqencd(C.nqkalg(a.ID), u8(pk), sz(pk), u8(seed), sz(seed), u8(ct), sz(ct), u8(ss), sz(ss))
	}
	if err := rc(c); err != nil {
		return nil, nil, err
	}
	return ct, ss, nil
}

// Decap is the shared secret in ct. A tampered ciphertext gives an
// unrelated pseudorandom secret, not an error (implicit rejection); only
// a key or ciphertext of the wrong size, or a damaged secret key, is an
// error.
func Decap(alg string, sk, ct []byte) ([]byte, error) {
	a, err := find(alg, "kem")
	if err != nil {
		return nil, err
	}
	ss := make([]byte, a.SS)
	if err := rc(C.nqdec(C.nqkalg(a.ID), u8(sk), sz(sk), u8(ct), sz(ct), u8(ss), sz(ss))); err != nil {
		return nil, err
	}
	return ss, nil
}
