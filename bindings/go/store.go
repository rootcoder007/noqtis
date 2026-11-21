// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

package noqtis

/*
#include <stdlib.h>
#include "noqtis.h"
*/
import "C"

import (
	"time"
	"unsafe"
)

// Trust in a key's owner to certify other keys, and how far a key is
// known to belong to its name.
const (
	TrustUnknown  = 0
	TrustNever    = 1
	TrustMarginal = 2
	TrustFull     = 3
	TrustUltimate = 4 // the owner's own key

	ValidNone     = 0
	ValidMarginal = 1
	ValidFull     = 2
)

// StoreKey is one public key of a key store.
type StoreKey struct {
	Alg         string
	KEM         bool
	Fingerprint []byte // SHA-256 of the public key, 32 bytes
	Name, Email string
	Card        bool // the store holds its identity card
	Trust       int
	Valid       int
	Certs       int // certifications of it under its present name
}

func fp32(m *cmem, fp []byte) (*C.uint8_t, error) {
	if len(fp) != 32 {
		return nil, why(-1, "a fingerprint is 32 bytes")
	}
	return m.bytes(fp), nil
}

// StoreAdd puts the public key pk of alg into the key store in the
// folder dir, which must exist, under name and, when not "", email;
// card, when not nil, is its identity card. It returns the key's
// fingerprint.
func StoreAdd(dir, alg string, pk []byte, name, email string, card []byte) ([]byte, error) {
	a, err := Find(alg)
	if err != nil {
		return nil, err
	}
	var m cmem
	defer m.free()
	cd, err := m.str(dir)
	if err != nil {
		return nil, err
	}
	cn, err := m.str(name)
	if err != nil {
		return nil, err
	}
	var ce *C.char
	if email != "" {
		if ce, err = m.str(email); err != nil {
			return nil, err
		}
	}
	kem := C.int(0)
	if a.Kind == "kem" {
		kem = 1
	}
	var cc *C.char
	if card != nil {
		cc = (*C.char)(unsafe.Pointer(m.bytes(card)))
	}
	fp := m.alloc(32, 1)
	if err := rc(C.nqksadd(cd, kem, C.int(a.ID), u8(pk), sz(pk), cn, ce, cc, sz(card), (*C.uint8_t)(fp))); err != nil {
		return nil, err
	}
	return C.GoBytes(fp, 32), nil
}

// StoreList lists the keys of the store whose name, address or
// fingerprint (in hex, from its start) matches query; all of them with
// "".
func StoreList(dir, query string) ([]StoreKey, error) {
	var m cmem
	defer m.free()
	cd, err := m.str(dir)
	if err != nil {
		return nil, err
	}
	var cq *C.char
	if query != "" {
		if cq, err = m.str(query); err != nil {
			return nil, err
		}
	}
	var n C.size_t
	c := C.nqkslist(cd, cq, nil, 0, &n)
	if c != C.NQEBUF {
		if err := rc(c); err != nil {
			return nil, err
		}
	}
	if n == 0 {
		return nil, nil
	}
	es := unsafe.Slice((*C.nqkse)(m.alloc(uintptr(n), unsafe.Sizeof(C.nqkse{}))), int(n))
	have := n
	if err := rc(C.nqkslist(cd, cq, &es[0], have, &n)); err != nil {
		return nil, err
	}
	if n > have {
		n = have
	}
	out := make([]StoreKey, 0, int(n))
	for i := 0; i < int(n); i++ {
		e := &es[i]
		k := StoreKey{
			KEM:         e.kem != 0,
			Fingerprint: C.GoBytes(unsafe.Pointer(&e.fp[0]), 32),
			Name:        C.GoString(&e.name[0]),
			Email:       C.GoString(&e.email[0]),
			Card:        e.card != 0,
			Trust:       int(e.trust),
			Valid:       int(e.valid),
			Certs:       int(e.ncert),
		}
		if k.KEM {
			k.Alg = C.GoString(C.nqkname(C.nqkalg(e.alg)))
		} else {
			k.Alg = C.GoString(C.nqsname(C.nqsalg(e.alg)))
		}
		out = append(out, k)
	}
	return out, nil
}

// StoreGet is the algorithm and the public key of the key with the
// fingerprint fp.
func StoreGet(dir string, fp []byte) (string, []byte, error) {
	var m cmem
	defer m.free()
	cd, err := m.str(dir)
	if err != nil {
		return "", nil, err
	}
	cf, err := fp32(&m, fp)
	if err != nil {
		return "", nil, err
	}
	var kem, alg C.int
	pk, err := m.buf(1<<16, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqksget(cd, cf, &kem, &alg, (*C.uint8_t)(p), cap, got)
	})
	if err != nil {
		return "", nil, err
	}
	if kem != 0 {
		return C.GoString(C.nqkname(C.nqkalg(alg))), pk, nil
	}
	return C.GoString(C.nqsname(C.nqsalg(alg))), pk, nil
}

// StoreCertify signs, with the signature key pair (sk, pk) of alg, that
// the key fp of the store belongs to the name and address the store has
// for it. The certification (text) is kept in the store and returned,
// to give to others.
func StoreCertify(dir, alg string, sk, pk, fp []byte, at time.Time) (string, error) {
	a, err := find(alg, "sign")
	if err != nil {
		return "", err
	}
	var m cmem
	defer m.free()
	cd, err := m.str(dir)
	if err != nil {
		return "", err
	}
	cf, err := fp32(&m, fp)
	if err != nil {
		return "", err
	}
	csk := m.bytes(sk)
	out, err := m.buf(2*a.Sig+4096, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqkscert(cd, C.nqsalg(a.ID), csk, sz(sk), u8(pk), sz(pk), cf, unix(at),
			(*C.char)(p), cap, got)
	})
	return string(out), err
}

// StoreAddCert puts a certification someone else made into the store:
// both keys must be in it, and its signature must verify.
func StoreAddCert(dir, cert string) error {
	var m cmem
	defer m.free()
	cd, err := m.str(dir)
	if err != nil {
		return err
	}
	b := []byte(cert)
	return rc(C.nqkscput(cd, (*C.char)(unsafe.Pointer(u8(b))), sz(b)))
}

// StoreTrust sets how far the owner of the key fp is trusted to certify
// other keys: TrustUnknown to TrustUltimate.
func StoreTrust(dir string, fp []byte, level int) error {
	var m cmem
	defer m.free()
	cd, err := m.str(dir)
	if err != nil {
		return err
	}
	cf, err := fp32(&m, fp)
	if err != nil {
		return err
	}
	return rc(C.nqkstrust(cd, cf, C.int(level)))
}

// StoreDelete removes the key fp and what the store holds about it.
func StoreDelete(dir string, fp []byte) error {
	var m cmem
	defer m.free()
	cd, err := m.str(dir)
	if err != nil {
		return err
	}
	cf, err := fp32(&m, fp)
	if err != nil {
		return err
	}
	return rc(C.nqksdel(cd, cf))
}

// StoreExport is a bundle (text) of the key fp: the key, its name and
// address, its identity card and the certifications of it, for another
// store to import or to publish for KeyURL.
func StoreExport(dir string, fp []byte) (string, error) {
	var m cmem
	defer m.free()
	cd, err := m.str(dir)
	if err != nil {
		return "", err
	}
	cf, err := fp32(&m, fp)
	if err != nil {
		return "", err
	}
	var n C.size_t
	c := C.nqksexp(cd, cf, nil, 0, &n)
	if c != C.NQEBUF {
		if err := rc(c); err != nil {
			return "", err
		}
	}
	out, err := m.buf(int(n)+1, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqksexp(cd, cf, (*C.char)(p), cap, got)
	})
	return string(out), err
}

// StoreImport puts the keys of a bundle into the store. With email not
// "" the bundle's keys must be for that address (a bundle fetched for
// it). It returns the fingerprint of the first key and how many keys
// came in.
func StoreImport(dir, bundle, email string) ([]byte, int, error) {
	var m cmem
	defer m.free()
	cd, err := m.str(dir)
	if err != nil {
		return nil, 0, err
	}
	var ce *C.char
	if email != "" {
		if ce, err = m.str(email); err != nil {
			return nil, 0, err
		}
	}
	b := []byte(bundle)
	fp := m.alloc(32, 1)
	var n C.size_t
	if err := rc(C.nqksimp(cd, (*C.char)(unsafe.Pointer(u8(b))), sz(b), ce, (*C.uint8_t)(fp), &n)); err != nil {
		return nil, 0, err
	}
	return C.GoBytes(fp, 32), int(n), nil
}

// KeyURL is where the bundle of an address is looked for, over https at
// its own domain: https://<domain>/.well-known/noqtis/<hash of the
// local part>. Fetch it, and give what comes back to StoreImport with
// the address.
func KeyURL(email string) (string, error) {
	var m cmem
	defer m.free()
	ce, err := m.str(email)
	if err != nil {
		return "", err
	}
	u := (*C.char)(m.alloc(512, 1))
	if err := rc(C.nqksurl(ce, u, 512)); err != nil {
		return "", err
	}
	return C.GoString(u), nil
}
