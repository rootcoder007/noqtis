// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

package noqtis

/*
#include <stdlib.h>
#include "noqtis.h"
*/
import "C"

import (
	"encoding/hex"
	"time"
	"unsafe"
)

// CardFields is what an identity card says: Name, and the others when
// not "". The library checks each: Name and Affil 1 to 255 bytes of
// text, no control character, no space at either end; ORCID an ORCID iD
// (or its https://orcid.org/ address) whose check digit is right; Email
// local@domain.tld in at most 254 bytes; URL an https:// address in at
// most 1024 bytes.
type CardFields struct {
	Name, ORCID, Email, URL, Affil string
}

// Card is an identity card that verified: its fields ("" for one it has
// not, the ORCID iD bare), when it was made (YYYY-MM-DDTHH:MM:SSZ) and
// its key: the algorithm, the public key and its SHA-256 in hex, as
// `noqtis inspect` shows a seal's key.
type Card struct {
	Name, ORCID, Email, URL, Affil string
	Created, Alg                   string
	PK                             []byte
	KeySHA256                      string
}

// MakeCard is an identity card (noqtis-idcard-1, JSON) for the key pair
// (sk, pk) of alg, made at created (the zero time for now) and signed by
// it under the card's own context, so that a card is never taken for a
// seal or a key statement. A field out of its limits, or keys that are
// not one pair, are ErrArg; Ed25519 alone is ErrUnsupported.
func MakeCard(alg string, sk, pk []byte, f CardFields, created time.Time) ([]byte, error) {
	a, err := find(alg, "sign")
	if err != nil {
		return nil, err
	}
	if created.IsZero() {
		created = time.Now()
	}
	var m cmem
	defer m.free()
	var cs [5]*C.char
	for i, v := range []string{f.Name, f.ORCID, f.Email, f.URL, f.Affil} {
		if v == "" && i > 0 {
			continue
		}
		if cs[i], err = m.str(v); err != nil {
			return nil, err
		}
	}
	csk, cpk := m.bytes(sk), m.bytes(pk)
	at := C.int64_t(created.Unix())
	var n C.size_t
	c := C.nqcard(C.nqsalg(a.ID), csk, sz(sk), cpk, sz(pk), cs[0], cs[1], cs[2], cs[3], cs[4], at, nil, 0, &n)
	if c != C.NQEBUF {
		if err := rc(c); err != nil {
			return nil, err
		}
	}
	out := (*C.char)(m.alloc(uintptr(n)+1, 1))
	c = C.nqcard(C.nqsalg(a.ID), csk, sz(sk), cpk, sz(pk), cs[0], cs[1], cs[2], cs[3], cs[4], at, out, n, &n)
	if err := rc(c); err != nil {
		return nil, err
	}
	return C.GoBytes(unsafe.Pointer(out), C.int(n)), nil
}

// VerifyCard checks an identity card (at most 256 KiB): the Card when it
// verifies and, with pk not nil, is for that public key; nil and no error
// when its signature does not verify or it is for another key, as Verify
// returns false. Input that is not a card is ErrDecode. A card is
// self-signed: compare KeySHA256 with the one its holder published, or
// pass pk.
func VerifyCard(card, pk []byte) (*Card, error) {
	var m cmem
	defer m.free()
	cc := (*C.char)(unsafe.Pointer(m.bytes(card)))
	var cpk *C.uint8_t
	if pk != nil {
		cpk = m.bytes(pk)
	}
	f := (*C.nqcardf)(m.alloc(1, unsafe.Sizeof(C.nqcardf{})))
	c := C.nqcardvrfy(cc, sz(card), cpk, sz(pk), f)
	if c == C.NQEVRFY {
		return nil, nil
	}
	if err := rc(c); err != nil {
		return nil, err
	}
	fp := C.GoBytes(unsafe.Pointer(&f.fp[0]), 32)
	return &Card{
		Name:      C.GoString(&f.name[0]),
		ORCID:     C.GoString(&f.orcid[0]),
		Email:     C.GoString(&f.email[0]),
		URL:       C.GoString(&f.url[0]),
		Affil:     C.GoString(&f.affil[0]),
		Created:   C.GoString(&f.utc[0]),
		Alg:       C.GoString(C.nqsname(f.alg)),
		PK:        C.GoBytes(unsafe.Pointer(&f.pk[0]), C.int(f.pklen)),
		KeySHA256: hex.EncodeToString(fp),
	}, nil
}
