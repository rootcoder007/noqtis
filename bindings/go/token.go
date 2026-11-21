// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

package noqtis

/*
#include <stdlib.h>
#include "noqtis.h"
*/
import "C"

import (
	"unsafe"
)

// Token is a loaded PKCS #11 module: the tokens it reaches (smart
// cards, hardware security modules, a software token) and, after
// Login, the keys of one. Private keys stay on the token. A Token is
// for one goroutine at a time; Close it when done.
type Token struct {
	p *C.nqp11
}

// TokenInfo is one token present.
type TokenInfo struct {
	Slot                        uint
	Label, Maker, Model, Serial string
	Login                       bool // its keys need the PIN
}

// TokenKey is a private key on a token that noqtis can use.
type TokenKey struct {
	Alg   string
	KEM   bool
	Label string
	ID    []byte
	k     C.nqp11k
}

// OpenToken loads the PKCS #11 module at the path module and starts
// it. The path must have a folder in it: a bare name, which the system
// would search for, is ErrArg.
func OpenToken(module string) (*Token, error) {
	var m cmem
	defer m.free()
	cm, err := m.str(module)
	if err != nil {
		return nil, err
	}
	t := &Token{}
	if err := rc(C.nqp11open(cm, &t.p)); err != nil {
		return nil, err
	}
	return t, nil
}

// Close ends the session and unloads the module.
func (t *Token) Close() {
	if t.p != nil {
		C.nqp11close(t.p)
		t.p = nil
	}
}

// Why is the module's own return value for the last call that failed
// with ErrIO or ErrUnsupported: a CKR number of the standard.
func (t *Token) Why() uint { return uint(C.nqp11why(t.p)) }

func (t *Token) live() error {
	if t.p == nil {
		return why(-10, "the token is closed")
	}
	return nil
}

// Tokens lists the tokens present.
func (t *Token) Tokens() ([]TokenInfo, error) {
	if err := t.live(); err != nil {
		return nil, err
	}
	var ts [64]C.nqp11t
	var n C.size_t
	if err := rc(C.nqp11toks(t.p, &ts[0], 64, &n)); err != nil {
		return nil, err
	}
	out := make([]TokenInfo, 0, int(n))
	for i := 0; i < int(n); i++ {
		e := &ts[i]
		out = append(out, TokenInfo{Slot: uint(e.slot), Label: C.GoString(&e.label[0]),
			Maker: C.GoString(&e.maker[0]), Model: C.GoString(&e.model[0]),
			Serial: C.GoString(&e.serial[0]), Login: e.login != 0})
	}
	return out, nil
}

// Login opens a session with the token in slot and, with pin not "",
// logs the user in. ErrVerify for a wrong or locked PIN.
func (t *Token) Login(slot uint, pin string) error {
	if err := t.live(); err != nil {
		return err
	}
	if pin == "" {
		return rc(C.nqp11login(t.p, C.ulong(slot), nil, 0))
	}
	var m cmem
	defer m.free()
	b := []byte(pin)
	cp := m.bytes(b)
	err := rc(C.nqp11login(t.p, C.ulong(slot), (*C.char)(unsafe.Pointer(cp)), sz(b)))
	C.nqwipe(unsafe.Pointer(cp), sz(b))
	return err
}

func tokkey(k *C.nqp11k) TokenKey {
	o := TokenKey{KEM: k.kem != 0, Label: C.GoString(&k.label[0]),
		ID: C.GoBytes(unsafe.Pointer(&k.id[0]), C.int(k.idlen)), k: *k}
	if o.KEM {
		o.Alg = C.GoString(C.nqkname(C.nqkalg(k.alg)))
	} else {
		o.Alg = C.GoString(C.nqsname(C.nqsalg(k.alg)))
	}
	return o
}

// Keys lists the private keys of the token that noqtis can use. A
// token shows its private keys after the PIN.
func (t *Token) Keys() ([]TokenKey, error) {
	if err := t.live(); err != nil {
		return nil, err
	}
	var ks [64]C.nqp11k
	var n C.size_t
	c := C.nqp11keys(t.p, &ks[0], 64, &n)
	if c != C.NQEBUF {
		if err := rc(c); err != nil {
			return nil, err
		}
	}
	if n > 64 {
		n = 64
	}
	out := make([]TokenKey, 0, int(n))
	for i := 0; i < int(n); i++ {
		out = append(out, tokkey(&ks[i]))
	}
	return out, nil
}

// PublicKey is the public key of k, as Verify and Encap take it.
func (t *Token) PublicKey(k TokenKey) ([]byte, error) {
	if err := t.live(); err != nil {
		return nil, err
	}
	var m cmem
	defer m.free()
	return m.buf(4096, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqp11pub(t.p, &k.k, (*C.uint8_t)(p), cap, got)
	})
}

// Sign signs msg on the token with the signature key k and the context
// ctx (nil for none): the signature Sign makes, which Verify checks.
func (t *Token) Sign(k TokenKey, msg, ctx []byte) ([]byte, error) {
	if err := t.live(); err != nil {
		return nil, err
	}
	a, err := find(k.Alg, "sign")
	if err != nil {
		return nil, err
	}
	var m cmem
	defer m.free()
	cm := m.bytes(msg)
	cc := m.bytes(ctx)
	return m.buf(a.Sig, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqp11sign(t.p, &k.k, cm, sz(msg), cc, sz(ctx), (*C.uint8_t)(p), cap, got)
	})
}

// Decaps decapsulates the ML-KEM ciphertext ct on the token with the
// key k, as Decap does. The module must be of PKCS #11 version 3.2;
// an older one is ErrUnsupported.
func (t *Token) Decaps(k TokenKey, ct []byte) ([]byte, error) {
	if err := t.live(); err != nil {
		return nil, err
	}
	a, err := find(k.Alg, "kem")
	if err != nil {
		return nil, err
	}
	var m cmem
	defer m.free()
	cc := m.bytes(ct)
	ss := m.alloc(uintptr(a.SS), 1)
	if err := rc(C.nqp11dec(t.p, &k.k, cc, sz(ct), (*C.uint8_t)(ss), C.size_t(a.SS))); err != nil {
		return nil, err
	}
	out := C.GoBytes(ss, C.int(a.SS))
	C.nqwipe(ss, C.size_t(a.SS))
	return out, nil
}

// Generate makes a key pair of alg on the token under label; the
// private key is marked never to leave it. ML-DSA, SLH-DSA, Ed25519
// and ML-KEM keys are made on tokens; others are ErrUnsupported.
func (t *Token) Generate(alg, label string) (TokenKey, error) {
	if err := t.live(); err != nil {
		return TokenKey{}, err
	}
	a, err := Find(alg)
	if err != nil {
		return TokenKey{}, err
	}
	var m cmem
	defer m.free()
	cl, err := m.str(label)
	if err != nil {
		return TokenKey{}, err
	}
	kem := C.int(0)
	if a.Kind == "kem" {
		kem = 1
	}
	var k C.nqp11k
	if err := rc(C.nqp11gen(t.p, kem, C.int(a.ID), cl, &k)); err != nil {
		return TokenKey{}, err
	}
	return tokkey(&k), nil
}
