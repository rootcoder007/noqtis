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

// OpenPGP algorithms, by their OpenPGP numbers: Ed25519 and X25519 of
// RFC 9580, and those of draft-ietf-openpgp-pqc.
const (
	PGPX25519   = 25
	PGPEd25519  = 27
	PGPMLDSA65  = 30 // ML-DSA-65 with Ed25519
	PGPSLH128s  = 32 // SLH-DSA-SHAKE-128s
	PGPSLH128f  = 33
	PGPSLH256s  = 34
	PGPMLKEM768 = 35 // ML-KEM-768 with X25519
)

// How PGPSign signs.
const (
	PGPInline   = 0 // a signed message that carries the data
	PGPDetached = 1 // the signature alone
	PGPClear    = 2 // the text with the armored signature under it
)

// Kinds of OpenPGP armor.
const (
	PGPMessage    = 1
	PGPPublicKey  = 2
	PGPPrivateKey = 3
	PGPSignature  = 4
)

// PGPKey is what an OpenPGP key or certificate says of itself.
type PGPKey struct {
	Alg            int    // the primary key's algorithm
	EncAlg         int    // the encryption subkey's, 0 when it has none
	Secret         bool   // a secret key
	Locked         bool   // under a passphrase
	Fingerprint    string // of the primary key, in hex
	EncFingerprint string // of the encryption subkey, "" when none
	Created        time.Time
	Expires        time.Time // the zero time: never
	UserID         string
}

// PGPGenerate makes a version 6 OpenPGP key (RFC 9580): a primary key
// of sigAlg that certifies and signs, the user ID uid (by convention
// "Name <address>"), and, when encAlg is not 0, an encryption subkey.
// It returns the secret key, under passphrase when that is not nil, and
// the certificate to give to others, both in binary (PGPArmor makes
// them text).
func PGPGenerate(sigAlg, encAlg int, uid string, created time.Time, passphrase []byte) (sec, pub []byte, err error) {
	var m cmem
	defer m.free()
	cu, err := m.str(uid)
	if err != nil {
		return nil, nil, err
	}
	const n = 1 << 18
	ps, pp := m.alloc(n, 1), m.alloc(n, 1)
	var cpw *C.uint8_t
	if passphrase != nil {
		cpw = m.bytes(passphrase)
	}
	var sn, pn C.size_t
	if err := rc(C.nqpgpgen(C.int(sigAlg), C.int(encAlg), cu, unix(created), cpw, sz(passphrase),
		(*C.uint8_t)(ps), n, &sn, (*C.uint8_t)(pp), n, &pn)); err != nil {
		return nil, nil, err
	}
	sec, pub = C.GoBytes(ps, C.int(sn)), C.GoBytes(pp, C.int(pn))
	C.nqwipe(ps, n)
	return sec, pub, nil
}

// PGPInfo reads an OpenPGP key or certificate (binary). Only what a
// self-signature of the primary key binds is taken; a key with none, or
// a revoked one, is ErrVerify.
func PGPInfo(key []byte) (*PGPKey, error) {
	var f C.nqpgpk
	if err := rc(C.nqpgpinfo(u8(key), sz(key), &f)); err != nil {
		return nil, err
	}
	k := &PGPKey{
		Alg:         int(f.alg),
		EncAlg:      int(f.encalg),
		Secret:      f.secret != 0,
		Locked:      f.locked != 0,
		Fingerprint: hex.EncodeToString(C.GoBytes(unsafe.Pointer(&f.fp[0]), 32)),
		Created:     time.Unix(int64(f.created), 0).UTC(),
		UserID:      C.GoString(&f.uid[0]),
	}
	if f.encalg != 0 {
		k.EncFingerprint = hex.EncodeToString(C.GoBytes(unsafe.Pointer(&f.encfp[0]), 32))
	}
	if f.expires != 0 {
		k.Expires = time.Unix(int64(f.expires), 0).UTC()
	}
	return k, nil
}

// PGPSign signs msg with the secret key (passphrase nil when it is not
// under one): mode PGPInline, PGPDetached or PGPClear. The result is
// binary packets, except PGPClear, which is text.
func PGPSign(key, passphrase, msg []byte, mode int, at time.Time) ([]byte, error) {
	var m cmem
	defer m.free()
	ck := m.bytes(key)
	var cpw *C.uint8_t
	if passphrase != nil {
		cpw = m.bytes(passphrase)
	}
	return m.buf(3*len(msg)+1<<17, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqpgpsign(ck, sz(key), cpw, sz(passphrase), u8(msg), sz(msg), C.int(mode),
			unix(at), (*C.uint8_t)(p), cap, got)
	})
}

// PGPVerify checks a signed message, a cleartext signature or a
// detached signature (msg is then what it signs, nil otherwise), armored
// or binary, under the certificate cert. It returns the data that was
// signed and the time of the signature; ErrVerify when it does not
// verify.
func PGPVerify(cert, sig, msg []byte) ([]byte, time.Time, error) {
	var m cmem
	defer m.free()
	var at C.int64_t
	var cm *C.uint8_t
	if msg != nil {
		cm = m.bytes(msg)
	}
	out, err := m.buf(len(sig)+len(msg)+1, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqpgpvrfy(u8(cert), sz(cert), u8(sig), sz(sig), cm, sz(msg), (*C.uint8_t)(p), cap, got, &at)
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	return out, time.Unix(int64(at), 0).UTC(), nil
}

// PGPEncrypt encrypts msg to the encryption subkeys of certs (at most
// 64) and, with passphrase not nil, to that passphrase as well: AES-256
// with OCB. With signer, a secret key (signerPass its passphrase), the
// message is signed first.
func PGPEncrypt(certs [][]byte, passphrase, signer, signerPass, msg []byte, at time.Time) ([]byte, error) {
	var m cmem
	defer m.free()
	cc, cl := m.blobs(certs)
	var cpw, cs, csp *C.uint8_t
	if passphrase != nil {
		cpw = m.bytes(passphrase)
	}
	if signer != nil {
		cs = m.bytes(signer)
	}
	if signerPass != nil {
		csp = m.bytes(signerPass)
	}
	n := len(msg) + len(msg)/512 + 2048*len(certs) + 1<<17
	return m.buf(n, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqpgpenc(cc, cl, C.size_t(len(certs)), cpw, sz(passphrase), cs, sz(signer), csp,
			sz(signerPass), u8(msg), sz(msg), unix(at), (*C.uint8_t)(p), cap, got)
	})
}

// PGPDecrypt opens an encrypted message, armored or binary, with the
// secret key (passphrase is then the key's) or, with key nil, with the
// passphrase of the message. With signer, a certificate, the message
// inside must be signed by it, and signed is true. ErrVerify when it
// does not open or the signature does not verify.
func PGPDecrypt(key, passphrase, signer, msg []byte) (out []byte, signed bool, at time.Time, err error) {
	var m cmem
	defer m.free()
	var ck, cpw *C.uint8_t
	if key != nil {
		ck = m.bytes(key)
	}
	if passphrase != nil {
		cpw = m.bytes(passphrase)
	}
	var sb C.int
	var t C.int64_t
	out, err = m.buf(len(msg)+1, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqpgpdec(ck, sz(key), cpw, sz(passphrase), u8(signer), sz(signer), u8(msg), sz(msg),
			(*C.uint8_t)(p), cap, got, &sb, &t)
	})
	if err != nil {
		return nil, false, time.Time{}, err
	}
	return out, sb != 0, time.Unix(int64(t), 0).UTC(), nil
}

// PGPArmor writes OpenPGP packets as ASCII armor of kind PGPMessage,
// PGPPublicKey, PGPPrivateKey or PGPSignature.
func PGPArmor(kind int, data []byte) (string, error) {
	var m cmem
	defer m.free()
	var n C.size_t
	if err := rc(C.nqpgparm(C.int(kind), u8(data), sz(data), nil, 0, &n)); err != nil {
		return "", err
	}
	out, err := m.buf(int(n), func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqpgparm(C.int(kind), u8(data), sz(data), (*C.char)(p), cap, got)
	})
	return string(out), err
}

// PGPDearmor reads one OpenPGP armor back: its kind and its packets.
func PGPDearmor(text string) (int, []byte, error) {
	var m cmem
	defer m.free()
	b := []byte(text)
	var kind C.int
	out, err := m.buf(len(b), func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqpgpdearm((*C.char)(unsafe.Pointer(u8(b))), sz(b), &kind, (*C.uint8_t)(p), cap, got)
	})
	if err != nil {
		return 0, nil, err
	}
	return int(kind), out, nil
}
