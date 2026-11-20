// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

package noqtis

/*
#include <stdlib.h>
#include "noqtis.h"
*/
import "C"

import "unsafe"

// What SealWhy names (nqsealwhy(3)).
const (
	WhyLink = 1 + iota // a symbolic link or reparse point
	WhyOdd             // not a regular file or folder
	WhyName            // a name noqtis refuses
	WhyCase            // a path equal to another but for ASCII case
	WhyKey             // a file that starts like a noqtis secret key
)

// SealWhy says why Seal refused dir (ErrArg): the first thing in it a
// capsule cannot hold (a Why* constant) and its path; 0 when nothing in
// it stops a seal (the keys given were then not one pair).
func SealWhy(dir string) (int, string, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return 0, "", err
	}
	p := (*C.char)(m.alloc(4200, 1))
	var w C.int
	if err := rc(C.nqsealwhy(d, &w, p, 4200)); err != nil {
		return 0, "", err
	}
	return int(w), C.GoString(p), nil
}

func whyc(c C.int, w *C.char) error {
	if c == 0 {
		return nil
	}
	if w != nil {
		return why(int(c), "%s", C.GoString(w))
	}
	return cerr(int(c))
}

// TSReq is the RFC 3161 TimeStampReq for the seal in dir: send it to a
// TSA (the library makes no network request) and give its reply to
// TSPut. nonce may be nil.
func TSReq(dir string, nonce []byte) ([]byte, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return nil, err
	}
	q := make([]byte, 256)
	var n C.size_t
	if err := rc(C.nqtsreq(d, u8(nonce), sz(nonce), u8(q), sz(q), &n)); err != nil {
		return nil, err
	}
	return q[:n], nil
}

// TSPut stores the TSA's reply as the seal's timestamp once it checks
// (with anchors, DER certificates, its TSA must chain to one): the time
// it gives, in seconds since 1970. ErrVerify, with what failed, when it
// does not check.
func TSPut(dir string, reply, nonce []byte, anchors [][]byte) (int64, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return 0, err
	}
	a, al := m.blobs(anchors)
	var gt C.int64_t
	var w *C.char
	c := C.nqtsput(d, m.bytes(reply), sz(reply), u8(nonce), sz(nonce),
		(**C.uint8_t)(unsafe.Pointer(a)), al, C.size_t(len(anchors)), &gt, &w)
	return int64(gt), whyc(c, w)
}

func hashid(h string) (C.nqhalg, error) {
	if h == "" {
		return 0, nil
	}
	i, err := hid(h)
	return C.nqhalg(i), err
}

// ERSReq is the TimeStampReq of the next archive timestamp of the
// capsule's evidence record (RFC 4998): hash "SHA-256", "SHA-384" or
// "SHA-512" for a hash-tree renewal, "" to keep the record's.
func ERSReq(dir, hash string, nonce []byte) ([]byte, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return nil, err
	}
	h, err := hashid(hash)
	if err != nil {
		return nil, err
	}
	q := make([]byte, 256)
	var n C.size_t
	var w *C.char
	if err := whyc(C.nqersreq(d, h, u8(nonce), sz(nonce), u8(q), sz(q), &n, &w), w); err != nil {
		return nil, err
	}
	return q[:n], nil
}

// ERSPut adds the reply to ERSReq to the evidence record (noqtis.ers)
// once it and the record check: its time, and how the record was
// renewed: 0 a new record, 1 a timestamp renewal, 2 a hash-tree renewal.
func ERSPut(dir, hash string, reply, nonce []byte, anchors [][]byte) (int64, int, error) {
	var m cmem
	defer m.free()
	d, err := m.str(dir)
	if err != nil {
		return 0, 0, err
	}
	h, err := hashid(hash)
	if err != nil {
		return 0, 0, err
	}
	a, al := m.blobs(anchors)
	var gt C.int64_t
	var how C.int
	var w *C.char
	c := C.nqersput(d, h, m.bytes(reply), sz(reply), u8(nonce), sz(nonce),
		(**C.uint8_t)(unsafe.Pointer(a)), al, C.size_t(len(anchors)), &gt, &how, &w)
	return int64(gt), int(how), whyc(c, w)
}

// sized calls f with room of cp bytes, then once more with the size it
// asked for (NQEBUF with *n).
func sized(cp int, f func(o *C.char, cp C.size_t, n *C.size_t) C.int) ([]byte, error) {
	for k := 0; k < 2; k++ {
		b := (*C.char)(C.malloc(C.size_t(cp)))
		var n C.size_t
		c := f(b, C.size_t(cp), &n)
		out := C.GoBytes(unsafe.Pointer(b), C.int(min(int(n), cp)))
		C.free(unsafe.Pointer(b))
		if c == -2 && int(n) > cp && k == 0 {
			cp = int(n) + 1
			continue
		}
		if err := rc(c); err != nil {
			return nil, err
		}
		return out, nil
	}
	return nil, cerr(-2)
}

func kstmt(exp bool, alg string, sk, pk []byte, nalg string, nsk, npk []byte, at int64, reason string) ([]byte, error) {
	a, err := find(alg, "sign")
	if err != nil {
		return nil, err
	}
	na := a
	if nalg != "" {
		if na, err = find(nalg, "sign"); err != nil {
			return nil, err
		}
	}
	var m cmem
	defer m.free()
	var r *C.char
	if reason != "" {
		if r, err = m.str(reason); err != nil {
			return nil, err
		}
	}
	return sized(65536, func(o *C.char, cp C.size_t, n *C.size_t) C.int {
		if exp {
			return C.nqkexp(C.nqsalg(a.ID), u8(sk), sz(sk), u8(pk), sz(pk), C.int64_t(at), r, o, cp, n)
		}
		return C.nqkstmt(C.nqsalg(a.ID), u8(sk), sz(sk), u8(pk), sz(pk), C.nqsalg(na.ID),
			u8(nsk), sz(nsk), u8(npk), sz(npk), C.int64_t(at), r, o, cp, n)
	})
}

// Rotate is a key statement (noqtis-keys-1, JSON) that the key pair (sk,
// pk) of alg is replaced by (nsk, npk) of nalg from at (seconds since
// 1970), signed by both keys; reason is "" or up to 255 bytes. Both
// algorithms must be post-quantum. Give it to Check in CheckOpts.Stmts.
func Rotate(alg string, sk, pk []byte, nalg string, nsk, npk []byte, at int64, reason string) ([]byte, error) {
	if len(nsk) == 0 || len(npk) == 0 {
		return nil, why(-1, "the new key pair is needed")
	}
	return kstmt(false, alg, sk, pk, nalg, nsk, npk, at, reason)
}

// Revoke is a key statement that the key pair (sk, pk) is revoked from
// at, signed by it; as Rotate.
func Revoke(alg string, sk, pk []byte, at int64, reason string) ([]byte, error) {
	return kstmt(false, alg, sk, pk, "", nil, nil, at, reason)
}

// Expire is a key statement that the key pair (sk, pk) seals until at
// and not after, signed by it; as Rotate. Check accepts its seals as
// before until that time has come, and from then on only with a verified
// timestamp from before it.
func Expire(alg string, sk, pk []byte, at int64, reason string) ([]byte, error) {
	return kstmt(true, alg, sk, pk, "", nil, nil, at, reason)
}

// DSSE is a DSSE envelope (canonical JSON) of payload of type typ (1 to
// 255 printable ASCII bytes, no quote or backslash), signed by the pair
// (sk, pk) over PAE(typ, payload); its keyid is the hex SHA-256 of pk.
func DSSE(alg string, sk, pk []byte, typ string, payload []byte) ([]byte, error) {
	a, err := find(alg, "sign")
	if err != nil {
		return nil, err
	}
	var m cmem
	defer m.free()
	t, err := m.str(typ)
	if err != nil {
		return nil, err
	}
	return sized(4*len(payload)+4*a.Sig+1024, func(o *C.char, cp C.size_t, n *C.size_t) C.int {
		return C.nqdsse(C.nqsalg(a.ID), u8(sk), sz(sk), u8(pk), sz(pk), t, u8(payload), sz(payload), o, cp, n)
	})
}

// DSSEVerify is the envelope's type and payload when one of its
// signatures verifies under pk; ok is false when none does. ErrDecode
// for text that is not an envelope.
func DSSEVerify(alg string, pk, env []byte) (typ string, payload []byte, ok bool, err error) {
	a, err := find(alg, "sign")
	if err != nil {
		return "", nil, false, err
	}
	var m cmem
	defer m.free()
	t := (*C.char)(m.alloc(256, 1))
	e := m.bytes(env)
	p, err := sized(len(env)+1, func(o *C.char, cp C.size_t, n *C.size_t) C.int {
		return C.nqdssevrfy(C.nqsalg(a.ID), u8(pk), sz(pk), (*C.char)(unsafe.Pointer(e)), sz(env),
			(*C.uint8_t)(unsafe.Pointer(o)), cp, n, t)
	})
	if e, isn := err.(*Error); isn && e.Code == -3 {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, err
	}
	return C.GoString(t), p, true, nil
}
