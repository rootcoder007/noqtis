// SPDX-License-Identifier: LGPL-3.0-or-later

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

// buf calls f with a C buffer of n bytes and gives what f wrote there.
func (m *cmem) buf(n int, f func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int) ([]byte, error) {
	if n < 1 {
		n = 1
	}
	p := m.alloc(uintptr(n), 1)
	if p == nil {
		return nil, cerr(-6)
	}
	var got C.size_t
	if err := rc(f(p, C.size_t(n), &got)); err != nil {
		return nil, err
	}
	return C.GoBytes(p, C.int(got)), nil
}

func unix(t time.Time) C.int64_t {
	if t.IsZero() {
		t = time.Now()
	}
	return C.int64_t(t.Unix())
}

// Armor writes data as text (RFC 7468): a -----BEGIN label----- line,
// base64 in lines of 64, and the END line. The label is capitals and
// digits with single spaces between them.
func Armor(label string, data []byte) (string, error) {
	var m cmem
	defer m.free()
	cl, err := m.str(label)
	if err != nil {
		return "", err
	}
	var n C.size_t
	if err := rc(C.nqarmlen(cl, sz(data), &n)); err != nil {
		return "", err
	}
	out, err := m.buf(int(n), func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqarmenc(cl, u8(data), sz(data), (*C.char)(p), cap, got)
	})
	return string(out), err
}

// Dearmor reads one armor back: its label and its bytes. Text that is
// not exactly one well-formed armor is ErrDecode.
func Dearmor(text string) (string, []byte, error) {
	var m cmem
	defer m.free()
	in := []byte(text)
	lab := (*C.char)(m.alloc(C.NQARMLAB, 1))
	out, err := m.buf(len(in), func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqarmdec((*C.char)(unsafe.Pointer(m.bytes(in))), sz(in), lab, C.NQARMLAB,
			(*C.uint8_t)(p), cap, got)
	})
	if err != nil {
		return "", nil, err
	}
	return C.GoString(lab), out, nil
}

// CertInfo is what an X.509 certificate says of its key and holder.
// Alg is "" for a key of a kind noqtis does not have.
type CertInfo struct {
	Alg         string
	KEM         bool
	Fingerprint string // SHA-256 of the certificate, in hex
	NotBefore   time.Time
	NotAfter    time.Time
	CA          bool
	Name, Email string
	PK          []byte
}

func certinfo(f *C.nqx5f, cert []byte) *CertInfo {
	c := &CertInfo{
		KEM:         f.kem != 0,
		Fingerprint: hex.EncodeToString(C.GoBytes(unsafe.Pointer(&f.fp[0]), 32)),
		NotBefore:   time.Unix(int64(f.nb), 0).UTC(),
		NotAfter:    time.Unix(int64(f.na), 0).UTC(),
		CA:          f.ca != 0,
		Name:        C.GoString(&f.name[0]),
		Email:       C.GoString(&f.email[0]),
	}
	if f.alg != 0 {
		if c.KEM {
			c.Alg = C.GoString(C.nqkname(C.nqkalg(f.alg)))
		} else {
			c.Alg = C.GoString(C.nqsname(C.nqsalg(f.alg)))
		}
	}
	if cert != nil && int(f.pkoff)+int(f.pklen) <= len(cert) {
		c.PK = append([]byte(nil), cert[int(f.pkoff):int(f.pkoff)+int(f.pklen)]...)
	}
	return c
}

// SelfCert is a self-signed X.509 certificate (DER) for the signature
// key pair (sk, pk) of alg, an ML-DSA, SLH-DSA or Ed25519 key, under
// name and, when not "", email, valid from notBefore to notAfter. It is
// a CA of path length 0, so that it can issue a KEMCert.
func SelfCert(alg string, sk, pk []byte, name, email string, notBefore, notAfter time.Time) ([]byte, error) {
	a, err := find(alg, "sign")
	if err != nil {
		return nil, err
	}
	var m cmem
	defer m.free()
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
	csk := m.bytes(sk)
	return m.buf(len(pk)+a.Sig+2048, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqx5self(C.nqsalg(a.ID), csk, sz(sk), u8(pk), sz(pk), cn, ce,
			C.int64_t(notBefore.Unix()), C.int64_t(notAfter.Unix()), (*C.uint8_t)(p), cap, got)
	})
}

// KEMCert is a certificate (DER) for the ML-KEM public key pk of alg,
// issued by the signature key issuerSK under the name of its own
// certificate issuerCert: what others encrypt to.
func KEMCert(issuerAlg string, issuerSK, issuerCert []byte, alg string, pk []byte, notBefore, notAfter time.Time) ([]byte, error) {
	ia, err := find(issuerAlg, "sign")
	if err != nil {
		return nil, err
	}
	a, err := find(alg, "kem")
	if err != nil {
		return nil, err
	}
	var m cmem
	defer m.free()
	csk := m.bytes(issuerSK)
	return m.buf(len(pk)+len(issuerCert)+ia.Sig+2048, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqx5kem(C.nqsalg(ia.ID), csk, sz(issuerSK), u8(issuerCert), sz(issuerCert),
			C.nqkalg(a.ID), u8(pk), sz(pk), C.int64_t(notBefore.Unix()), C.int64_t(notAfter.Unix()),
			(*C.uint8_t)(p), cap, got)
	})
}

// ReadCert reads a certificate (DER): its key, holder and dates. It
// checks no signature; CMSVerify and SMIMEVerify do, against anchors.
func ReadCert(cert []byte) (*CertInfo, error) {
	var f C.nqx5f
	if err := rc(C.nqx5info(u8(cert), sz(cert), &f)); err != nil {
		return nil, err
	}
	return certinfo(&f, cert), nil
}

// CMSSign is a CMS SignedData (RFC 5652, DER) of msg, signed with the
// key sk of alg whose certificate is cert; with detached the content is
// left out. at is the signing time (the zero time for now).
func CMSSign(alg string, sk, cert, msg []byte, detached bool, at time.Time) ([]byte, error) {
	a, err := find(alg, "sign")
	if err != nil {
		return nil, err
	}
	var m cmem
	defer m.free()
	csk := m.bytes(sk)
	d := C.int(0)
	if detached {
		d = 1
	}
	return m.buf(len(msg)+len(cert)+a.Sig+4096, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqcmssign(C.nqsalg(a.ID), csk, sz(sk), u8(cert), sz(cert), u8(msg), sz(msg), d,
			unix(at), (*C.uint8_t)(p), cap, got)
	})
}

// CMSVerify checks a SignedData against the anchors, certificates (DER)
// the caller trusts: the signer's certificate must be one of them. msg
// is the content of a detached signature, nil otherwise. It returns the
// content and the signer; ErrVerify when the signature does not verify
// or the signer is not an anchor. at is when to judge the dates (the
// zero time for now).
func CMSVerify(cms, msg []byte, anchors [][]byte, at time.Time) ([]byte, *CertInfo, error) {
	var m cmem
	defer m.free()
	ca, cl := m.blobs(anchors)
	var f C.nqx5f
	out, err := m.buf(len(cms)+len(msg), func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqcmsvrfy(u8(cms), sz(cms), u8(msg), sz(msg), ca, cl, C.size_t(len(anchors)),
			unix(at), (*C.uint8_t)(p), cap, got, &f)
	})
	if err != nil {
		return nil, nil, err
	}
	return out, certinfo(&f, nil), nil
}

// CMSEncrypt is a CMS AuthEnvelopedData (RFC 5083, AES-256-GCM, DER) of
// msg to the ML-KEM certificates certs (RFC 9629, RFC 9936): the secret
// key of any one of them opens it.
func CMSEncrypt(certs [][]byte, msg []byte) ([]byte, error) {
	var m cmem
	defer m.free()
	cc, cl := m.blobs(certs)
	n := len(msg) + 4096
	for _, c := range certs {
		n += len(c) + 2048
	}
	return m.buf(n, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqcmsenc(cc, cl, C.size_t(len(certs)), u8(msg), sz(msg), (*C.uint8_t)(p), cap, got)
	})
}

// CMSDecrypt opens an AuthEnvelopedData with the ML-KEM secret key sk
// of alg; cert, when not nil, is the key's certificate and names the
// recipient to use. ErrVerify when it is not for this key or was
// changed.
func CMSDecrypt(alg string, sk, cert, cms []byte) ([]byte, error) {
	a, err := find(alg, "kem")
	if err != nil {
		return nil, err
	}
	var m cmem
	defer m.free()
	csk := m.bytes(sk)
	return m.buf(len(cms), func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqcmsdec(C.nqkalg(a.ID), csk, sz(sk), u8(cert), sz(cert), u8(cms), sz(cms),
			(*C.uint8_t)(p), cap, got)
	})
}

// SMIMESign is an S/MIME message (RFC 8551) of the MIME entity entity
// (header lines, an empty line, the body), signed as CMSSign signs:
// application/pkcs7-mime, or with detached multipart/signed, which
// keeps the entity readable.
func SMIMESign(alg string, sk, cert []byte, entity string, detached bool, at time.Time) (string, error) {
	a, err := find(alg, "sign")
	if err != nil {
		return "", err
	}
	var m cmem
	defer m.free()
	csk := m.bytes(sk)
	e := []byte(entity)
	d := C.int(0)
	if detached {
		d = 1
	}
	out, err := m.buf(3*len(e)+2*(len(cert)+a.Sig)+8192, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqsmsign(C.nqsalg(a.ID), csk, sz(sk), u8(cert), sz(cert),
			(*C.char)(unsafe.Pointer(u8(e))), sz(e), d, unix(at), (*C.char)(p), cap, got)
	})
	return string(out), err
}

// SMIMEVerify checks a signed S/MIME message against the anchors, as
// CMSVerify does, and returns the entity that was signed and the
// signer.
func SMIMEVerify(mime string, anchors [][]byte, at time.Time) (string, *CertInfo, error) {
	var m cmem
	defer m.free()
	ca, cl := m.blobs(anchors)
	b := []byte(mime)
	var f C.nqx5f
	out, err := m.buf(len(b)+1, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqsmvrfy((*C.char)(unsafe.Pointer(u8(b))), sz(b), ca, cl, C.size_t(len(anchors)),
			unix(at), (*C.char)(p), cap, got, &f)
	})
	if err != nil {
		return "", nil, err
	}
	return string(out), certinfo(&f, nil), nil
}

// SMIMEEncrypt is an encrypted S/MIME message (authEnveloped-data) of
// the MIME entity to the ML-KEM certificates certs.
func SMIMEEncrypt(certs [][]byte, entity string) (string, error) {
	var m cmem
	defer m.free()
	cc, cl := m.blobs(certs)
	e := []byte(entity)
	n := 3*len(e) + 8192
	for _, c := range certs {
		n += 2*len(c) + 4096
	}
	out, err := m.buf(n, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqsmenc(cc, cl, C.size_t(len(certs)), (*C.char)(unsafe.Pointer(u8(e))), sz(e),
			(*C.char)(p), cap, got)
	})
	return string(out), err
}

// SMIMEDecrypt opens an encrypted S/MIME message, as CMSDecrypt does,
// and returns the MIME entity inside.
func SMIMEDecrypt(alg string, sk, cert []byte, mime string) (string, error) {
	a, err := find(alg, "kem")
	if err != nil {
		return "", err
	}
	var m cmem
	defer m.free()
	csk := m.bytes(sk)
	b := []byte(mime)
	out, err := m.buf(len(b)+1, func(p unsafe.Pointer, cap C.size_t, got *C.size_t) C.int {
		return C.nqsmdec(C.nqkalg(a.ID), csk, sz(sk), u8(cert), sz(cert),
			(*C.char)(unsafe.Pointer(u8(b))), sz(b), (*C.char)(p), cap, got)
	})
	return string(out), err
}
