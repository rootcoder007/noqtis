// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

package noqtis

/*
#include <stdlib.h>
#include "noqtis.h"
*/
import "C"

import (
	"io"
	"runtime"
	"unsafe"
)

// Wipe zeroes b (nqwipe): the compiler cannot remove the stores.
func Wipe(b []byte) {
	if len(b) > 0 {
		C.nqwipe(unsafe.Pointer(&b[0]), sz(b))
	}
}

// CTEq reports whether a and b are equal, in time that depends only on
// their length (nqcteq): compare MACs and tags with it.
func CTEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	return C.nqcteq(unsafe.Pointer(&a[0]), unsafe.Pointer(&b[0]), sz(a)) == 1
}

// Blake2b is the n-byte BLAKE2b digest (RFC 7693; n 1 to 64) of data,
// keyed (a MAC) with up to 64 bytes of key (nil for the plain hash).
func Blake2b(data, key []byte, n int) ([]byte, error) {
	if n < 1 || n > 64 {
		return nil, why(-1, "n: 1 to 64 bytes")
	}
	out := make([]byte, n)
	if err := rc(C.nqb2b(u8(key), sz(key), u8(data), sz(data), u8(out), sz(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// Argon2Cost is the cost of Argon2id: T passes over M KiB in P lanes.
type Argon2Cost struct{ T, M, P uint32 }

// Argon2id is n bytes (4 to 1024) of Argon2id (RFC 9106, version 0x13)
// of the password and the salt (8 bytes or more) with cost c and an
// optional secret key and associated data (nil for none).
func Argon2id(pw, salt []byte, c Argon2Cost, n int, key, ad []byte) ([]byte, error) {
	if n < 4 || n > 1024 {
		return nil, why(-1, "n: 4 to 1024 bytes")
	}
	out := make([]byte, n)
	if err := rc(C.nqa2id(u8(pw), sz(pw), u8(salt), sz(salt), u8(key), sz(key), u8(ad), sz(ad),
		C.uint32_t(c.T), C.uint32_t(c.M), C.uint32_t(c.P), u8(out), sz(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// PBKDF2 is n bytes (1 to 1024) of PBKDF2 (RFC 8018) of the password and
// the salt after iters iterations (1 to 100000000) of the HMAC of alg
// ("SHA-256", "SHA3-512", ...; not SHAKE). It costs an attacker no
// memory: where the choice is free, Argon2id is the one to use.
func PBKDF2(alg string, pw, salt []byte, iters uint32, n int) ([]byte, error) {
	i, err := hid(alg)
	if err != nil {
		return nil, err
	}
	if n < 1 || n > 1024 {
		return nil, why(-1, "n: 1 to 1024 bytes")
	}
	out := make([]byte, n)
	if err := rc(C.nqpbkdf2(C.nqhalg(i), u8(pw), sz(pw), u8(salt), sz(salt), C.uint32_t(iters),
		u8(out), sz(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// cctx is a context in C memory, wiped and freed by drop or, when it is
// lost, by the garbage collector.
type cctx struct {
	p unsafe.Pointer
	n C.size_t
}

func newctx(n uintptr) *cctx {
	c := &cctx{p: C.calloc(1, C.size_t(n)), n: C.size_t(n)}
	runtime.SetFinalizer(c, (*cctx).drop)
	return c
}

func (c *cctx) drop() {
	if c.p != nil {
		C.nqwipe(c.p, c.n)
		C.free(c.p)
		c.p = nil
	}
}

func (c *cctx) live() error {
	if c.p == nil {
		return cerr(-10)
	}
	return nil
}

// Hasher is a digest of data written in pieces (an io.Writer), as Hash
// gives it for the whole. Sum may be called again for SHAKE, to squeeze
// more output.
type Hasher struct {
	c     *cctx
	n     int
	shake bool
}

// NewHasher starts a hash of alg ("SHA-256", "SHAKE128", ...).
func NewHasher(alg string) (*Hasher, error) {
	i, err := hid(alg)
	if err != nil {
		return nil, err
	}
	c := newctx(unsafe.Sizeof(C.nqhctx{}))
	if err := rc(C.nqhini((*C.nqhctx)(c.p), C.nqhalg(i))); err != nil {
		c.drop()
		return nil, err
	}
	return &Hasher{c: c, n: int(C.nqhlen(C.nqhalg(i))), shake: i >= 11}, nil
}

// Write adds p to the message.
func (h *Hasher) Write(p []byte) (int, error) {
	if err := h.c.live(); err != nil {
		return 0, err
	}
	if err := rc(C.nqhupd((*C.nqhctx)(h.c.p), u8(p), sz(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Sum is the digest; n is the output length for SHAKE (0: its default).
func (h *Hasher) Sum(n int) ([]byte, error) {
	if n != 0 && !h.shake {
		return nil, why(-1, "n is for SHAKE")
	}
	if n == 0 {
		n = h.n
	}
	if err := h.c.live(); err != nil {
		return nil, err
	}
	out := make([]byte, n)
	if err := rc(C.nqhfin((*C.nqhctx)(h.c.p), u8(out), sz(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// PWEnc is sk under the passphrase pw (noqtis-pwkey-1): Argon2id with m
// KiB, t passes and p lanes (0 for each: 64 MiB, 3, 4) gives the key of
// ChaCha20-Poly1305, whose associated data includes ad.
func PWEnc(pw, sk, ad []byte, m, t, p uint32) ([]byte, error) {
	out := make([]byte, len(sk)+51)
	var n C.size_t
	if err := rc(C.nqpwenc(u8(pw), sz(pw), u8(ad), sz(ad), C.uint32_t(m), C.uint32_t(t), C.uint32_t(p),
		u8(sk), sz(sk), u8(out), sz(out), &n)); err != nil {
		return nil, err
	}
	return out[:n], nil
}

// The derivations of PWEnc2: Argon2id, PWEnc's, and PBKDF2 with
// HMAC-SHA-256, for places whose rules ask for it.
const (
	KDFArgon2id = 1
	KDFPBKDF2   = 2
)

// PWEnc2 is PWEnc under the derivation kdf: KDFArgon2id with m, t and p
// as there, or KDFPBKDF2 with t the iteration count (0: 600000; 100000
// to 10000000) and m and p 0. PWDec reads both.
func PWEnc2(kdf int, pw, sk, ad []byte, m, t, p uint32) ([]byte, error) {
	out := make([]byte, len(sk)+51)
	var n C.size_t
	if err := rc(C.nqpwenc2(C.int(kdf), u8(pw), sz(pw), u8(ad), sz(ad), C.uint32_t(m), C.uint32_t(t),
		C.uint32_t(p), u8(sk), sz(sk), u8(out), sz(out), &n)); err != nil {
		return nil, err
	}
	return out[:n], nil
}

// PWDec is the key PWEnc protected: ErrVerify for a wrong passphrase or
// ad, or any changed byte; ErrLimit for parameters over the limits (a
// file cannot ask for more memory or time). Wipe it after use.
func PWDec(pw, data, ad []byte) ([]byte, error) {
	sk := make([]byte, max(len(data)-51, 1))
	var n C.size_t
	if err := rc(C.nqpwdec(u8(pw), sz(pw), u8(ad), sz(ad), u8(data), sz(data), u8(sk), sz(sk), &n)); err != nil {
		return nil, err
	}
	return sk[:n], nil
}

// Mu is the 64-byte message representative of FIPS 204 for msg under pk,
// as Sign computes it (ML-DSA only; o's Ctx and Prehash are used), so
// that the message can be hashed away from the key.
func Mu(alg string, pk, msg []byte, o *SignOpts) ([]byte, error) {
	a, err := find(alg, "sign")
	if err != nil {
		return nil, err
	}
	if o == nil {
		o = &SignOpts{}
	}
	ph, err := o.ph()
	if err != nil {
		return nil, err
	}
	mu := make([]byte, 64)
	if err := rc(C.nqsmu(C.nqsalg(a.ID), u8(pk), sz(pk), u8(msg), sz(msg), u8(o.Ctx), sz(o.Ctx),
		C.int(ph), u8(mu), 64)); err != nil {
		return nil, err
	}
	return mu, nil
}

// rnd is the randomness of o: nil for the hedged signature.
func (o *SignOpts) rnd(n int) ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	if o.Deterministic && o.Rnd != nil {
		return nil, why(-1, "Deterministic and Rnd exclude each other")
	}
	if o.Deterministic {
		return make([]byte, n), nil
	}
	return o.Rnd, nil
}

// rp is r as the library takes it: NULL for nil, a valid pointer for an
// empty but present one (Ed25519's deterministic signature).
func rp(r []byte, one *C.uint8_t) *C.uint8_t {
	if r == nil {
		return nil
	}
	if len(r) == 0 {
		return one
	}
	return u8(r)
}

// SignMu is the signature of the message whose mu is mu (from Mu): the
// bytes Sign gives for that message with the same randomness (o's Rnd or
// Deterministic; its other options are not used).
func SignMu(alg string, sk, mu []byte, o *SignOpts) ([]byte, error) {
	a, err := find(alg, "sign")
	if err != nil {
		return nil, err
	}
	r, err := o.rnd(32)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, a.Sig)
	var n C.size_t
	if err := rc(C.nqsignmu(C.nqsalg(a.ID), u8(sk), sz(sk), u8(mu), sz(mu), u8(r), sz(r),
		u8(sig), sz(sig), &n)); err != nil {
		return nil, err
	}
	return sig[:n], nil
}

// VerifyMu reports whether sig verifies for the message whose mu is mu.
func VerifyMu(alg string, pk, mu, sig []byte) (bool, error) {
	a, err := find(alg, "sign")
	if err != nil {
		return false, err
	}
	switch c := C.nqvrfymu(C.nqsalg(a.ID), u8(pk), sz(pk), u8(mu), sz(mu), u8(sig), sz(sig)); c {
	case 0:
		return true, nil
	case -3, -4:
		return false, nil
	default:
		return false, cerr(int(c))
	}
}

// Signer is a signature over a message written in pieces (an io.Writer,
// so io.Copy feeds it): Sum gives the bytes Sign gives for the whole
// message with the same randomness. Only the piece at hand is held; the
// secret key is the caller's slice, not a copy. ML-DSA (pure and
// pre-hash), and HashSLH-DSA, Ed25519ph and the hybrids with Prehash
// "SHA-512"; the others are ErrUnsupported. One use: after Sum, ErrState.
type Signer struct {
	a  Alg
	sk []byte
	c  *cctx
}

func sini(alg string, k []byte, o *SignOpts, v bool) (Alg, *cctx, error) {
	a, err := find(alg, "sign")
	if err != nil {
		return a, nil, err
	}
	if o == nil {
		o = &SignOpts{}
	}
	ph, err := o.ph()
	if err != nil {
		return a, nil, err
	}
	c := newctx(unsafe.Sizeof(C.nqsctx{}))
	x := (*C.nqsctx)(c.p)
	var r C.int
	if v {
		r = C.nqvini(x, C.nqsalg(a.ID), u8(k), sz(k), u8(o.Ctx), sz(o.Ctx), C.int(ph))
	} else {
		r = C.nqsini(x, C.nqsalg(a.ID), u8(k), sz(k), u8(o.Ctx), sz(o.Ctx), C.int(ph))
	}
	if err := rc(r); err != nil {
		c.drop()
		return a, nil, err
	}
	return a, c, nil
}

// NewSigner starts a signature with sk; o's Ctx and Prehash as for Sign.
func NewSigner(alg string, sk []byte, o *SignOpts) (*Signer, error) {
	a, c, err := sini(alg, sk, o, false)
	if err != nil {
		return nil, err
	}
	return &Signer{a: a, sk: sk, c: c}, nil
}

func supd(c *cctx, p []byte) (int, error) {
	if err := c.live(); err != nil {
		return 0, err
	}
	if err := rc(C.nqsupd((*C.nqsctx)(c.p), u8(p), sz(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Write adds p to the message.
func (s *Signer) Write(p []byte) (int, error) { return supd(s.c, p) }

// Sum is the signature; o's Rnd or Deterministic as for Sign.
func (s *Signer) Sum(o *SignOpts) ([]byte, error) {
	if err := s.c.live(); err != nil {
		return nil, err
	}
	n, _ := RndLen(s.a.Name)
	r, err := o.rnd(n)
	if err != nil {
		return nil, err
	}
	one := (*C.uint8_t)(C.calloc(1, 1))
	defer C.free(unsafe.Pointer(one))
	sig := make([]byte, s.a.Sig)
	var on C.size_t
	c := C.nqsfin((*C.nqsctx)(s.c.p), u8(s.sk), sz(s.sk), rp(r, one), sz(r), u8(sig), sz(sig), &on)
	s.c.drop()
	if err := rc(c); err != nil {
		return nil, err
	}
	return sig[:on], nil
}

// Verifier is Verify over a message written in pieces, as Signer.
type Verifier struct {
	pk []byte
	c  *cctx
}

// NewVerifier starts checking a signature under pk.
func NewVerifier(alg string, pk []byte, o *SignOpts) (*Verifier, error) {
	_, c, err := sini(alg, pk, o, true)
	if err != nil {
		return nil, err
	}
	return &Verifier{pk: pk, c: c}, nil
}

// Write adds p to the message.
func (v *Verifier) Write(p []byte) (int, error) { return supd(v.c, p) }

// Check reports whether sig is a valid signature of the whole message.
func (v *Verifier) Check(sig []byte) (bool, error) {
	if err := v.c.live(); err != nil {
		return false, err
	}
	c := C.nqvfin((*C.nqsctx)(v.c.p), u8(v.pk), sz(v.pk), u8(sig), sz(sig))
	v.c.drop()
	switch c {
	case 0:
		return true, nil
	case -3, -4:
		return false, nil
	default:
		return false, cerr(int(c))
	}
}

// KSeal is msg sealed to the ML-KEM public key pk (noqtis-kseal-1): only
// the holder of the secret key opens it, with the same ctx (at most 255
// bytes).
func KSeal(alg string, pk, msg, ctx []byte) ([]byte, error) {
	a, err := find(alg, "kem")
	if err != nil {
		return nil, err
	}
	out := make([]byte, 22+a.CT+len(msg))
	var n C.size_t
	if err := rc(C.nqkseal(C.nqkalg(a.ID), u8(pk), sz(pk), u8(ctx), sz(ctx), u8(msg), sz(msg),
		u8(out), sz(out), &n)); err != nil {
		return nil, err
	}
	return out[:n], nil
}

// KOpen is the message KSeal sealed: ErrVerify for a changed byte,
// another key or another ctx, ErrDecode for bytes that are not a sealed
// message of this algorithm.
func KOpen(alg string, sk, data, ctx []byte) ([]byte, error) {
	a, err := find(alg, "kem")
	if err != nil {
		return nil, err
	}
	out := make([]byte, max(len(data), 1))
	var n C.size_t
	if err := rc(C.nqkopen(C.nqkalg(a.ID), u8(sk), sz(sk), u8(ctx), sz(ctx), u8(data), sz(data),
		u8(out), sz(out), &n)); err != nil {
		return nil, err
	}
	return out[:n], nil
}

// Chunk is the default chunk size of a sealed stream (NQKFCHUNK).
const Chunk = 65536

// the chunk calls of a sealed stream
const (
	kseal = iota
	ksealfin
	kopen
	kopenfin
)

func kstep(c *cctx, op int, in []byte, cp int) ([]byte, error) {
	if err := c.live(); err != nil {
		return nil, err
	}
	out := make([]byte, max(cp, 1))
	var n C.size_t
	x, o := (*C.nqkfctx)(c.p), u8(out)
	var r C.int
	switch op {
	case kseal:
		r = C.nqkfeupd(x, u8(in), sz(in), o, C.size_t(cp), &n)
	case ksealfin:
		r = C.nqkfefin(x, u8(in), sz(in), o, C.size_t(cp), &n)
	case kopen:
		r = C.nqkfdupd(x, u8(in), sz(in), o, C.size_t(cp), &n)
	default:
		r = C.nqkfdfin(x, u8(in), sz(in), o, C.size_t(cp), &n)
	}
	last := op == ksealfin || op == kopenfin
	if last || (r != 0 && r != -2) {
		c.drop()
	}
	if err := rc(r); err != nil {
		return nil, err
	}
	return out[:n], nil
}

// Boxer seals a stream to an ML-KEM public key (noqtis-kstream-1), the
// format of noqtis box: write Header first, then Seal each full chunk of
// Chunk bytes and Final the last (0 to Chunk bytes; a stream that ends
// on a full chunk ends with it).
type Boxer struct {
	Header []byte
	Chunk  int
	c      *cctx
}

// NewBoxer starts a stream to pk with chunks of chunk bytes (1024 to
// 16777216; 0 for Chunk).
func NewBoxer(alg string, pk, ctx []byte, chunk int) (*Boxer, error) {
	a, err := find(alg, "kem")
	if err != nil {
		return nil, err
	}
	if chunk == 0 {
		chunk = Chunk
	}
	if chunk < 0 || chunk > 1<<24 {
		return nil, why(-1, "chunk: 1024 to 16777216 bytes")
	}
	c := newctx(unsafe.Sizeof(C.nqkfctx{}))
	h := make([]byte, 17+a.CT)
	var hl C.size_t
	if err := rc(C.nqkfeini((*C.nqkfctx)(c.p), C.nqkalg(a.ID), u8(pk), sz(pk), u8(ctx), sz(ctx),
		C.uint32_t(chunk), u8(h), sz(h), &hl)); err != nil {
		c.drop()
		return nil, err
	}
	return &Boxer{Header: h[:hl], Chunk: chunk, c: c}, nil
}

// Seal is one full chunk, sealed.
func (b *Boxer) Seal(p []byte) ([]byte, error) {
	return kstep(b.c, kseal, p, b.Chunk+16)
}

// Final is the last chunk, sealed; the stream ends.
func (b *Boxer) Final(p []byte) ([]byte, error) {
	return kstep(b.c, ksealfin, p, b.Chunk+16)
}

// Unboxer opens what Boxer wrote: NewUnboxer with the header, then Open
// each sealed chunk (Chunk + 16 bytes) and Final the last. A chunk's
// plaintext comes back only when its tag verifies (ErrVerify otherwise:
// a changed, moved, dropped or cut chunk).
type Unboxer struct {
	Chunk int
	c     *cctx
}

// NewUnboxer reads the header (17 bytes and the KEM ciphertext).
func NewUnboxer(alg string, sk, hdr, ctx []byte) (*Unboxer, error) {
	a, err := find(alg, "kem")
	if err != nil {
		return nil, err
	}
	c := newctx(unsafe.Sizeof(C.nqkfctx{}))
	var ch C.uint32_t
	if err := rc(C.nqkfdini((*C.nqkfctx)(c.p), C.nqkalg(a.ID), u8(sk), sz(sk), u8(ctx), sz(ctx),
		u8(hdr), sz(hdr), &ch)); err != nil {
		c.drop()
		return nil, err
	}
	return &Unboxer{Chunk: int(ch), c: c}, nil
}

// Open is one sealed chunk, opened.
func (u *Unboxer) Open(p []byte) ([]byte, error) {
	return kstep(u.c, kopen, p, u.Chunk)
}

// Final is the last sealed chunk, opened; the stream ends.
func (u *Unboxer) Final(p []byte) ([]byte, error) {
	return kstep(u.c, kopenfin, p, u.Chunk)
}

// pump moves r to w in pieces of n bytes through f, its flag true for the
// last piece (the one no byte follows), one piece in memory.
func pump(r io.Reader, w io.Writer, n int, f func([]byte, bool) ([]byte, error)) error {
	b := make([]byte, n)
	defer Wipe(b)
	pre := 0
	var nx [1]byte
	for {
		k, err := io.ReadFull(r, b[pre:])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return why(-7, "%v", err)
		}
		got := pre + k
		more := false
		if got == n {
			m, err := io.ReadFull(r, nx[:])
			if err != nil && err != io.EOF {
				return why(-7, "%v", err)
			}
			more = m == 1
		}
		o, err := f(b[:got], !more)
		if err != nil {
			return err
		}
		if _, err := w.Write(o); err != nil {
			return why(-7, "%v", err)
		}
		if !more {
			return nil
		}
		b[0], pre = nx[0], 1
	}
}

// Box seals all of r to w as noqtis box does (the same format), one
// chunk in memory; chunk as for NewBoxer.
func Box(alg string, pk []byte, r io.Reader, w io.Writer, ctx []byte, chunk int) error {
	b, err := NewBoxer(alg, pk, ctx, chunk)
	if err != nil {
		return err
	}
	if _, err := w.Write(b.Header); err != nil {
		return why(-7, "%v", err)
	}
	return pump(r, w, b.Chunk, func(p []byte, last bool) ([]byte, error) {
		if last {
			return b.Final(p)
		}
		return b.Seal(p)
	})
}

// Unbox opens a sealed stream from r to w, chunk by chunk. On an error
// what was written before the bad chunk had verified, but the stream is
// incomplete: discard w's output.
func Unbox(alg string, sk []byte, r io.Reader, w io.Writer, ctx []byte) error {
	a, err := find(alg, "kem")
	if err != nil {
		return err
	}
	h := make([]byte, 17+a.CT)
	k, err := io.ReadFull(r, h)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return why(-7, "%v", err)
	}
	u, err := NewUnboxer(alg, sk, h[:k], ctx)
	if err != nil {
		return err
	}
	return pump(r, w, u.Chunk+16, func(p []byte, last bool) ([]byte, error) {
		if last {
			return u.Final(p)
		}
		return u.Open(p)
	})
}
