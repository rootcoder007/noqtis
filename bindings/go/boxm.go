// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

package noqtis

/*
#include <stdlib.h>
#include "noqtis.h"
*/
import "C"

import (
	"io"
	"unsafe"
)

// Rcp is one recipient of BoxTo: an ML-KEM algorithm and its public key.
type Rcp struct {
	Alg string
	PK  []byte
}

// Sender is who signs a stream of BoxTo: a signature algorithm and
// its secret key.
type Sender struct {
	Alg string
	SK  []byte
}

// BoxTo seals all of r to w for every recipient in rcps (1 to 64), as
// noqtis box -p ... -p ... does (noqtis-kstream-2): the secret key of any
// one of them opens it. With sig not nil the stream is signed by its
// sender: the signature is inside the encryption and covers the
// recipients. One chunk is in memory; chunk as for NewBoxer.
func BoxTo(rcps []Rcp, sig *Sender, r io.Reader, w io.Writer, ctx []byte, chunk int) error {
	if len(rcps) == 0 || len(rcps) > 64 {
		return why(-1, "recipients: 1 to 64")
	}
	if chunk == 0 {
		chunk = Chunk
	}
	if chunk < 0 || chunk > 1<<24 {
		return why(-1, "chunk: 1024 to 16777216 bytes")
	}
	var m cmem
	defer m.free()
	// the recipients' keys in C memory: the array holds pointers
	cr := unsafe.Slice((*C.nqkrcp)(m.alloc(uintptr(len(rcps)), unsafe.Sizeof(C.nqkrcp{}))), len(rcps))
	for i, x := range rcps {
		a, err := find(x.Alg, "kem")
		if err != nil {
			return err
		}
		cr[i].alg = C.nqkalg(a.ID)
		cr[i].pk = m.bytes(x.PK)
		cr[i].pklen = C.size_t(len(x.PK))
	}
	var sg C.nqsalg
	rec := 0
	var sk []byte
	if sig != nil {
		a, err := find(sig.Alg, "sign")
		if err != nil {
			return err
		}
		sg, rec, sk = C.nqsalg(a.ID), a.Sig+16, sig.SK
		if len(sk) == 0 {
			return why(-1, "the signer's secret key is needed")
		}
	}
	var hl C.size_t
	if err := rc(C.nqkmhlen(&cr[0], C.size_t(len(rcps)), &hl)); err != nil {
		return err
	}
	c := newctx(unsafe.Sizeof(C.nqkmctx{}))
	defer c.drop()
	h := make([]byte, int(hl))
	if err := rc(C.nqkmeini((*C.nqkmctx)(c.p), &cr[0], C.size_t(len(rcps)), sg, u8(ctx), sz(ctx),
		C.uint32_t(chunk), u8(h), sz(h), &hl)); err != nil {
		return err
	}
	if _, err := w.Write(h[:hl]); err != nil {
		return why(-7, "%v", err)
	}
	out := make([]byte, chunk+16+rec)
	return pump(r, w, chunk, func(p []byte, last bool) ([]byte, error) {
		var n C.size_t
		var e C.int
		if last {
			e = C.nqkmefin((*C.nqkmctx)(c.p), u8(p), sz(p), u8(sk), sz(sk), u8(out), sz(out), &n)
		} else {
			e = C.nqkmeupd((*C.nqkmctx)(c.p), u8(p), sz(p), u8(out), sz(out), &n)
		}
		if err := rc(e); err != nil {
			return nil, err
		}
		return out[:n], nil
	})
}

// UnboxFrom opens a stream BoxTo sealed, from r to w, with the secret key
// sk (of the ML-KEM algorithm alg) of one of its recipients. sender is
// the public key the stream must be signed with: a stream that is not
// signed, or is signed by another key, gives ErrVerify. With sender nil
// the signature is not checked. It returns the signature algorithm the
// stream names, "" when it is not signed.
//
// Plaintext is written chunk by chunk, before the signature at the end
// is checked: on an error discard what w received.
func UnboxFrom(alg string, sk, sender []byte, r io.Reader, w io.Writer, ctx []byte) (string, error) {
	a, err := find(alg, "kem")
	if err != nil {
		return "", err
	}
	fx := make([]byte, 24)
	if _, err := io.ReadFull(r, fx); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return "", cerr(-4)
		}
		return "", why(-7, "%v", err)
	}
	var hl, nr C.size_t
	var sg C.nqsalg
	if err := rc(C.nqkmpeek(u8(fx), sz(fx), &hl, &sg, &nr)); err != nil {
		return "", err
	}
	h := make([]byte, int(hl))
	copy(h, fx)
	if _, err := io.ReadFull(r, h[24:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return "", cerr(-4)
		}
		return "", why(-7, "%v", err)
	}
	name, rec := "", 0
	if sg != 0 {
		var z C.nqssz
		if err := rc(C.nqssize(sg, &z)); err != nil {
			return "", err
		}
		name, rec = C.GoString(C.nqsname(sg)), int(z.sig)+16
	}
	c := newctx(unsafe.Sizeof(C.nqkmctx{}))
	defer c.drop()
	var ch C.uint32_t
	if err := rc(C.nqkmdini((*C.nqkmctx)(c.p), C.nqkalg(a.ID), u8(sk), sz(sk), u8(ctx), sz(ctx),
		u8(h), sz(h), &ch, nil)); err != nil {
		return name, err
	}
	// the window: one chunk, the record after the last, and one byte
	// more; full, its first chunk is not the last
	full := int(ch) + 16
	win := make([]byte, full+rec+1)
	out := make([]byte, max(int(ch), 1))
	have := 0
	for {
		k, err := io.ReadFull(r, win[have:])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return name, why(-7, "%v", err)
		}
		have += k
		more := have == len(win)
		var n C.size_t
		var e C.int
		if more {
			e = C.nqkmdupd((*C.nqkmctx)(c.p), u8(win[:full]), C.size_t(full), u8(out), sz(out), &n)
		} else {
			e = C.nqkmdfin((*C.nqkmctx)(c.p), u8(win[:have]), C.size_t(have), u8(sender), sz(sender),
				u8(out), sz(out), &n)
		}
		if err := rc(e); err != nil {
			return name, err
		}
		if _, err := w.Write(out[:n]); err != nil {
			return name, why(-7, "%v", err)
		}
		if !more {
			return name, nil
		}
		have = copy(win, win[full:have])
	}
}
