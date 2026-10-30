// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

package noqtis

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
)

// KeyMagic is the first word of every key file.
const KeyMagic = "noqtis-key-1"

// Key is a decoded key file (DESIGN.md, "Key files"): the algorithm's
// name as noqtis spells it, "pub" or "sec", and the key bytes.
type Key struct {
	Alg  string
	Kind string
	Key  []byte
}

func kalg(name string) (Alg, error) {
	a, err := Find(name)
	if err != nil {
		return a, why(-8, "unknown algorithm %q (the names `noqtis algs` lists)", name)
	}
	return a, nil
}

func ksize(a Alg, kind string) int {
	if kind == "pub" {
		return a.PK
	}
	return a.SK
}

// 0-25 'A'.., 26-51 'a'.., 52-61 '0'.., 62 '+', 63 '/', without branches
func ench(x int32) byte {
	c := x + 65
	c += ((25 - x) >> 8) & 6
	c -= ((51 - x) >> 8) & 75
	c -= ((61 - x) >> 8) & 15
	c += ((62 - x) >> 8) & 3
	return byte(c)
}

// the value of a base64 character, or -1, without branches
func dech(b byte) int32 {
	c := int32(b)
	r := func(lo, hi, off int32) int32 {
		m := ((lo - 1 - c) & (c - hi - 1)) >> 8 // -1 when lo <= c <= hi
		return m & (c - lo + off + 1)
	}
	v := int32(-1) + r(65, 90, 0) + r(97, 122, 26) + r(48, 57, 52)
	v += (((42 - c) & (c - 44)) >> 8) & 63 // '+': 62
	v += (((46 - c) & (c - 48)) >> 8) & 64 // '/': 63
	return v
}

func b64e(k []byte) []byte {
	out := make([]byte, 0, (len(k)+2)/3*4)
	for i := 0; i < len(k); i += 3 {
		n := len(k) - i
		v := int32(k[i]) << 16
		if n > 1 {
			v |= int32(k[i+1]) << 8
		}
		if n > 2 {
			v |= int32(k[i+2])
		}
		out = append(out, ench(v>>18), ench((v>>12)&63))
		if n > 1 {
			out = append(out, ench((v>>6)&63))
		} else {
			out = append(out, '=')
		}
		if n > 2 {
			out = append(out, ench(v&63))
		} else {
			out = append(out, '=')
		}
	}
	return out
}

// strict, padded, canonical base64, or nil
func b64d(s []byte) []byte {
	if len(s)%4 != 0 {
		return nil
	}
	out := make([]byte, 0, len(s)/4*3)
	bad := int32(0)
	for i := 0; i < len(s); i += 4 {
		g := s[i : i+4]
		pad := 0
		if i+4 == len(s) {
			if g[3] == '=' {
				pad++
			}
			if g[2] == '=' {
				pad++
			}
			if pad == 1 && g[2] == '=' {
				return nil
			}
		}
		v := uint32(0)
		for j, c := range g {
			d := int32(0)
			if j < 4-pad {
				d = dech(c)
			}
			bad |= d
			v = v<<6 | uint32(d)&63
		}
		out = append(out, byte(v>>16))
		if pad < 2 {
			out = append(out, byte(v>>8))
		} else if v&0xffff != 0 {
			return nil
		}
		if pad < 1 {
			out = append(out, byte(v))
		} else if v&0xff != 0 {
			return nil
		}
	}
	if bad < 0 {
		return nil
	}
	return out
}

// EncodeKey is the key file text for key: kind is "pub" or "sec".
func EncodeKey(alg, kind string, key []byte) (string, error) {
	a, err := kalg(alg)
	if err != nil {
		return "", err
	}
	if kind != "pub" && kind != "sec" {
		return "", why(-1, `kind: "pub" or "sec"`)
	}
	if want := ksize(a, kind); len(key) != want {
		return "", why(-1, "%s %s key: %d bytes, not %d", a.Name, kind, want, len(key))
	}
	b := b64e(key)
	var s strings.Builder
	s.WriteString(KeyMagic + " " + a.Name + " " + kind + "\n")
	for i := 0; i < len(b); i += 64 {
		e := min(i+64, len(b))
		s.Write(b[i:e])
		s.WriteByte('\n')
	}
	return s.String(), nil
}

func notkey() error {
	return why(-4, "not a noqtis key file (want a first line %q)", KeyMagic+" <alg> <pub|sec>")
}

// DecodeKey is the algorithm, kind and key of key file text, read as
// strictly as the CLI reads it: the exact header, "\n" or "\r\n" line
// ends and nothing else outside the base64 alphabet, canonical padding,
// and the algorithm's exact key size.
func DecodeKey(text []byte) (*Key, error) {
	nl := bytes.IndexByte(text, '\n')
	if nl < 0 || nl >= 96 {
		return nil, notkey()
	}
	h := strings.TrimSuffix(string(text[:nl]), "\r")
	f := strings.Split(h, " ")
	if len(f) != 3 || f[0] != KeyMagic || (f[2] != "pub" && f[2] != "sec") {
		return nil, notkey()
	}
	a, err := kalg(f[1])
	if err != nil {
		return nil, err
	}
	want := ksize(a, f[2])
	body := make([]byte, 0, len(text)-nl)
	for _, c := range text[nl+1:] {
		if c != '\r' && c != '\n' {
			body = append(body, c)
		}
	}
	k := b64d(body)
	if k == nil || len(k) != want {
		return nil, why(-4, "the key is not %d bytes of base64 for %s (the file is damaged or cut short)", want, a.Name)
	}
	return &Key{Alg: a.Name, Kind: f[2], Key: k}, nil
}

// ReadKey reads a key file; kind "pub" or "sec" requires that kind, ""
// takes either.
func ReadKey(path, kind string) (*Key, error) {
	if kind != "" && kind != "pub" && kind != "sec" {
		return nil, why(-1, `kind: "", "pub" or "sec"`)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, why(-7, "cannot read key file %s: %v", path, err)
	}
	defer f.Close()
	t, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, why(-7, "cannot read key file %s: %v", path, err)
	}
	k, err := DecodeKey(t)
	if err != nil {
		return nil, err
	}
	if kind != "" && k.Kind != kind {
		w := map[string]string{"pub": "public", "sec": "secret"}
		return nil, why(-1, "%s is a %s key; give the %s key", path, w[k.Kind], w[kind])
	}
	return k, nil
}

// WriteKey writes a key file. A secret key file is created owner-only
// (on Unix), never through a link; an existing file is kept unless
// force, which removes it first so the new one never inherits its
// permissions.
func WriteKey(path, alg, kind string, key []byte, force bool) error {
	t, err := EncodeKey(alg, kind, key)
	if err != nil {
		return err
	}
	if force {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return why(-7, "cannot replace %s: %v", path, err)
		}
	}
	mode := os.FileMode(0o644)
	if kind == "sec" {
		mode = 0o600
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, fs.ErrExist) {
		return why(-7, "%s exists (pass force to replace it)", path)
	}
	if err != nil {
		return why(-7, "cannot write %s: %v", path, err)
	}
	if _, err := f.WriteString(t); err != nil {
		f.Close()
		return why(-7, "cannot write %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		return why(-7, "cannot write %s: %v", path, err)
	}
	return nil
}
