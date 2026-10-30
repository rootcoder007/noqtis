---
title: Use from Go
description: The noqtis Go package - seal and check a folder, sign and verify, encapsulate and hash, with the C library compiled in by cgo.
---

The Go package compiles the C library into itself with cgo, from a copy
of the sources in the module: it needs a C compiler (gcc or clang; on
Windows, MinGW-w64 gcc) and nothing else. It builds on Linux, macOS and
Windows.

```sh
go get github.com/rootcoder007/noqtis/bindings/go
```

```go
import "github.com/rootcoder007/noqtis/bindings/go"   // package noqtis
```

## Seal and check a folder

This is `Example_seal` in the package's `example_test.go`; `go test`
runs it and checks what it prints:

```go
// a folder with some results
d, _ := os.MkdirTemp("", "noqtis-go-demo")
defer os.RemoveAll(d)
os.MkdirAll(filepath.Join(d, "data"), 0o755)
os.WriteFile(filepath.Join(d, "data", "in.csv"), []byte("a,b\n1,2\n"), 0o644)
os.WriteFile(filepath.Join(d, "report.txt"), []byte("r\n"), 0o644)

// seal it, then check it with the public key pinned
pk, sk, _ := noqtis.SignKeyGen("ML-DSA-65", nil)
if err := noqtis.Seal(d, "ML-DSA-65", sk, pk, `{"project":"tutorial"}`); err != nil {
	panic(err)
}
o := &noqtis.CheckOpts{Trust: pk}
r, err := noqtis.Check(d, o)
if err != nil {
	panic(err)
}
fmt.Printf("check: %v (%d checks)\n", r.OK(), len(r.Rows))

// change a file: the check fails and says why
os.WriteFile(filepath.Join(d, "report.txt"), []byte("r\nedited\n"), 0o644)
r, _ = noqtis.Check(d, o)
fmt.Println("after edit:", r.OK())
for _, row := range r.Failed() {
	fmt.Println("FAIL", row.Check, row.Detail)
}
```

It prints:

```text
check: true (22 checks)
after edit: false
FAIL file report.txt: size differs
```

- `Seal` writes `noqtis.json` and `noqtis.sig` into the folder; `meta`
  is JSON text (an object), signed with the manifest and never
  interpreted. `Seal2` seals in format 2, with the capsules it was made
  from.
- `Check` returns a `*Report` also when the capsule fails: `OK()` is
  true only when every check passed, and `Rows` lists every check.
  Without `Trust` it accepts the key in the seal, and the `key` row says
  so.
- `Inspect`, `CapID`, `Prove` and `CheckProof` do what `noqtis inspect`,
  the capsule id, `noqtis prove` and `noqtis check --proof` do.

## Sign and verify

`Example_sign`:

```go
pk, sk, err := noqtis.SignKeyGen("ML-DSA-65", nil)
if err != nil {
	panic(err)
}
o := &noqtis.SignOpts{Ctx: []byte("app-v1")}
msg := []byte("the results in table 2")
sig, err := noqtis.Sign("ML-DSA-65", sk, msg, o)
if err != nil {
	panic(err)
}
fmt.Println("signature:", len(sig), "bytes")
ok, _ := noqtis.Verify("ML-DSA-65", pk, msg, sig, o)
fmt.Println("verify:", ok)
ok, _ = noqtis.Verify("ML-DSA-65", pk, []byte("other"), sig, o)
fmt.Println("other message:", ok)
```

```text
signature: 3309 bytes
verify: true
other message: false
```

`Verify` returns `false, nil` for a bad signature; only a bad argument is
an error. Every error is an `*noqtis.Error` with the library's code
(`Code`) and message (`Msg`, from `nqerr`); `errors.Is(err,
noqtis.ErrVerify)` and its siblings match by code.

## Notes

- `KEMKeyGen`, `Encap` and `Decap` do key encapsulation; `Hash`,
  `HashN`, `HMAC` and `Random` the rest; `ReadKey` and `WriteKey` read
  and write the CLI's key files.
- Secret keys are plain `[]byte`: overwrite them yourself when that
  matters.

The full API is in the package's
[README](https://github.com/rootcoder007/noqtis/tree/main/bindings/go#readme).
