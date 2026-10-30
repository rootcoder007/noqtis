# noqtis for Go <img src="https://raw.githubusercontent.com/rootcoder007/noqtis/main/docs/logo/noqtis-hex-512.png" align="right" height="139" alt="NOQTIS hex logo" />

Post-quantum signatures, key encapsulation, hashes and sealed file
capsules, from the [noqtis](https://github.com/rootcoder007/noqtis) C
library. cgo compiles the library into the package from the copy in
`csrc/`: a C compiler is all it needs (gcc or clang; on Windows, a
MinGW-w64 gcc), no system `libnoqtis`.

| Family | Algorithms | Standard |
|---|---|---|
| Signatures | ML-DSA-44/65/87 | FIPS 204 |
| | SLH-DSA-SHA2 and SLH-DSA-SHAKE, 128/192/256, s and f | FIPS 205 |
| | Ed25519, and the hybrids ML-DSA-44/65/87+Ed25519 | RFC 8032 |
| KEMs | ML-KEM-512/768/1024 | FIPS 203 |
| | HQC-128/192/256 | HQC round 4 |
| Hashes | SHA-224 ... SHA-512/256, SHA3-224 ... SHA3-512, SHAKE128/256, HMAC | FIPS 180-4, FIPS 202 |

```sh
go get github.com/rootcoder007/noqtis/bindings/go
```

```go
import "github.com/rootcoder007/noqtis/bindings/go"   // package noqtis
```

## Signatures

From `example_test.go` (`go test -run Example`, which checks the output):

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
// Output:
// signature: 3309 bytes
// verify: true
// other message: false
```

- `SignKeyGen(alg, seed)` returns `pk, sk`; a non-nil seed gives the
  standard's deterministic key pair.
- `SignOpts` holds the context (`Ctx`, at most 255 bytes),
  `Deterministic` (all-zero per-signature randomness), `Rnd` (that
  randomness given explicitly) and `Prehash` (`"SHA-512"` or any name
  from `noqtis.Hashes()`: HashML-DSA / HashSLH-DSA / Ed25519ph; the
  message is still the message). A nil `*SignOpts` is all defaults.
- `Verify` returns `false, nil` for a bad or malformed signature; only a
  bad argument is an error.

## Key encapsulation

```go
pk, sk, _ := noqtis.KEMKeyGen("ML-KEM-768", nil)
ct, ss, _ := noqtis.Encap("ML-KEM-768", pk, nil)
ss2, _ := noqtis.Decap("ML-KEM-768", sk, ct) // equal to ss
```

A tampered ciphertext decapsulates to an unrelated secret rather than an
error (implicit rejection, as FIPS 203 requires).

## Hashes and random bytes

```go
noqtis.Hash("SHA3-256", []byte("abc"))
noqtis.HashN("SHAKE256", []byte("abc"), 100)   // 100 bytes of output
noqtis.HMAC("SHA-256", []byte("key"), []byte("data"))
noqtis.Random(32)                              // the OS CSPRNG
```

## Capsules

A capsule is a folder sealed with a manifest of every file in it
(`noqtis.json`) and a post-quantum signature over it (`noqtis.sig`), the
same files the `noqtis` command writes and checks. From
`example_test.go`:

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
// Output:
// check: true (22 checks)
// after edit: false
// FAIL file report.txt: size differs
```

- `Check` returns a `*Report` (`Code`, `Rows` of `Check`, `OK`,
  `Detail`) also when the capsule fails; `Report.OK()` is true only when
  every check passed. A nil `*CheckOpts` (or a nil `Trust`) accepts the
  key in the seal, and the `key` row says so. `CheckOpts` also takes TSA
  `Anchors` (DER), `Only` (a partial check), `Lineage` (folders to find
  a format 2 capsule's inputs in) and key statements (`Stmts`).
- `Seal2(dir, alg, sk, pk, meta, inputs)` seals in format 2 (a Merkle
  tree over the files), recording the capsules it was made from
  (`noqtis.Input{ID, Name}`, the ID from `CapID`).
- `Prove(dir, []string{"data/in.csv"})` writes a proof (noqtis-proof-1)
  that shows those files of a format 2 capsule and nothing of the
  others; `CheckProof(proof, opts, dir)` checks one.
- `Inspect(dir)` says what a capsule says without checking anything (the
  `info.*` rows, `Report.Get("info.alg")`); `Files(dir)` adds one
  `info.file` row per listed file.

## Identity cards

```go
f := noqtis.CardFields{Name: "Ada Lovelace", ORCID: "0000-0002-1825-0097"}
card, err := noqtis.MakeCard("ML-DSA-65", sk, pk, f, time.Time{})
c, err := noqtis.VerifyCard(card, pk) // *Card, or nil when it does not verify
```

A card (noqtis-idcard-1, JSON) binds the key to its holder's name and,
when given, ORCID iD (check digit verified), e-mail address, `https://`
page and affiliation, signed by the key under its own context, so it is
never a seal or a key statement. It is self-signed: compare `KeySHA256`
with the one its holder published, or pass the key.

## Key files

`ReadKey`, `WriteKey`, `EncodeKey` and `DecodeKey` read and write the
text key files `noqtis keygen` makes (`noqtis-key-1 <alg> <pub|sec>`,
then base64), as strictly as the command-line tool reads them:

```go
k, err := noqtis.ReadKey("me", "sec")        // *Key{Alg, Kind, Key}
sig, err := noqtis.Sign(k.Alg, k.Key, []byte("a message"), nil)

pk, sk, _ := noqtis.SignKeyGen("ML-DSA-65", nil)
noqtis.WriteKey("you", "ML-DSA-65", "sec", sk, false)      // owner-only, no overwrite
noqtis.WriteKey("you.pub", "ML-DSA-65", "pub", pk, false)
```

## Errors

Every failure is an `*noqtis.Error`: `Code` is the library's `NQE*`
value (-1 for NQEARG, ...), `Msg` the library's message (`nqerr`) and
`Why` what was wrong. `errors.Is(err, noqtis.ErrVerify)` (and `ErrArg`,
`ErrBuf`, `ErrDecode`, `ErrRand`, `ErrMem`, `ErrIO`, `ErrUnsupported`,
`ErrLimit`, `ErrState`) matches by code.

## Notes

- `csrc/` is a copy of the library's `src/` and `include/`, and the
  `nq_*.c` files include it, one per source file; `sh tools/vendor.sh`
  makes them again after a change to the library, and CI fails when they
  are out of date.
- Secret keys and shared secrets are plain `[]byte`: overwrite them
  yourself when that matters.

Licensed under Apache-2.0 WITH LLVM-exception.
