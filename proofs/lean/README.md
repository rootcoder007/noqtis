# Lean proofs of the arithmetic

Machine-checked proofs (Lean 4 and Mathlib) of the mathematical facts the
C code relies on: the constants, reductions, roundings, encodings and bit
tricks, each stated for the constants and input ranges the C uses. Each
theorem's docstring names the C function and file it is about.

What they prove, and what they do not: they prove the mathematics and the
stated bounds of a model written in Lean. They do not prove that the C
code computes that model. The link from each C function to its model is
by inspection (the model is written to mirror the C expression by
expression, and the docstring names the function) and by the tests
(ACVP and Wycheproof vectors, the OpenSSL cross-check, the differential
test). They are not a proof of the C program, of the compiler, or of any
side-channel property.

| file | about | main theorems |
|---|---|---|
| `Mlkem.lean` | src/mlkem/ring.h, kem.c | Montgomery `nqmkmr` and Barrett `nqmkbr` (residue and range for every input the code gives them), `nqmkps`, the divide-free `nqmkdq`/`nqmkmq`, Compress/Decompress rounding and FIPS 203's error bound for d = 1, 4, 5, 10, 11, 17 a primitive 256th root of unity, the roots of X¹²⁸ + 1, the inverse NTT's factor |
| `Mldsa.lean` | src/mldsa/md.h, poly.c, sign.c | Montgomery `nqmdmr`, `nqmdrd`, `nqmdcq`, Power2Round, `nqmddec` equal to FIPS 204's Decompose for both γ₂, FIPS 204's Lemma 2 (UseHint(MakeHint(z, r), r) = HighBits(r + z)), 1753 a primitive 512th root of unity |
| `Ct.lean` | src/core/int.h, core.c, mldsa/poly.c, mlkem/ring.h | `nqctmask`, `nqctsel`, `nqcmov`, `nqcteq`, `nqmkps` for every word, and the wrap in `nqmddec`, `nqmdmkh`, `nqmdchk` for every word in the range the code gives them; the byte order of the 32-bit load/store helpers (the 64-bit ones are built from them or the same way) |
| `Slh.lean` | src/slh/slh.c, in.h | WOTS+ len = 2n + 3, the checksum fits, FIPS 205's m, the signature sizes |
| `Gf.lean` | src/hqc/code.c | `gm` is the GF(2⁸) product mod 0x11D, `ginv` the inverse, α = x of order 255 |
| `Ntt.lean` | src/mlkem/kem.c (`nqmkntt`, `nqmkint`, `nqmkdot`), src/mldsa/poly.c (`nqmdntt`, `nqmdint`) | X²⁵⁶ + 1 = ∏ (X² − 17^(2i+1)) over Z₃₃₂₉ (the 128 moduli of ML-KEM's incomplete NTT) and = ∏ (X − 1753^(2i+1)) over Z₈₃₈₀₄₁₇ (ML-DSA's complete NTT) |
| `Enc.lean` | src/mlkem (`nqmkbe`/`nqmkbd`), src/mldsa/poly.c (`nqmdbpk`/`nqmdbun`) | ByteEncode_d and ByteDecode_d are inverse bijections between L values of d bits and the d·L/8-byte string |

Byte order. Every statement about bytes is about a byte sequence: the
little-endian packing of FIPS 203 and 204 (`Enc.lean`) is the number
`Σ aᵢ 2^{d i} = Σ bⱼ 256^j` written in two bases, and the load/store
helpers (`Ct.lean`) are proved inverse between a word and its four bytes
in each order. None depends on the host's byte order. The C helpers
behind them assume none either: `nqld32l`, `nqst32l`, `nqld32b`,
`nqst32b`, `nqld64l`, `nqst64l`, `nqld64b`, `nqst64b` (src/core/int.h),
`nqmkbe`/`nqmkbd` and `nqmdbpk`/`nqmdbun` build values with shifts and
ORs of single bytes and never read a word through a pointer cast; CI runs
the tests on little-endian hosts and on big-endian s390x.

C semantics assumed. Signed `>>` of a negative value is an arithmetic
shift (implementation-defined in C11; what GCC, Clang and MSVC do), which
is floor division by a power of two; the models write it as `Int./` by a
positive literal, which is floor division. Casts to narrower unsigned
types keep the low bits, and back to signed take them as two's
complement (`lo16`, `lo32`). The bit-level theorems in `Ct.lean` and
`Gf.lean` model uint32_t and int32_t as 32-bit `BitVec`s.

Axioms. Every theorem uses only the standard ones (`propext`,
`Classical.choice`, `Quot.sound`) or fewer, except those proved with
`bv_decide` (`Ct.lean`; `Gf.gm_spec`): with this Lean (4.34) each of
those also depends on axioms `<theorem>._native.bv_decide.ax_*` that
`bv_decide` adds, stating that the compiled SAT-certificate checker
accepted its certificate; that trusts the Lean compiler and runtime as
`Lean.ofReduceBool` does (earlier Lean versions used that axiom by name).
`#print axioms` on each shows this. The exhaustive checks
(`Gf.ginv_spec`, `Gf.alpha_order`, `Slh`) use `decide`, which the kernel
checks itself. There is no `sorry`.

Not proved: that the NTT and inverse NTT butterfly networks of
`nqmkntt`/`nqmkint` and `nqmdntt`/`nqmdint` compute the transforms
(here: the roots of unity and the factorisations of X²⁵⁶ + 1 the
transforms work modulo); bounds on the coefficients inside the
butterflies; anything about SHA-2, SHA-3 or the samplers.

## Build

Lean and Mathlib as `lean-toolchain` and `lake-manifest.json` pin them:

```sh
lake exe cache get   # the prebuilt Mathlib, about 5 GB
lake build           # must end "Build completed successfully"
```

CI: `.github/workflows/lean.yml`.
