# CBMC proofs of the parsers

[CBMC](https://www.cprover.org/cbmc/) proves properties of C code for
every input up to a size: it unrolls the loops, turns the program and
the property into a formula, and has a solver show that no input breaks
it. These proofs cover the code that reads untrusted bytes: the DER
reader (certificates, OCSP, CRLs, timestamp tokens), the base64 decoder
(capsules, key files) and the JSON reader (capsules, the ACVP
harnesses).

They are **bounded** proofs. Each holds for every input up to the size
given below and says nothing about longer ones, except `hdr`, which
holds for every length. Longer inputs are left to the fuzzers (`fuzz/`)
and the tests.

## What every proof checks

On every path, for every input within the bound, CBMC checks:

- every array access and pointer dereference is inside its object
  (`--bounds-check`, `--pointer-check`), and no pointer arithmetic
  overflows (`--pointer-overflow-check`);
- no signed or unsigned arithmetic overflows (`--signed-overflow-check`,
  `--unsigned-overflow-check`), no division by zero, no undefined shift;
- for the JSON proofs, that every allocation is freed
  (`--memory-leak-check`);
- the assertions in each harness (below);
- `--unwinding-assertions`: every loop finished within the unwinding
  given, so a bound too small fails the proof instead of passing it.

`--conversion-check` is not used: it reports the code's deliberate
narrowing casts (such as `(uint8_t)(v >> 8)` in the base64 decoder),
which are well defined in C.

## The proofs

| Proof | Code | Bound | What it shows besides the checks above |
|---|---|---|---|
| `hdr` | `nqdhdr` | every length | a header read is 2 to 9 bytes, the element and its contents lie inside the input, the tag fields are in range |
| `der` | `nqdinit`, `nqdnext`, `nqddown`, `nqdend` | 6 bytes, every level of nesting those allow | every element lies inside its parent, and its contents inside it, as the X.509, OCSP, CRL and timestamp parsers walk them |
| `dwalk` | `nqdone`, `nqdwalk`, `nqdprim` and the content checks (INTEGER, OID, BIT STRING, the strings, the times, SET order) | 6 bytes | an accepted input is exactly one element |
| `b64` | `nqb64d` | 32 characters, into outputs of up to 24 bytes | what it reports written fits the output |
| `jlex` | the JSON lexers: `skipws`, `rdstr` (escapes and raw UTF-8), `rdnum`, `rdword` | 4 bytes | a token stays inside the input; a string is shorter than its raw text and NUL-terminated |
| `json` | `nqjparse` and `nqjfree`, with every allocation allowed to fail | 1 byte | a parse that succeeds gives a value; an error offset lies inside the input |

The JSON bounds are small. The parser keeps its tree in allocated nodes
and arrays, and CBMC's formula for them outgrows 6 GB of memory: the
whole parser fits at 1 byte and the lexers at 4 bytes, both with
`--slice-formula` (which drops what no check depends on). So these proofs show little more than that the error and free
paths are sound for the shortest inputs; `\u` escapes (6 bytes or more),
nested containers and object members are covered by the fuzzer
(`fuzz/fjson.c`) and the tests, not here.

## How the inputs are laid out

A bounds check catches a read past an object, not past the length a
function is told. So each harness gives the parser exactly the bytes it
is told of: `hdr`, `b64` (its input and its output buffer), `jlex` and
`json` allocate exactly n bytes; `der` and `dwalk` put the n bytes at
the end of an object of N bytes, which keeps their formulas within
6 GB. Either way a read or write one byte past what the parser was
given is out of bounds. (In the second layout a read before the input
is caught only when n = N.) Fresh memory has nondeterministic contents
in CBMC, so every input of each length is covered.

Two negative controls check that this bites: `neg.c` tells `nqdhdr`
(exact-size layout) and `nqdone` (end-of-object layout, `-DEND`) that
the input holds one byte more than it does, and `run.sh` fails unless
CBMC reports the out-of-bounds read in both.

In every proof CBMC's `malloc` may return NULL, so each allocation
failure path is checked too.

The harnesses replace the allocator hook (`nqmal`, `nqfree`) with plain
`malloc` and `free`; `jlex` includes `src/core/json.c` to reach its
static functions.

## Running them

```sh
sh proofs/cbmc/run.sh
```

It needs `cbmc` (tested with 6.7.1). Each proof prints
`VERIFICATION SUCCESSFUL` with its time, and the whole run takes about 7
minutes on one core and at most 6 GB of memory. The logs are in
`$TMPDIR/cbmc-<name>.log`. CI runs it in a pinned Fedora 43 container
(`.github/workflows/cbmc.yml`).

A proof that fails prints the failed checks; `cbmc --trace` with the
same arguments shows an input that breaks it.
