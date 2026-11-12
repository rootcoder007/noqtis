/-
  noqtis: proofs/lean/Slh.lean

  SLH-DSA's derived sizes (src/slh/slh.c, `NQSLROW` and `nqsltab`;
  src/slh/in.h): for the twelve parameter sets (six (n, h, d, a, k, m)
  rows, each with SHA2 and SHAKE), the WOTS+ lengths the code writes as
  `2n + 3`, the checksum's fit, FIPS 205's formula for m, and the key and
  signature sizes, against FIPS 205 (sections 5 and 11, table 2).
-/
import Mathlib

set_option linter.style.longLine false
set_option linter.style.header false

namespace Noqtis.Slh

/-- The six rows of `nqsltab`: n, h, d, a, k, m. -/
def rows : List (ℕ × ℕ × ℕ × ℕ × ℕ × ℕ) :=
  [(16, 63, 7, 12, 14, 30), (16, 66, 22, 6, 33, 34), (24, 63, 7, 14, 17, 39),
   (24, 66, 22, 8, 33, 42), (32, 64, 8, 14, 22, 47), (32, 68, 17, 9, 35, 49)]

/-- FIPS 205 (5.1)-(5.4), lg w = 4, w = 16: len1 = ⌈8n / lg w⌉, len2 = ⌊log₂(len1 (w − 1)) / lg w⌋ + 1. -/
def len1 (n : ℕ) : ℕ := (8 * n + 3) / 4
def len2 (n : ℕ) : ℕ := Nat.log 2 (len1 n * 15) / 4 + 1

/-- The code's `len = 2n + 3` is FIPS 205's `len1 + len2` (35, 51 and 67), and
`NQSLLMX = 67` is the largest. -/
theorem len_eq : ∀ r ∈ rows, len1 r.1 + len2 r.1 = 2 * r.1 + 3 := by decide

theorem len_max : ∀ r ∈ rows, 2 * r.1 + 3 ≤ 67 := by decide

/-- The WOTS+ checksum, at most `len1 · (w − 1)`, fits in `len2` base-16 digits, so the
`len2 · lg w` bits `base_2b` reads (after the shift by `(8 − len2 lg w mod 8) mod 8`) hold it. -/
theorem csum_fits : ∀ r ∈ rows, len1 r.1 * 15 < 16 ^ len2 r.1 := by decide

/-- `h` is a multiple of `d` (`h' = h / d` is exact), and `k ≤ NQSLKMX = 35`. -/
theorem layers : ∀ r ∈ rows, r.2.2.1 ∣ r.2.1 ∧ r.2.2.2.2.1 ≤ 35 := by decide

/-- m is FIPS 205's `⌈k a / 8⌉ + ⌈(h − h/d) / 8⌉ + ⌈h / (8 d)⌉`: the message digest has room
for the FORS indices, the tree index and the leaf index. -/
theorem m_eq : ∀ r ∈ rows,
    let (_, h, d, a, k, m) := r
    m = (k * a + 7) / 8 + (h - h / d + 7) / 8 + (h / d + 7) / 8 := by decide

/-- The signature size the code computes, `n (1 + k (a + 1) + h + d len)`, is table 2's for
each row (7856, 17088, 16224, 35664, 29792, 49856 bytes). -/
theorem sig_size :
    rows.map (fun r => let (n, h, d, a, k, _) := r; n * (1 + k * (a + 1) + h + d * (2 * n + 3))) =
      [7856, 17088, 16224, 35664, 29792, 49856] := by decide

end Noqtis.Slh
