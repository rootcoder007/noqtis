/-
  noqtis: proofs/lean/Mldsa.lean

  The arithmetic src/mldsa relies on, q = 8380417, for the constants and
  ranges the C code uses (src/mldsa/md.h, src/mldsa/poly.c,
  src/mldsa/sign.c). As in Mlkem.lean, C's arithmetic `>>` of a negative
  value (GCC, Clang, MSVC) is floor division by a power of two, which is
  `Int./` by a positive literal here.
-/
import Mathlib

set_option linter.style.longLine false
set_option linter.style.header false

namespace Noqtis.Mldsa

/-! ### Montgomery reduction, `nqmdmr` (md.h) -/

/-- `(int32_t)(uint32_t)x`: the low 32 bits of `x`, as a signed value. -/
def lo32 (x : Int) : Int := if x % 4294967296 < 2147483648 then x % 4294967296 else x % 4294967296 - 4294967296

/-- `nqmdmr(a)`: `t = (int32_t)(uint32_t)(a * 58728449)`, then `(a − t q) >> 32`. -/
def mont (a : Int) : Int := (a - lo32 (a * 58728449) * 8380417) / 4294967296

/-- 58728449 is q⁻¹ mod 2³². -/
theorem qinv32 : (58728449 * 8380417 : Int) % 4294967296 = 1 := by norm_num

/-- `nqmdmr`, md.h: for `|a| < 2³¹ q` the shift is exact, `2³² · mont a ≡ a (mod q)`, and the
result lies in `(−q, q)`. -/
theorem mont_spec (a : Int) (h1 : -(2147483648 * 8380417) < a) (h2 : a < 2147483648 * 8380417) :
    (a - lo32 (a * 58728449) * 8380417) % 4294967296 = 0 ∧
    (4294967296 * mont a - a) % 8380417 = 0 ∧
    -8380417 < mont a ∧ mont a < 8380417 := by
  unfold mont lo32
  split_ifs <;> omega

/-! ### `nqmdrd` and `nqmdcq` (md.h) -/

/-- `nqmdrd(a)`: `t = (a + 2²²) >> 23`, `a − t q`. -/
def rd (a : Int) : Int := a - (a + 4194304) / 8388608 * 8380417

/-- For every `int32_t` up to `2³¹ − 2²² − 1` (so `a + 2²²` does not overflow) the result is
congruent to `a` and lies in `[−6283009, 6283008]`. -/
theorem rd_spec (a : Int) (h1 : -2147483648 ≤ a) (h2 : a ≤ 2147483647 - 4194304) :
    (rd a - a) % 8380417 = 0 ∧ -6283009 ≤ rd a ∧ rd a ≤ 6283008 := by
  unfold rd
  omega

/-- `nqmdcq(a) = a + ((a >> 31) & q)`: `+q` exactly when `a < 0`. -/
def cq (a : Int) : Int := if a < 0 then a + 8380417 else a

theorem cq_spec (a : Int) (h1 : -8380417 < a) (h2 : a < 8380417) :
    0 ≤ cq a ∧ cq a < 8380417 ∧ (cq a - a) % 8380417 = 0 := by
  unfold cq
  split_ifs <;> omega

/-! ### Power2Round (sign.c, FIPS 204 Algorithm 35) -/

/-- sign.c: `a1 = (a + 2¹² − 1) >> 13`, `a0 = a − a1 2¹³`. -/
def p2r1 (a : Int) : Int := (a + 4095) / 8192

/-- For `0 ≤ a < q`: `a = a1 2¹³ + a0` with `−2¹² < a0 ≤ 2¹²` (FIPS 204's `r mod± 2^d`),
and `a1 < 2¹⁰`, so t1 packs in 10 bits. -/
theorem p2r_spec (a : Int) (h0 : 0 ≤ a) (h1 : a < 8380417) :
    a = p2r1 a * 8192 + (a - p2r1 a * 8192) ∧
    -4096 < a - p2r1 a * 8192 ∧ a - p2r1 a * 8192 ≤ 4096 ∧
    0 ≤ p2r1 a ∧ p2r1 a < 1024 := by
  unfold p2r1
  omega

/-! ### Decompose (poly.c `nqmddec`; FIPS 204 Algorithm 36) -/

/-- FIPS 204's Decompose for `0 ≤ r < q` and `α = 2γ₂`: `r0 = r mod± α`; if `r − r0 = q − 1`
then `(0, r0 − 1)`, else `((r − r0)/α, r0)`. -/
def decompose (g2 r : Int) : Int × Int :=
  let r0' := r % (2 * g2)
  let r0 := if r0' > g2 then r0' - 2 * g2 else r0'
  if r - r0 = 8380416 then (0, r0 - 1) else ((r - r0) / (2 * g2), r0)

/-- `nqmddec` with γ₂ = (q − 1)/88 (ML-DSA-44): `a1 = (a + 127) >> 7`,
`a1 = (a1 · 11275 + 2²³) >> 24`, `a1 = 0` when `a1 > 43` (the xor with the mask
`((43 − a1) >> 31) & a1`; Ct.lean proves that bit form), `a0 = a − 2γ₂ a1`, then `−q` when
`a0 > (q − 1)/2`. -/
def dec88 (a : Int) : Int × Int :=
  let b := (a + 127) / 128
  let c := (b * 11275 + 8388608) / 16777216
  let a1 := if c > 43 then 0 else c
  let a0 := a - a1 * 2 * 95232
  (a1, if a0 > 4190208 then a0 - 8380417 else a0)

/-- The same with γ₂ = (q − 1)/32 (ML-DSA-65, -87): `a1 = (a1 · 1025 + 2²¹) >> 22`, `& 15`. -/
def dec32 (a : Int) : Int × Int :=
  let b := (a + 127) / 128
  let a1 := ((b * 1025 + 2097152) / 4194304) % 16
  let a0 := a - a1 * 2 * 261888
  (a1, if a0 > 4190208 then a0 - 8380417 else a0)

/-- The first two steps of `nqmddec` compute `⌊(a + γ₂ − 1)/(2γ₂)⌋` without a divide. -/
theorem q88 (a : Int) (h0 : 0 ≤ a) (h1 : a < 8380417) :
    ((a + 127) / 128 * 11275 + 8388608) / 16777216 = (a + 95231) / 190464 := by
  omega

theorem q32 (a : Int) (h0 : 0 ≤ a) (h1 : a < 8380417) :
    ((a + 127) / 128 * 1025 + 2097152) / 4194304 = (a + 261887) / 523776 := by
  omega

theorem dec88_spec (a : Int) (h0 : 0 ≤ a) (h1 : a < 8380417) :
    dec88 a = decompose 95232 a := by
  unfold dec88 decompose
  dsimp only
  rw [q88 a h0 h1]
  -- the top of the range, where a1 wraps to 0, is split off for omega
  rcases lt_or_ge a 8285185 with h | h
  · split_ifs <;> simp only [Prod.mk.injEq, true_and] <;> omega
  · have hm : a % (2 * 95232) = a - 43 * 190464 ∨ a = 8380416 := by omega
    split_ifs <;> simp only [Prod.mk.injEq, true_and] <;> omega

theorem dec32_spec (a : Int) (h0 : 0 ≤ a) (h1 : a < 8380417) :
    dec32 a = decompose 261888 a := by
  unfold dec32 decompose
  dsimp only
  rw [q32 a h0 h1]
  split_ifs <;> simp only [Prod.mk.injEq] <;> omega

/-! ### Hints (poly.c `nqmduse`; FIPS 204 Algorithms 39, 40 and Lemma 2) -/

/-- HighBits and LowBits. -/
def hi (g2 r : Int) : Int := (decompose g2 r).1
def lo (g2 r : Int) : Int := (decompose g2 r).2

/-- `nqmduse` / UseHint: with `m = (q − 1)/(2γ₂)` (44 or 16), `a1` unchanged without a hint,
else `a1 ± 1 mod m` by the sign of `a0`. -/
def use (g2 m : Int) (h : Bool) (r : Int) : Int :=
  if !h then hi g2 r
  else if lo g2 r > 0 then (hi g2 r + 1) % m else (hi g2 r - 1) % m

/-- FIPS 204's MakeHint: whether adding `z` changes the high bits. -/
def mkh (g2 z r : Int) : Bool := decide (hi g2 r ≠ hi g2 ((r + z) % 8380417))

/-- What Decompose returns, without `mod`: `r = r1 · 2γ₂ + r0` with `−γ₂ < r0 ≤ γ₂` and
`0 ≤ r1 < m`, or, at the top of the range, `r1 = 0` and `r0 = r − q ∈ [−γ₂, 0]`. -/
theorem dec_char (g2 m r : Int) (hg : g2 = 95232 ∧ m = 44 ∨ g2 = 261888 ∧ m = 16)
    (h0 : 0 ≤ r) (h1 : r < 8380417) :
    (r = hi g2 r * (2 * g2) + lo g2 r ∧ -g2 < lo g2 r ∧ lo g2 r ≤ g2 ∧
      0 ≤ hi g2 r ∧ hi g2 r < m) ∨
    (hi g2 r = 0 ∧ lo g2 r = r - 8380417 ∧ -g2 ≤ lo g2 r ∧ lo g2 r ≤ 0) := by
  unfold hi lo decompose
  rcases hg with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;>
  · dsimp only
    split_ifs <;> omega

/-- FIPS 204, Lemma 2 (as used by Verify): for `0 ≤ r < q` and `‖z‖∞ ≤ γ₂`,
`UseHint(MakeHint(z, r), r) = HighBits(r + z)`, for both γ₂ of ML-DSA (with `m` = 44, 16). -/
theorem use_mkh (g2 m r z : Int) (hg : g2 = 95232 ∧ m = 44 ∨ g2 = 261888 ∧ m = 16)
    (h0 : 0 ≤ r) (h1 : r < 8380417) (hz : -g2 ≤ z ∧ z ≤ g2) :
    use g2 m (mkh g2 z r) r = hi g2 ((r + z) % 8380417) := by
  have hr := dec_char g2 m r hg h0 h1
  have hs := dec_char g2 m ((r + z) % 8380417) hg (by omega) (by omega)
  have hw : (r + z) % 8380417 = r + z ∨ (r + z) % 8380417 = r + z + 8380417 ∨
      (r + z) % 8380417 = r + z - 8380417 := by
    rcases hg with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;> omega
  unfold use mkh
  generalize hi g2 r = a1 at *
  generalize lo g2 r = a0 at *
  generalize hi g2 ((r + z) % 8380417) = b1 at *
  generalize lo g2 ((r + z) % 8380417) = b0 at *
  generalize (r + z) % 8380417 = s at *
  rcases hg with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;>
  · simp only [ne_eq, decide_not, Bool.not_not, decide_eq_true_eq]
    split_ifs <;> omega

/-! ### The NTT's root of unity -/

/-- 1753 as a unit mod q. -/
def zeta : (ZMod 8380417)ˣ := ZMod.unitOfCoprime 1753 (by norm_num)

theorem pow1753 (n : ℕ) : (1753 : ZMod 8380417) ^ n = ((1753 ^ n % 8380417 : ℕ) : ZMod 8380417) := by
  rw [ZMod.natCast_mod]; push_cast; rfl

/-- `1753^256 = −1` and `1753^512 = 1` mod q. -/
theorem zeta_half : (1753 : ZMod 8380417) ^ 256 = -1 := by
  rw [pow1753]; norm_num; rfl

set_option exponentiation.threshold 600 in
theorem zeta_full : (1753 : ZMod 8380417) ^ 512 = 1 := by
  rw [pow1753]; norm_num

/-- 1753 is a primitive 512-th root of unity mod q (FIPS 204's ζ). -/
theorem zeta_order : orderOf zeta = 512 := by
  have h1 : ¬ zeta ^ 2 ^ 8 = 1 := by
    intro h
    have := congrArg (fun u : (ZMod 8380417)ˣ => (u : ZMod 8380417)) h
    simp only [Units.val_pow_eq_pow_val, Units.val_one] at this
    rw [show (zeta : ZMod 8380417) = 1753 from rfl, show (2 : ℕ) ^ 8 = 256 by norm_num,
      zeta_half] at this
    exact absurd this (by decide)
  have h2 : zeta ^ 2 ^ (8 + 1) = 1 := by
    ext
    simp only [Units.val_pow_eq_pow_val, Units.val_one]
    rw [show (zeta : ZMod 8380417) = 1753 from rfl, show (2 : ℕ) ^ (8 + 1) = 512 by norm_num,
      zeta_full]
  simpa using orderOf_eq_prime_pow h1 h2

end Noqtis.Mldsa
