/-
  noqtis: proofs/lean/Mlkem.lean

  The arithmetic src/mlkem relies on, q = 3329, stated for the constants
  and input ranges the C code uses (src/mlkem/ring.h, src/mlkem/kem.c).
  C's `>>` on a negative signed value is an arithmetic shift with GCC,
  Clang and MSVC (implementation-defined in C11), i.e. floor division by
  a power of two: here `Int./` by a positive literal, which is floor
  division (Int.ediv) as well.
-/
import Mathlib

set_option linter.style.longLine false
set_option linter.style.header false

namespace Noqtis.Mlkem

/-- q of FIPS 203. -/
def q : Int := 3329

/-! ### Montgomery reduction, `nqmkmr` (ring.h) -/

/-- `(int16_t)(uint16_t)x`: the low 16 bits of `x`, as a signed value. -/
def lo16 (x : Int) : Int := if x % 65536 < 32768 then x % 65536 else x % 65536 - 65536

/-- `nqmkmr(a)`: `t = (int16_t)(uint16_t)(a * 62209)`, then `(a - t q) >> 16`. -/
def mont (a : Int) : Int := (a - lo16 (a * 62209) * 3329) / 65536

/-- 62209 is q⁻¹ mod 2¹⁶. -/
theorem qinv16 : (62209 * 3329 : Int) % 65536 = 1 := by norm_num

/-- `nqmkmr`, ring.h: for `|a| < 2¹⁵ q` the shift is exact (`a − t q ≡ 0 mod 2¹⁶`), the
result is `a · 2⁻¹⁶ mod q`, i.e. `2¹⁶ · mont a ≡ a (mod q)`, and it lies in `(−q, q)`. -/
theorem mont_spec (a : Int) (h1 : -(32768 * 3329) < a) (h2 : a < 32768 * 3329) :
    (a - lo16 (a * 62209) * 3329) % 65536 = 0 ∧
    65536 * mont a = a - lo16 (a * 62209) * 3329 ∧
    (65536 * mont a - a) % 3329 = 0 ∧
    -3329 < mont a ∧ mont a < 3329 := by
  unfold mont lo16
  split_ifs <;> omega

/-! ### Barrett reduction, `nqmkbr` (ring.h) -/

/-- `nqmkbr(a)`: `v = ((1 << 26) + q/2) / q`, `t = (v a + 2²⁵) >> 26`, `a − t q`. -/
def barrett (a : Int) : Int := a - (20159 * a + 33554432) / 67108864 * 3329

theorem barrett_v : ((2 : Int) ^ 26 + 3329 / 2) / 3329 = 20159 := by norm_num

/-- `nqmkbr`, ring.h: for every `int16_t` input the result is congruent to it mod q and lies
in `[−(q−1)/2, (q−1)/2]`, and `v a + 2²⁵` fits in an `int32_t`. -/
theorem barrett_spec (a : Int) (h1 : -32768 ≤ a) (h2 : a ≤ 32767) :
    (barrett a - a) % 3329 = 0 ∧ -1664 ≤ barrett a ∧ barrett a ≤ 1664 ∧
    -2147483648 ≤ 20159 * a + 33554432 ∧ 20159 * a + 33554432 ≤ 2147483647 := by
  unfold barrett
  omega

/-! ### `nqmkps` (ring.h): `a + ((a >> 15) & q)` -/

/-- For a 16-bit `a`, `a >> 15` is `−1` when `a < 0` and `0` otherwise, so the mask adds q
exactly to negative values. -/
def pos (a : Int) : Int := if a < 0 then a + 3329 else a

theorem pos_spec (a : Int) (h1 : -3329 < a) (h2 : a < 3329) :
    0 ≤ pos a ∧ pos a < 3329 ∧ (pos a - a) % 3329 = 0 := by
  unfold pos
  split_ifs <;> omega

/-! ### Division by q without a divide, `nqmkdq` / `nqmkmq` (ring.h) -/

/-- `nqmkdq(n) = (n * 10321340) >> 35` is `⌊n / q⌋` for `0 ≤ n < 2²³`, so `nqmkmq` is
`n mod q`. -/
theorem divq (n : Int) (h0 : 0 ≤ n) (h1 : n < 8388608) :
    n * 10321340 / 34359738368 = n / 3329 := by
  omega

theorem modq (n : Int) (h0 : 0 ≤ n) (h1 : n < 8388608) :
    n - 3329 * (n * 10321340 / 34359738368) = n % 3329 := by
  omega

/-! ### Compress and Decompress (ring.h `nqmkcp`, `nqmkdc`; FIPS 203 (4.7), (4.8)) -/

/-- `nqmkcp` before the mask: `⌊(2^d x + (q−1)/2) / q⌋`; FIPS 203 rounds
`2^d x / q` to the nearest integer, halves up. With q odd no half occurs, and the two agree:
here for any integer `m` (in the code `m = 2^d x ≥ 0`). -/
theorem compress_round (m : Int) :
    (m + 1664) / 3329 = (2 * m + 3329) / (2 * 3329) := by
  omega

/-- Compress then Decompress for `d` bits, as the C code computes them, for `x` in `[0, q)`. -/
def comp (d : Nat) (x : Int) : Int := ((2 ^ d * x + 1664) / 3329) % 2 ^ d
def decomp (d : Nat) (y : Int) : Int := (y * 3329 + 2 ^ d / 2) / 2 ^ d

/-- FIPS 203's bound (section 4.2.1): `Decompress_d(Compress_d(x))` is within
`⌈q / 2^{d+1}⌋` of `x` modulo q (the distance mod q is the least of `|e|`, `|e − q|`), for
each `d` ML-KEM uses: 832, 104, 52, 2 and 1 for d = 1, 4, 5, 10 and 11. `y` is the compressed value before the mask; it never exceeds `2^d`, and
`y mod 2^d` is `y` except at `2^d`, where it wraps to 0. -/
theorem comp_err (N B : Int) (x : Int) (h0 : 0 ≤ x) (h1 : x < 3329)
    (hN : N = 2 ∧ B = 832 ∨ N = 16 ∧ B = 104 ∨ N = 32 ∧ B = 52 ∨ N = 1024 ∧ B = 2 ∨
      N = 2048 ∧ B = 1) :
    let y := (N * x + 1664) / 3329
    let c := if y = N then 0 else y
    let e := (c * 3329 + N / 2) / N - x
    c = y % N ∧ ((-B ≤ e ∧ e ≤ B) ∨ (-B ≤ e + 3329 ∧ e + 3329 ≤ B)) := by
  rcases hN with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;>
  · simp only
    split_ifs <;> omega

/-! ### The NTT's root of unity -/

/-- 17 as a unit mod q. -/
def zeta : (ZMod 3329)ˣ := ZMod.unitOfCoprime 17 (by norm_num)

theorem zeta_val : (zeta : ZMod 3329) = 17 := rfl

/-- `17^n mod q`, through ℕ (fast to evaluate). -/
theorem pow17 (n : ℕ) : (17 : ZMod 3329) ^ n = ((17 ^ n % 3329 : ℕ) : ZMod 3329) := by
  rw [ZMod.natCast_mod]; push_cast; rfl

/-- `17^128 = −1` mod q. -/
theorem zeta_half : (17 : ZMod 3329) ^ 128 = -1 := by
  rw [pow17]; norm_num; rfl

theorem zeta_full : (17 : ZMod 3329) ^ 256 = 1 := by
  rw [pow17]; norm_num

/-- 17 is a primitive 256-th root of unity mod q: its order is exactly 256. -/
theorem zeta_order : orderOf zeta = 256 := by
  have h1 : ¬ zeta ^ 2 ^ 7 = 1 := by
    intro h
    have := congrArg (fun u : (ZMod 3329)ˣ => (u : ZMod 3329)) h
    simp only [Units.val_pow_eq_pow_val, zeta_val, Units.val_one] at this
    rw [show (2 : ℕ) ^ 7 = 128 by norm_num, zeta_half] at this
    exact absurd this (by decide)
  have h2 : zeta ^ 2 ^ (7 + 1) = 1 := by
    ext
    simp only [Units.val_pow_eq_pow_val, zeta_val, Units.val_one]
    rw [show (2 : ℕ) ^ (7 + 1) = 256 by norm_num, zeta_full]
  simpa using orderOf_eq_prime_pow h1 h2

/-- Each `ζ^(2i+1)` is a root of `X¹²⁸ + 1`, so `X²⁵⁶ + 1 = ∏ (X² − ζ^(2i+1))` is the
factorisation ML-KEM's incomplete NTT works modulo. -/
theorem zeta_odd_root (i : ℕ) : ((17 : ZMod 3329) ^ (2 * i + 1)) ^ 128 + 1 = 0 := by
  rw [← pow_mul, show (2 * i + 1) * 128 = 256 * i + 128 by ring, pow_add, pow_mul,
    zeta_full, one_pow, one_mul, zeta_half]
  ring

/-- The 128 values `ζ^(2i+1)`, `i < 128`, are distinct (ζ has order 256). -/
theorem zeta_odd_inj : Set.InjOn (fun i : ℕ => zeta ^ (2 * i + 1)) (Set.Iio 128) := by
  intro i hi j hj h
  simp only [Set.mem_Iio] at hi hj
  have := (pow_inj_mod (x := zeta)).mp h
  rw [zeta_order] at this
  omega

/-- `nqmkint`'s final factor: f = 1441 = 2³² / 128 mod q, i.e. the Montgomery square of
128⁻¹, so the inverse NTT's `mont(f · x)` multiplies by 128⁻¹ · 2¹⁶. -/
theorem invntt_factor : (1441 * 128 : Int) % 3329 = (2 ^ 32 : Int) % 3329 := by norm_num

end Noqtis.Mlkem
