/-
  noqtis: proofs/lean/Enc.lean

  ByteEncode_d / ByteDecode_d of FIPS 203 (algorithms 5 and 6) and the
  bit packing of FIPS 204 (SimpleBitPack, BitPack), as the C code does
  them (src/mlkem: `nqmkbe`, `nqmkbd`; src/mldsa/poly.c: `nqmdbpk`,
  `nqmdbun`): L values of d bits each, value i at bits d·i … d·i + d − 1,
  bit k of the stream in bit k mod 8 of byte ⌊k/8⌋. Both sides are stated
  on byte sequences (lists of numbers below 256), so nothing here depends
  on the host's byte order: the stream is the number
  `N = Σ aᵢ 2^{d i} = Σ bⱼ 256^j`, written in base 2^d and in base 256.
-/
import Mathlib

set_option linter.style.longLine false
set_option linter.style.header false

namespace Noqtis.Enc

open Nat

/-- Digit `i` of `n` in base `b`, for each `i < k`. -/
def digs (b k n : ℕ) : List ℕ := (List.range k).map (fun i => n / b ^ i % b)

/-- ByteEncode_d: the L values `a` (each below 2^d) as B bytes. -/
def encode (d B : ℕ) (a : List ℕ) : List ℕ := digs 256 B (ofDigits (2 ^ d) a)

/-- ByteDecode_d: B bytes as L values of d bits (FIPS 203 decodes `mod 2^d`, then ML-KEM
reduces mod q where it must; the decode itself is this). -/
def decode (d L : ℕ) (b : List ℕ) : List ℕ := digs (2 ^ d) L (ofDigits 256 b)

/-- Writing the first k digits back gives `n mod b^k`. -/
theorem ofDigits_digs (b k n : ℕ) : ofDigits b (digs b k n) = n % b ^ k := by
  induction k with
  | zero => simp [digs, Nat.mod_one]
  | succ k ih =>
    have e : digs b (k + 1) n = digs b k n ++ [n / b ^ k % b] := by
      simp [digs, List.range_succ]
    rw [e, ofDigits_append, ih, ofDigits_singleton]
    have hl : (digs b k n).length = k := by simp [digs]
    rw [hl, Nat.mod_pow_succ]

/-- The digits of a number written from digits below b are those digits. -/
theorem digs_ofDigits (b : ℕ) (hb : 1 < b) (a : List ℕ) (ha : ∀ x ∈ a, x < b) :
    digs b a.length (ofDigits b a) = a := by
  induction a with
  | nil => simp [digs]
  | cons x xs ih =>
    have hx : x < b := ha x (by simp)
    have hxs : ∀ y ∈ xs, y < b := fun y hy => ha y (by simp [hy])
    have hb0 : 0 < b := by omega
    rw [List.length_cons, ofDigits_cons]
    unfold digs at ih ⊢
    rw [List.range_succ_eq_map, List.map_cons, List.map_map]
    congr 1
    · simp [Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hx]
    · trans (List.range xs.length).map (fun i => ofDigits b xs / b ^ i % b)
      · apply List.map_congr_left
        intro i _
        simp only [Function.comp, Nat.succ_eq_add_one]
        rw [pow_succ, mul_comm (b ^ i) b, ← Nat.div_div_eq_div_mul,
          Nat.add_mul_div_left _ _ hb0, Nat.div_eq_of_lt hx, zero_add]
      · exact ih hxs

/-- ByteDecode_d undoes ByteEncode_d: for L values below 2^d and `d · L = 8 · B`. -/
theorem decode_encode (d L B : ℕ) (hd : 0 < d) (hLB : d * L = 8 * B) (a : List ℕ)
    (hl : a.length = L) (ha : ∀ x ∈ a, x < 2 ^ d) :
    decode d L (encode d B a) = a := by
  unfold decode encode
  have h2 : 1 < 2 ^ d := Nat.one_lt_two_pow (by omega)
  rw [ofDigits_digs 256 B _]
  have hlt : ofDigits (2 ^ d) a < 256 ^ B := by
    calc ofDigits (2 ^ d) a < (2 ^ d) ^ a.length := ofDigits_lt_base_pow_length h2 ha
      _ = 256 ^ B := by rw [hl, ← pow_mul, hLB, show (256 : ℕ) = 2 ^ 8 by norm_num, ← pow_mul]
  rw [Nat.mod_eq_of_lt hlt, ← hl]
  exact digs_ofDigits _ h2 a ha

/-- And ByteEncode_d undoes ByteDecode_d: for B bytes and `d · L = 8 · B`, so the two are
inverse bijections between L-tuples of d-bit values and B-byte strings. -/
theorem encode_decode (d L B : ℕ) (hLB : d * L = 8 * B) (b : List ℕ)
    (hl : b.length = B) (hb : ∀ x ∈ b, x < 256) :
    encode d B (decode d L b) = b := by
  unfold decode encode
  rw [ofDigits_digs (2 ^ d) L _]
  have hlt : ofDigits 256 b < (2 ^ d) ^ L := by
    calc ofDigits 256 b < 256 ^ b.length := ofDigits_lt_base_pow_length (by norm_num) hb
      _ = (2 ^ d) ^ L := by rw [hl, ← pow_mul, hLB, show (256 : ℕ) = 2 ^ 8 by norm_num, ← pow_mul]
  rw [Nat.mod_eq_of_lt hlt, ← hl]
  exact digs_ofDigits 256 (by norm_num) b hb

/-- The sizes ML-KEM and ML-DSA use: 256 values of d bits are 32 d bytes. -/
theorem sizes (d : ℕ) : d * 256 = 8 * (32 * d) := by ring

end Noqtis.Enc
