/-
  noqtis: proofs/lean/Ntt.lean

  The algebra under ML-KEM's NTT (src/mlkem/kem.c `nqmkntt`, `nqmkint`,
  `nqmkdot`): over Z_q, q = 3329, X²⁵⁶ + 1 is the product of the 128
  quadratics X² − ζ^(2i+1), ζ = 17, so by the Chinese remainder theorem a
  polynomial mod X²⁵⁶ + 1 is the same as its 128 remainders mod those
  quadratics, which is what the NTT computes and multiplies pointwise
  (FIPS 203, section 4.3). The same for ML-DSA (src/mldsa/poly.c
  `nqmdntt`, `nqmdint`, q = 8380417, ζ = 1753): X²⁵⁶ + 1 is the product of
  the 256 linear factors X − ζ^(2i+1) (FIPS 204, section 7.5). Not proved
  here: that the butterfly networks compute those remainders, in their
  bit-reversed order.
-/
import Mathlib

set_option linter.style.longLine false
set_option linter.style.header false

namespace Noqtis.Ntt

open Polynomial

instance : Fact (Nat.Prime 3329) := ⟨by norm_num⟩

theorem pow17 (n : ℕ) : (17 : ZMod 3329) ^ n = ((17 ^ n % 3329 : ℕ) : ZMod 3329) := by
  rw [ZMod.natCast_mod]; push_cast; rfl

theorem z128 : (17 : ZMod 3329) ^ 128 = -1 := by rw [pow17]; norm_num; rfl
theorem z256 : (17 : ZMod 3329) ^ 256 = 1 := by rw [pow17]; norm_num

/-- The 128 odd powers `ζ^(2i+1)`. -/
noncomputable def rts : Multiset (ZMod 3329) :=
  (Finset.range 128).val.map (fun i => (17 : ZMod 3329) ^ (2 * i + 1))

theorem root (i : ℕ) : ((17 : ZMod 3329) ^ (2 * i + 1)) ^ 128 + 1 = 0 := by
  rw [← pow_mul, show (2 * i + 1) * 128 = 256 * i + 128 by ring, pow_add, pow_mul,
    z256, one_pow, one_mul, z128]
  ring

/-- No two of them are equal: `ζ^(2i+1) = ζ^(2j+1)` with `i, j < 128` would make
`ζ^(2(j−i)) = 1` with `0 < 2(j − i) < 256`, below ζ's order. -/
theorem rts_nodup : rts.Nodup := by
  unfold rts
  apply Multiset.Nodup.map_on _ (Finset.range 128).nodup
  intro i hi j hj h
  simp only [Finset.mem_val, Finset.mem_range] at hi hj
  by_contra hne
  -- ζ is a unit of order 256
  let u : (ZMod 3329)ˣ := ZMod.unitOfCoprime 17 (by norm_num)
  have hu : (u : ZMod 3329) = 17 := rfl
  have hord : orderOf u = 256 := by
    have h1 : ¬ u ^ 2 ^ 7 = 1 := by
      intro e
      have := congrArg (fun v : (ZMod 3329)ˣ => (v : ZMod 3329)) e
      simp only [Units.val_pow_eq_pow_val, hu, Units.val_one] at this
      rw [show (2 : ℕ) ^ 7 = 128 by norm_num, z128] at this
      exact absurd this (by decide)
    have h2 : u ^ 2 ^ (7 + 1) = 1 := by
      ext
      simp only [Units.val_pow_eq_pow_val, hu, Units.val_one]
      rw [show (2 : ℕ) ^ (7 + 1) = 256 by norm_num, z256]
    simpa using orderOf_eq_prime_pow h1 h2
  have hu' : u ^ (2 * i + 1) = u ^ (2 * j + 1) := by
    ext
    simp only [Units.val_pow_eq_pow_val, hu]
    exact h
  have := (pow_inj_mod (x := u)).mp hu'
  rw [hord] at this
  omega

/-- X¹²⁸ + 1 = ∏_{i<128} (X − ζ^(2i+1)) over Z_q. -/
theorem split128 :
    (X ^ 128 + 1 : (ZMod 3329)[X]) = ((Finset.range 128).val.map
      (fun i => X - C ((17 : ZMod 3329) ^ (2 * i + 1)))).prod := by
  set p : (ZMod 3329)[X] := X ^ 128 + 1 with hp
  have hmon : p.Monic := by
    simpa using monic_X_pow_add_C (1 : ZMod 3329) (n := 128) (by norm_num)
  have hdeg : p.natDegree = 128 := by
    rw [hp, natDegree_add_eq_left_of_natDegree_lt] <;> simp
  have hne : p ≠ 0 := hmon.ne_zero
  have hle : rts ≤ p.roots := by
    rw [Multiset.le_iff_subset rts_nodup]
    intro x hx
    unfold rts at hx
    simp only [Multiset.mem_map, Finset.mem_val, Finset.mem_range] at hx
    obtain ⟨i, -, rfl⟩ := hx
    rw [mem_roots hne, IsRoot, hp]
    simp [root i]
  have hcard : rts.card = 128 := by
    unfold rts; rw [Multiset.card_map, Finset.card_val, Finset.card_range]
  have hroots : p.roots = rts := by
    symm
    apply Multiset.eq_of_le_of_card_le hle
    rw [hcard, ← hdeg]
    exact card_roots' p
  have hsplit := prod_multiset_X_sub_C_of_monic_of_roots_card_eq hmon
    (by rw [hroots, hcard, hdeg])
  rw [← hsplit, hroots]
  unfold rts
  rw [Multiset.map_map]
  simp only [Function.comp_def]

/-- X²⁵⁶ + 1 = ∏_{i<128} (X² − ζ^(2i+1)) over Z_q: the moduli of ML-KEM's NTT. -/
theorem split256 :
    (X ^ 256 + 1 : (ZMod 3329)[X]) = ((Finset.range 128).val.map
      (fun i => X ^ 2 - C ((17 : ZMod 3329) ^ (2 * i + 1)))).prod := by
  have h := congrArg (fun f : (ZMod 3329)[X] => f.comp (X ^ 2)) split128
  simp only [add_comp, pow_comp, X_comp, one_comp] at h
  rw [← pow_mul] at h
  rw [h, multiset_prod_comp, Multiset.map_map]
  simp only [Function.comp_def, sub_comp, X_comp, C_comp]

/-! ### ML-DSA: the complete NTT -/

instance : Fact (Nat.Prime 8380417) := ⟨by norm_num⟩

theorem pow1753 (n : ℕ) : (1753 : ZMod 8380417) ^ n = ((1753 ^ n % 8380417 : ℕ) : ZMod 8380417) := by
  rw [ZMod.natCast_mod]; push_cast; rfl

theorem d256 : (1753 : ZMod 8380417) ^ 256 = -1 := by rw [pow1753]; norm_num; rfl

set_option exponentiation.threshold 600 in
theorem d512 : (1753 : ZMod 8380417) ^ 512 = 1 := by rw [pow1753]; norm_num

/-- The 256 odd powers `1753^(2i+1)`. -/
noncomputable def drts : Multiset (ZMod 8380417) :=
  (Finset.range 256).val.map (fun i => (1753 : ZMod 8380417) ^ (2 * i + 1))

theorem droot (i : ℕ) : ((1753 : ZMod 8380417) ^ (2 * i + 1)) ^ 256 + 1 = 0 := by
  rw [← pow_mul, show (2 * i + 1) * 256 = 512 * i + 256 by ring, pow_add, pow_mul,
    d512, one_pow, one_mul, d256]
  ring

theorem drts_nodup : drts.Nodup := by
  unfold drts
  apply Multiset.Nodup.map_on _ (Finset.range 256).nodup
  intro i hi j hj h
  simp only [Finset.mem_val, Finset.mem_range] at hi hj
  let u : (ZMod 8380417)ˣ := ZMod.unitOfCoprime 1753 (by norm_num)
  have hu : (u : ZMod 8380417) = 1753 := rfl
  have hord : orderOf u = 512 := by
    have h1 : ¬ u ^ 2 ^ 8 = 1 := by
      intro e
      have := congrArg (fun v : (ZMod 8380417)ˣ => (v : ZMod 8380417)) e
      simp only [Units.val_pow_eq_pow_val, hu, Units.val_one] at this
      rw [show (2 : ℕ) ^ 8 = 256 by norm_num, d256] at this
      exact absurd this (by decide)
    have h2 : u ^ 2 ^ (8 + 1) = 1 := by
      ext
      simp only [Units.val_pow_eq_pow_val, hu, Units.val_one]
      rw [show (2 : ℕ) ^ (8 + 1) = 512 by norm_num, d512]
    simpa using orderOf_eq_prime_pow h1 h2
  have hu' : u ^ (2 * i + 1) = u ^ (2 * j + 1) := by
    ext
    simp only [Units.val_pow_eq_pow_val, hu]
    exact h
  have := (pow_inj_mod (x := u)).mp hu'
  rw [hord] at this
  omega

/-- X²⁵⁶ + 1 = ∏_{i<256} (X − 1753^(2i+1)) over Z_q, q = 8380417: ML-DSA's NTT is complete. -/
theorem dsplit256 :
    (X ^ 256 + 1 : (ZMod 8380417)[X]) = ((Finset.range 256).val.map
      (fun i => X - C ((1753 : ZMod 8380417) ^ (2 * i + 1)))).prod := by
  set p : (ZMod 8380417)[X] := X ^ 256 + 1 with hp
  have hmon : p.Monic := by
    simpa using monic_X_pow_add_C (1 : ZMod 8380417) (n := 256) (by norm_num)
  have hdeg : p.natDegree = 256 := by
    rw [hp, natDegree_add_eq_left_of_natDegree_lt] <;> simp
  have hne : p ≠ 0 := hmon.ne_zero
  have hle : drts ≤ p.roots := by
    rw [Multiset.le_iff_subset drts_nodup]
    intro x hx
    unfold drts at hx
    simp only [Multiset.mem_map, Finset.mem_val, Finset.mem_range] at hx
    obtain ⟨i, -, rfl⟩ := hx
    rw [mem_roots hne, IsRoot, hp]
    simp [droot i]
  have hcard : drts.card = 256 := by
    unfold drts; rw [Multiset.card_map, Finset.card_val, Finset.card_range]
  have hroots : p.roots = drts := by
    symm
    apply Multiset.eq_of_le_of_card_le hle
    rw [hcard, ← hdeg]
    exact card_roots' p
  have hsplit := prod_multiset_X_sub_C_of_monic_of_roots_card_eq hmon
    (by rw [hroots, hcard, hdeg])
  rw [← hsplit, hroots]
  unfold drts
  rw [Multiset.map_map]
  simp only [Function.comp_def]

end Noqtis.Ntt
