/-
  noqtis: proofs/lean/Ct.lean

  The branch-free bit tricks the C code uses on secret values, for every
  machine word: src/core/int.h (`nqctmask`, `nqctsel`, `nqcmov`),
  src/core/core.c (`nqcteq`), src/mldsa/poly.c (`nqmddec`'s wrap,
  `nqmdmkh`, `nqmdchk`), src/mlkem/ring.h (`nqmkps`), and the byte
  order of the load and store helpers of int.h. Words are `BitVec`s, so
  each statement is about the bits C computes, with unsigned wrap-around;
  signed `>>` is `BitVec.sshiftRight`. The value barrier `nqctbar` (an
  XOR with a volatile zero) is the identity on values and is left out.

  Proofs by `bv_decide` (a SAT solver whose certificate the kernel checks
  through `Lean.ofReduceBool`, the one axiom beyond the standard three
  that these theorems use) or by `decide` / `simp`.
-/
import Mathlib

set_option linter.style.longLine false
set_option linter.style.header false

namespace Noqtis.Ct

/-- `nqctmask(x) = 0 − ((x | −x) >> 31)`: all ones when `x ≠ 0`, zero when `x = 0`. -/
theorem ctmask (x : BitVec 32) :
    0#32 - ((x ||| (0#32 - x)) >>> 31) = if x = 0#32 then 0#32 else BitVec.allOnes 32 := by
  by_cases h : x = 0#32 <;> simp only [h, ↓reduceIte] <;> bv_decide

/-- `nqctsel(mask, a, b) = b ^ (mask & (a ^ b))`: `a` for an all-ones mask, `b` for zero. -/
theorem ctsel (a b : BitVec 32) :
    b ^^^ (BitVec.allOnes 32 &&& (a ^^^ b)) = a ∧ b ^^^ (0#32 &&& (a ^^^ b)) = b := by
  constructor <;> bv_decide

/-- `nqcmov`, per byte: `m = (uint8_t)(0 − cond)` for `cond ∈ {0, 1}`, and
`dst ^ (m & (dst ^ src))` is `src` when `cond = 1`, `dst` when `cond = 0`. -/
theorem cmov (d s : BitVec 8) (c : BitVec 32) (hc : c = 0#32 ∨ c = 1#32) :
    d ^^^ ((0#32 - c).truncate 8 &&& (d ^^^ s)) = if c = 1#32 then s else d := by
  rcases hc with rfl | rfl <;> bv_decide

/-- `nqcteq`'s last step, `1 & ((d − 1) >> 8)` on the OR of the byte differences `d`
(zero-extended to unsigned int): 1 exactly when every byte was equal. -/
theorem cteq (d : BitVec 8) :
    1#32 &&& ((d.zeroExtend 32 - 1#32) >>> 8) = if d = 0#8 then 1#32 else 0#32 := by
  by_cases h : d = 0#8 <;> simp only [h, ↓reduceIte] <;> bv_decide

/-- `nqmkps(a) = a + ((a >> 15) & q)` on int16: adds q exactly when `a < 0`. -/
theorem mkps (a : BitVec 16) :
    a + (a.sshiftRight 15 &&& 3329#16) = if a.slt 0#16 then a + 3329#16 else a := by
  by_cases h : a.slt 0#16 <;> simp only [h, ↓reduceIte] <;> bv_decide

/-- `nqmddec` (γ₂ = (q−1)/88): `a1 ^= ((43 − a1) >> 31) & a1` sets `a1` to 0 when it is
above 43 and leaves it otherwise, for the values it can take (0 to 44). -/
theorem dec_wrap (a1 : BitVec 32) (h : a1.ule 44#32) :
    a1 ^^^ ((43#32 - a1).sshiftRight 31 &&& a1) = if a1 = 44#32 then 0#32 else a1 := by
  by_cases e : a1 = 44#32 <;> simp only [e, ↓reduceIte] <;> bv_decide

/-- `nqmdmkh(a0, a1)` returns 1 exactly when `a0 > γ₂`, `a0 < −γ₂`, or `a0 = −γ₂` and
`a1 ≠ 0` (the reference implementation's make_hint), for both γ₂ and `|a0| < 2³⁰`; the
comparisons are the top bits of `γ₂ − a0` and `a0 + γ₂`, and `nqctmask` gives the rest. -/
theorem mkh (a0 a1 g2 : BitVec 32) (hg : g2 = 95232#32 ∨ g2 = 261888#32)
    (hlo : (-1073741824#32).sle a0) (hhi : a0.sle 1073741824#32) :
    let gt := (g2 - a0) >>> 31
    let lt := (a0 + g2) >>> 31
    let eq := 1#32 ^^^ ((0#32 - (((a0 + g2) ||| (0#32 - (a0 + g2))) >>> 31)) &&& 1#32)
    let nz := (0#32 - ((a1 ||| (0#32 - a1)) >>> 31)) &&& 1#32
    (gt ||| lt ||| (eq &&& nz)) =
      if g2.slt a0 ∨ a0.slt (0#32 - g2) ∨ (a0 = 0#32 - g2 ∧ a1 ≠ 0#32) then 1#32 else 0#32 := by
  rcases hg with rfl | rfl <;>
  · simp only
    split_ifs <;> bv_decide (config := { timeout := 600 })

/-- `nqmdchk(a, b)`, per coefficient: `t = a − ((a >> 31) & 2a)` is `|a|`, and the flag
`(b − 1 − t) >> 31` is 1 exactly when `|a| ≥ b`, for `|a| < 2³⁰` and `0 < b < 2³⁰`. -/
theorem mdchk (a b : BitVec 32) (ha1 : (-1073741824#32).slt a) (ha2 : a.slt 1073741824#32)
    (hb1 : 0#32 ≠ b) (hb2 : b.ult 1073741824#32) :
    let t := a - (a.sshiftRight 31 &&& (2#32 * a))
    ((b - 1#32 - t) >>> 31 = if b.sle t then 1#32 else 0#32) ∧
      (t = if a.slt 0#32 then 0#32 - a else a) := by
  simp only
  constructor <;> split_ifs <;> bv_decide (config := { timeout := 600 })

/-! ### Byte order: the helpers name the order, not the host's -/

/-- `nqld32l`: the little-endian value of four bytes, `p0 + 2⁸ p1 + 2¹⁶ p2 + 2²⁴ p3`. -/
def ld32l (p0 p1 p2 p3 : BitVec 8) : BitVec 32 :=
  p0.zeroExtend 32 ||| (p1.zeroExtend 32 <<< 8) ||| (p2.zeroExtend 32 <<< 16) ||| (p3.zeroExtend 32 <<< 24)

/-- `nqst32l`: byte `i` is `(uint8_t)(v >> 8i)`. -/
def byte (v : BitVec 32) (i : Nat) : BitVec 8 := (v >>> (8 * i)).truncate 8

/-- `nqld32b`: the big-endian load is the little-endian one of the reversed bytes. -/
def ld32b (p0 p1 p2 p3 : BitVec 8) : BitVec 32 := ld32l p3 p2 p1 p0

/-- Storing then loading gives the word back, and loading then storing gives the bytes back,
for both orders (`nqst32b` writes byte `3 − i` of the value to `p[i]`): the helpers are
inverse bijections between a word and its byte sequence, whatever the host's own byte order,
since they use shifts and ORs on values and never a pointer cast. -/
theorem ldst32l (v : BitVec 32) : ld32l (byte v 0) (byte v 1) (byte v 2) (byte v 3) = v := by
  unfold ld32l byte; bv_decide

theorem stld32l (p0 p1 p2 p3 : BitVec 8) :
    byte (ld32l p0 p1 p2 p3) 0 = p0 ∧ byte (ld32l p0 p1 p2 p3) 1 = p1 ∧
    byte (ld32l p0 p1 p2 p3) 2 = p2 ∧ byte (ld32l p0 p1 p2 p3) 3 = p3 := by
  unfold ld32l byte
  refine ⟨?_, ?_, ?_, ?_⟩ <;> bv_decide

theorem ldst32b (v : BitVec 32) : ld32b (byte v 3) (byte v 2) (byte v 1) (byte v 0) = v := by
  unfold ld32b ld32l byte; bv_decide

theorem stld32b (p0 p1 p2 p3 : BitVec 8) :
    byte (ld32b p0 p1 p2 p3) 3 = p0 ∧ byte (ld32b p0 p1 p2 p3) 2 = p1 ∧
    byte (ld32b p0 p1 p2 p3) 1 = p2 ∧ byte (ld32b p0 p1 p2 p3) 0 = p3 := by
  unfold ld32b ld32l byte
  refine ⟨?_, ?_, ?_, ?_⟩ <;> bv_decide

/-- The little-endian load is the number the byte sequence spells in base 256: the OR of the
shifted bytes equals their sum `p0 + 2⁸ p1 + 2¹⁶ p2 + 2²⁴ p3` (which is below 2³², so there
is no wrap-around). -/
theorem ld32l_val (p0 p1 p2 p3 : BitVec 8) :
    ld32l p0 p1 p2 p3 = p0.zeroExtend 32 + 256#32 * p1.zeroExtend 32 +
      65536#32 * p2.zeroExtend 32 + 16777216#32 * p3.zeroExtend 32 := by
  unfold ld32l
  bv_decide

end Noqtis.Ct
