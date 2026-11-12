/-
  noqtis: proofs/lean/Gf.lean

  GF(2⁸) as HQC's Reed-Solomon code uses it (src/hqc/code.c): the field
  polynomial x⁸ + x⁴ + x³ + x² + 1 (0x11D), the constant-time multiply
  `gm`, the inverse `ginv` (an addition chain for a²⁵⁴) and the table of
  powers of α = x (`gexp`). Words are `BitVec 32`, as the C's uint32_t.
-/
import Mathlib

set_option linter.style.longLine false
set_option linter.style.header false

namespace Noqtis.Gf

/-- code.c `gm(a, b)`: the carry-less product computed with "holes" (each operand split
into four interleaved pieces, so the integer multiplies cannot carry into a bit that is
kept), then two folds of `x⁸ = x⁴ + x³ + x² + 1`. -/
def gm (a b : BitVec 32) : BitVec 32 :=
  let a0 := a &&& 0x11#32; let a1 := a &&& 0x22#32; let a2 := a &&& 0x44#32; let a3 := a &&& 0x88#32
  let b0 := b &&& 0x11#32; let b1 := b &&& 0x22#32; let b2 := b &&& 0x44#32; let b3 := b &&& 0x88#32
  let p := (((a0 * b0) ^^^ (a1 * b3) ^^^ (a2 * b2) ^^^ (a3 * b1)) &&& 0x1111#32) |||
    (((a0 * b1) ^^^ (a1 * b0) ^^^ (a2 * b3) ^^^ (a3 * b2)) &&& 0x2222#32) |||
    (((a0 * b2) ^^^ (a1 * b1) ^^^ (a2 * b0) ^^^ (a3 * b3)) &&& 0x4444#32) |||
    (((a0 * b3) ^^^ (a1 * b2) ^^^ (a2 * b1) ^^^ (a3 * b0)) &&& 0x8888#32)
  let f := fun p : BitVec 32 =>
    let hi := p >>> 8
    (p &&& 0xFF#32) ^^^ hi ^^^ (hi <<< 2) ^^^ (hi <<< 3) ^^^ (hi <<< 4)
  f (f p)

/-- The schoolbook product of two polynomials over GF(2): XOR of `a` shifted by each set
bit of `b`. -/
def clmul (a b : BitVec 32) : BitVec 32 :=
  (List.range 8).foldl (fun acc i => if b.getLsbD i then acc ^^^ (a <<< i) else acc) 0#32

/-- Reduction modulo 0x11D, from bit 14 down to bit 8. -/
def reduce (p : BitVec 32) : BitVec 32 :=
  [14, 13, 12, 11, 10, 9, 8].foldl
    (fun acc k => if acc.getLsbD k then acc ^^^ (0x11D#32 <<< (k - 8)) else acc) p

/-- `gm` is the product in GF(2)[x]/(x⁸ + x⁴ + x³ + x² + 1) for all bytes `a`, `b`. -/
theorem gm_spec (a b : BitVec 32) (ha : a.ult 256#32) (hb : b.ult 256#32) :
    gm a b = reduce (clmul a b) := by
  unfold gm reduce clmul
  simp only [List.range, List.range.loop, List.foldl]
  -- a few seconds alone; more than the default 10 s on a loaded machine
  bv_decide (config := { timeout := 600 })

/-- code.c `ginv(a)`: `a², a³, a⁴, a⁷, a¹¹, a¹⁵, a³⁰, a⁶⁰, a¹²⁰, a¹²⁷, a²⁵⁴`. -/
def ginv (a : BitVec 32) : BitVec 32 :=
  let a2 := gm a a; let a3 := gm a2 a; let a4 := gm a2 a2
  let a7 := gm a4 a3; let a11 := gm a4 a7; let a15 := gm a11 a4
  let t30 := gm a15 a15; let t60 := gm t30 t30; let t120 := gm t60 t60
  let t127 := gm t120 a7
  gm t127 t127

/-- The exponents of the chain: 15·2·2·2 = 120, 120 + 7 = 127, 2 · 127 = 254 = 2⁸ − 2. -/
theorem chain : 15 * 2 * 2 * 2 + 7 = 127 ∧ 2 * 127 = 2 ^ 8 - 2 := by norm_num

/-- `ginv a` is the inverse of every nonzero byte (checked for all 255 of them), and
`ginv 0 = 0`. -/
theorem ginv_spec :
    (List.range 256).all (fun a => a == 0 ||
      gm (ginv (BitVec.ofNat 32 a)) (BitVec.ofNat 32 a) == 1#32) = true ∧
    ginv 0#32 = 0#32 := by
  decide +kernel

/-- code.c `gexp`: `x <<= 1; x ^= 0x11D & (0 − (x >> 8))`, multiplication by α = x. -/
def step (x : ℕ) : ℕ := if (2 * x) / 256 = 1 then (2 * x) ^^^ 0x11D else 2 * x

/-- α has order 255: the 255 powers `gexp` tabulates are distinct nonzero bytes and the
256th wraps to 1, so α generates GF(2⁸)ˣ (0x11D is a primitive polynomial). -/
theorem alpha_order :
    let e := (List.range 255).map (fun i => step^[i] 1)
    e.Nodup ∧ (∀ v ∈ e, 0 < v ∧ v < 256) ∧ step^[255] 1 = 1 := by
  decide +kernel

end Noqtis.Gf
