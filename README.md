# Cofactor-torsion attacks on hinted scalar multiplications in SNARK circuits

A minimal, self-contained proof of concept for the cofactor-torsion soundness bug
in `gnark`'s hinted-output scalar multiplication, which implements the GLV /
fake-GLV methods of [eprint 2025/933](https://eprint.iacr.org/2025/933).

The PoC calls the **public** `sw_emulated.Curve.ScalarMul` gadget on an
**unpatched** `gnark` (pinned below to commit `48e4e4b67730`), forges a
torsion-shifted output through a solver-hint override, shows the gadget accepts
it, then shows the proposed subgroup-binding fix rejects the forgery while
keeping the honest witness valid.

## The bug

`ScalarMul` hints the output `Q = [s]P` and certifies it with a fraction
decomposition of `s`, but never binds `Q` to the prime-order subgroup
`𝔾 = E(𝔽ₚ)[r]`. A malicious prover can return `Q' = [s]P + T` for a rational
cofactor-torsion point `T ≠ 𝒪` and pass the check.

## The PoC (BLS12-381 𝔾₁)

- Curve `E/𝔽ₚ : y² = x³ + 4`, `#E = r·h`, with 3 | h. `T = (0, 2)` is the
  ψ-fixed order-3 torsion point.
- **Chosen-scalar forgery**, `ℓ = 3`: the forged decomposition fixes the
  output-side coefficients to `(x,y,z,t) = (1,0,0,3)`, so the residual
  `[3]ψ(T) = 𝒪` vanishes; the scalar relation then forces
  `s = (3λ)⁻¹ mod r`. The prover submits `Q' = [s]P + T`.
- Two solver-hint overrides realize the forgery without touching the circuit:
  - `scalarMulHint` → returns `[s]P + T` instead of `[s]P`;
  - `rationalReconstructExt` → returns the forged `(1,0,0,3)`.
- **The fix** (`assertInSubgroup`): hint a preimage `S = [ℓ⁻¹ mod r]·R`, assert
  `S` is on-curve, and enforce `[ℓ]·S == R` in-circuit. A torsion-shifted `R`
  has no `[ℓ]`-preimage of the honest output, so the equality fails.

## Tests

| test | asserts |
|------|---------|
| `TestHonestBaseline`   | honest `[s]P` solves the unfixed circuit |
| `TestForgeryAccepted`  | **attack**: unfixed circuit accepts `[s]P + T` as `[s]P` |
| `TestFixBlocksForgery` | fixed circuit rejects the forged `[s]P + T` (unsatisfied constraint) |
| `TestFixKeepsHonest`   | fixed circuit still accepts the honest `[s]P` |

```
$ go test -v ./...
--- PASS: TestHonestBaseline
ATTACK: ScalarMul accepted [s]P + T as [s]P  (soundness broken)
--- PASS: TestForgeryAccepted
FIX: subgroup binding rejected the forged [s]P + T
--- PASS: TestFixBlocksForgery
--- PASS: TestFixKeepsHonest
ok  	github.com/consensys/scalarmul-in-snark-attack
```

## Running

Requires Go ≥ 1.24. The vulnerable `gnark` is pinned in `go.mod` to the public
pre-fix commit, so no local checkout is needed:

```bash
go test -v ./...
```

To reproduce against a local `gnark` tree instead (e.g. to try the patched
branch and confirm the attack no longer solves), add a replace directive:

```bash
go mod edit -replace github.com/consensys/gnark=/path/to/gnark
go test -v ./...
```

## Files

- `attack_test.go` — the whole PoC: circuit, hint overrides (attack), fix, tests.
- `go.mod` — pins `gnark` to the unpatched commit `48e4e4b67730`.
