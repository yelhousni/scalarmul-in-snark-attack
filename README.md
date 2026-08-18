# Cofactor-torsion attacks on hinted scalar multiplications in SNARK circuits

A minimal, self-contained proof of concept for the cofactor-torsion soundness
bug in `gnark`'s hinted-output scalar multiplication, which implements the GLV
/ fake-GLV methods of [eprint 2025/933](https://eprint.iacr.org/2025/933)
([Latincrypt
2025](https://link.springer.com/chapter/10.1007/978-3-032-06754-8_4)).

The PoC calls the **public** `ScalarMul` gadgets on an **unpatched** `gnark`
(pinned below to commit `48e4e4b67730`), forges a torsion-shifted output
through two solver-hint overrides, and shows each impacted group accepts the
forgery. It also shows the subgroup-binding fix rejecting the forgeries.

## The core observation

`ScalarMul` hints the output `Q = [s]P` and certifies it with a fraction
decomposition of `s`, but never binds `Q` to the prime-order subgroup
`𝔾 = E(𝔽ₚ)[r]`. A malicious prover can return `Q' = [s]P + T` for a rational
cofactor-torsion point `T ≠ 𝒪` and pass the check.

## Two forgery families

The certifying identity, read over the whole curve, is
`[u1]P + [u2]ψ(P) + [v1]Q + [v2]ψ(Q) = 0`. Substituting `Q' = Q + T` leaves the
residual `[v1]T + [v2]ψ(T)`; the forgery is accepted iff `(v1,v2)` vanish it.

- **chosen-scalar** — fix `(u1,u2,v1,v2) = (1,0,0,ℓ)`, so the residual `[ℓ]ψ(T)=𝒪`
  automatically, and the identity forces `s = -(ℓλ)⁻¹ mod r`. Reaches every
  cofactor prime `ℓ < 2^(N/4+2)`. Works for any rational `ℓ`-torsion `T`.
- **any-scalar** — keep the (arbitrary) honest scalar and scale the honest
  decomposition by `ℓ`, so `v1,v2` both vanish mod `ℓ`. Fits the sub-scalar range
  only for small `ℓ` (2, 3); larger `ℓ` needs the eigen-route sublattice
  reduction (not implemented here).

The exploit replaces two solver hints via `solver.OverrideHint` — the fraction
decomposition (`rationalReconstructExt` / `…G2`) and the hinted output
(`scalarMulHint` / `scalarMulG2Hint`) — without touching the circuit.

## Impacted groups and what is demonstrated

| Group | field | cofactor small part | chosen-scalar `ℓ` | any-scalar `ℓ` |
|-------|-------|---------------------|-------------------|----------------|
| BLS12-381 𝔾₁ | 𝔽ₚ  | `3·11²·10177²`        | `3, 11, 10177`      | `3` |
| BW6-761 𝔾₁   | 𝔽ₚ  | `2²·127`             | `2, 127`            | `2` |
| BW6-761 𝔾₂   | 𝔽ₚ  | `3·13`               | `3, 13`             | `3` |
| BLS12-381 𝔾₂ | 𝔽ₚ² | `13²·23²·2713·11953` | `13, 23, 2713, 11953` | `13, 23`¹ |
| BN254 𝔾₂     | 𝔽ₚ² | `10069`              | `10069`             | —²  |

Every listed case is a runnable test that shows the unpatched gadget **accepting**
`[s]P + T` as `[s]P`. Notes:

- ¹ BLS12-381 𝔾₂ any-scalar is reachable for `ℓ ∈ {13,23}` but only via the
  eigen-route reduction (`v1+μ·v2 ≡ 0 mod ℓ`); the simple `ℓ`-scaling used for the
  small-`ℓ` groups overflows the 66-bit sub-scalar range (`13·r^{1/4}` needs 68
  bits), so it is not exhibited in this minimal artifact.
- ² BN254 𝔾₂ any-scalar is not reachable at all: `10069 ≫ ρ⁴ ≈ 100`.
- **BN254 𝔾₁ is prime-order (cofactor 1) and therefore immune** — there is no
  cofactor torsion to shift by, so it has no test.

## The fix (BLS12-381 𝔾₁)

`assertInSubgroup(R)`: hint a preimage `S = [ℓ⁻¹ mod r]·R`, assert `S` on-curve,
and enforce `[ℓ]·S == R` in-circuit. A torsion-shifted `R` has no `[ℓ]`-preimage
of the honest output, so the equality is unsatisfiable and the forgery is
rejected; the honest witness still solves.

## Running

Requires Go ≥ 1.24. The vulnerable `gnark` is pinned in `go.mod` to the public
pre-fix commit, so no local checkout is needed:

```bash
go test ./... -v
```

Each `TestXxx` prints an `ATTACK …` line per accepted forgery; `TestBLS12381G1Fix`
prints the `FIX …` line. To reproduce against a local `gnark` tree (e.g. to
confirm the patched branch defeats the attack), add a replace directive:

```bash
go mod edit -replace github.com/consensys/gnark=/path/to/gnark
go test ./... -v
```

## Files

- `common.go` — chosen/any-scalar decompositions and the two generic hint
  overrides (shared by every group).
- `torsion.go` — full-group orders and rational `ℓ`-torsion point generation for
  every group (plain double-and-add, since gnark-crypto's `ScalarMultiplication`
  reduces mod `r`).
- `attack_<curve>_<group>_test.go` — one circuit + attack driver per group.
- `attack_bls12381_g1_test.go` — also contains the subgroup-binding fix.
- `torsion_test.go` — sanity check that every generated `T` is on-curve of order `ℓ`.
