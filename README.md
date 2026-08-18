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
- **any-scalar** — keep the (arbitrary) honest scalar and adapt the
  decomposition (`eigen.go`). Three sub-routes, by cost:
  - **scaling** — multiply the honest decomposition by `ℓ` (`v1,v2` both vanish
    mod `ℓ`); penalty `ℓ`, so only tiny `ℓ` (2, 3).
  - **eigen route** — a short vector of the index-`ℓ` sublattice `v1+μ·v2 ≡ 0 mod ℓ`,
    where `μ` is the eigenvalue of `φ` on a rational `ℓ`-torsion eigenvector `T`
    (so `[v1]T+[v2]φ(T)=[v1+μv2]T=𝒪`); penalty ~`ℓ^{1/4}`, reaches `ℓ≡1 mod 3` into
    the hundreds (here 13, 127).
  - **both-zero route** — a short vector of the index-`ℓ²` sublattice
    `v1=v2=0 mod ℓ`, valid for *any* `ℓ`-torsion (no eigenvalue needed); penalty
    ~`ℓ^{1/2}` (here 11, 23).

  The eigen and both-zero routes reduce with the LLL vendored from gnark-crypto.

The exploit replaces two solver hints via `solver.OverrideHint` — the fraction
decomposition (`rationalReconstructExt` / `…G2`) and the hinted output
(`scalarMulHint` / `scalarMulG2Hint`) — without touching the circuit.

## Impacted groups and what is demonstrated

| Group | field | cofactor small part | chosen-scalar `ℓ` | any-scalar `ℓ` (route) |
|-------|-------|---------------------|-------------------|----------------|
| BLS12-381 𝔾₁ | 𝔽ₚ  | `3·11²·10177²`        | `3, 11, 10177`      | `3` (scaling), `11` (both-zero) |
| BW6-761 𝔾₁   | 𝔽ₚ  | `2²·127`             | `2, 127`            | `2` (both-zero), `127` (eigen) |
| BW6-761 𝔾₂   | 𝔽ₚ  | `3·13`               | `3, 13`             | `3` (scaling), `13` (eigen) |
| BLS12-381 𝔾₂ | 𝔽ₚ² | `13²·23²·2713·11953` | `13, 23, 2713, 11953` | `13` (eigen), `23` (both-zero) |
| BN254 𝔾₂     | 𝔽ₚ² | `10069`              | `10069`             | —¹  |

Every listed case is a runnable test that shows the unpatched gadget **accepting**
`[s]P + T` as `[s]P`. A prime is any-scalar reachable when *some* route (eigen for
`ℓ≡1 mod 3`, both-zero otherwise) yields a decomposition within the range; each
entry was confirmed to fit by LLL (e.g. `127` on BW6-761 𝔾₁ lands at 95 bits,
`23` on BLS12-381 𝔾₂ right at the 66-bit bound). The larger primes 10177 (𝔾₁) and
2713, 11953 (𝔾₂) overflow by either route, so they are chosen-scalar only. Notes:

- ¹ BN254 𝔾₂ any-scalar is not reachable at all: `10069 ≫` the eigen bound.
- **BN254 𝔾₁ is prime-order (cofactor 1) and therefore immune** — there is no
  cofactor torsion to shift by, so it has no test.

## The fix (all groups)

`assertInSubgroup(R)`: provide a preimage `S = [c'⁻¹ mod r]·R`, assert `S`
on-curve, and enforce `[c']·S == R`, where `c'` is the per-group
cofactor-clearing constant (the product of the reachable prime powers, e.g.
`3·11²·10177²` for BLS12-381 𝔾₁, `2²·127` for BW6-761 𝔾₁, `13²·23²·2713·11953`
for BLS12-381 𝔾₂). A torsion-shifted `R = [s]P + T` is not in `[c']·E(𝔽ₚ)` (whose
`c'`-part is trivial), so no on-curve `S` satisfies the equality and every forgery
is rejected; the honest witness still solves. Each `TestXxxFix` runs the honest
case plus every chosen-scalar forgery for its group.

`ScalarMul` is itself the hinted (attackable) gadget and there is no public
`Double`, so `[c']·S` is built from the public complete addition `AddUnified` by
binary double-and-add, doubling `P` via a distinct copy (a fresh hint for 𝔾₁ /
BW6-761 𝔾₂, or `Select(1, P, ·)` for the tower-field 𝔾₂) so `P.x − P.x` never
folds to a constant. On-curve uses `AssertIsOnCurve` (𝔾₁), a 𝔾₂-parameter
`sw_emulated` curve (BW6-761 𝔾₂, which lives over 𝔽ₚ), `AssertIsOnTwist`
(BLS12-381 𝔾₂), or a manual `y²=x³+b'` in 𝔽ₚ² (BN254 𝔾₂, which exposes none).

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
- `fix.go` — the subgroup-binding fix: cofactor-clearing constant, sound
  constant multiplication, and the 𝔾₁ `assertInSubgroup` (the 𝔾₂ variants live in
  each group's file).
- `eigen.go` — the eigen-route any-scalar construction: the endomorphism `φ`
  off-circuit, rational `ℓ`-torsion eigenvector + eigenvalue `μ`, and the
  short-sublattice decomposition. The LLL reducer is vendored verbatim from
  gnark-crypto (`algebra/lattice`) — the exact routine the gadget's own
  decomposition uses — since the package exports only the `RationalReconstruct*`
  wrappers, which can't express the extra congruence `v1+μ·v2 ≡ 0 mod ℓ`.
- `torsion.go` — full-group orders and rational `ℓ`-torsion point generation for
  every group (plain double-and-add, since gnark-crypto's `ScalarMultiplication`
  reduces mod `r`).
- `attack_<curve>_<group>_test.go` — one circuit + attack driver per group.
- `attack_bls12381_g1_test.go` — also contains the subgroup-binding fix.
- `torsion_test.go` — sanity check that every generated `T` is on-curve of order `ℓ`.
