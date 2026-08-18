package attack

// BLS12-381 G1 (cofactor small part 3 * 11^2 * 10177^2). Exhibits both forgery
// families against the public sw_emulated.Curve.ScalarMul gadget, and the
// subgroup-binding fix. G1 is the prime-field case, handled by sw_emulated.

import (
	"math/big"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

// GLV eigenvalue lambda (psi(P)=[lambda]P on E[r]); same value the gadget uses.
var blsLambda, _ = new(big.Int).SetString("228988810152649578064853576960394133503", 10)

func init() { solver.RegisterHint(preimageHintBLSG1) }

// ---- circuit: call the public gadget, optionally bind the output ----

type bls12381G1Circuit struct {
	P       sw_emulated.AffinePoint[emparams.BLS12381Fp]
	S       emulated.Element[emparams.BLS12381Fr]
	Q       sw_emulated.AffinePoint[emparams.BLS12381Fp]
	withFix bool
}

func (c *bls12381G1Circuit) Define(api frontend.API) error {
	cr, err := sw_emulated.New[emparams.BLS12381Fp, emparams.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return err
	}
	res := cr.ScalarMul(&c.P, &c.S)
	if c.withFix {
		assertInSubgroupBLSG1(api, cr, res)
	}
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

func blsG1Point(p bls.G1Affine) sw_emulated.AffinePoint[emparams.BLS12381Fp] {
	return sw_emulated.AffinePoint[emparams.BLS12381Fp]{
		X: emulated.ValueOf[emparams.BLS12381Fp](p.X),
		Y: emulated.ValueOf[emparams.BLS12381Fp](p.Y),
	}
}

// solveBLSG1 runs the gadget on the given witness with the two malicious hint
// overrides (empty vec => honest, no overrides) and returns whether it solves.
func solveBLSG1(t *testing.T, fix bool, P bls.G1Affine, s *big.Int, out bls.G1Affine, vec *[4]*big.Int) error {
	key := "blsG1"
	if fix {
		key = "blsG1fix"
	}
	ccs := compileOnce(t, key, &bls12381G1Circuit{withFix: fix})
	w := &bls12381G1Circuit{P: blsG1Point(P), S: emulated.ValueOf[emparams.BLS12381Fr](s), Q: blsG1Point(out), withFix: fix}
	wit, err := frontend.NewWitness(w, scalarField())
	if err != nil {
		t.Fatal(err)
	}
	var opts []solver.Option
	if vec != nil {
		coords := []*big.Int{out.X.BigInt(new(big.Int)), out.Y.BigInt(new(big.Int))}
		hs := sw_emulated.GetHints()
		opts = []solver.Option{
			solver.OverrideHint(solver.GetHintID(hs[1]), forgeOutputHint(coords)),
			solver.OverrideHint(solver.GetHintID(hs[3]), forgeDecompHint(*vec)),
		}
	}
	return ccs.IsSolved(wit, opts...)
}

func TestBLS12381G1(t *testing.T) {
	r := blsfr.Modulus()
	_, _, P, _ := bls.Generators()

	// chosen-scalar: reaches every cofactor prime below 2^(N/4+2)
	for _, ell := range []int64{3, 11, 10177} {
		s := chosenScalar(blsLambda, ell, r)
		T := blsG1Torsion(ell)
		var honest, forged bls.G1Affine
		honest.ScalarMultiplication(&P, s)
		forged.Add(&honest, &T)
		vec := chosenVec(ell)
		if err := solveBLSG1(t, false, P, s, forged, &vec); err != nil {
			t.Fatalf("chosen-scalar ell=%d must be ACCEPTED (unpatched): %v", ell, err)
		}
		t.Logf("ATTACK chosen-scalar ell=%-6d accepted [s]P+T as [s]P", ell)
	}

	// any-scalar (eigen/both-zero route, ell=3): honest scalar, decomposition
	// scaled by 3 so the residual [3]psi(T)=0. Works for any scalar.
	{
		ell := int64(3)
		s := anyScalar(r)
		vec := scaleDecomp(honestDecomp(s, r, blsLambda), ell)
		if maxAbsBits(vec) >= subScalarBits(r) {
			t.Fatalf("scaled decomposition overflows the sub-scalar range")
		}
		T := blsG1Torsion(ell)
		var honest, forged bls.G1Affine
		honest.ScalarMultiplication(&P, s)
		forged.Add(&honest, &T)
		if err := solveBLSG1(t, false, P, s, forged, &vec); err != nil {
			t.Fatalf("any-scalar ell=%d must be ACCEPTED (unpatched): %v", ell, err)
		}
		t.Logf("ATTACK any-scalar   ell=%-6d accepted [s]P+T as [s]P", ell)
	}
}

func TestBLS12381G1Fix(t *testing.T) {
	r := blsfr.Modulus()
	_, _, P, _ := bls.Generators()

	// honest witness still solves the fixed circuit
	s := anyScalar(r)
	var honest bls.G1Affine
	honest.ScalarMultiplication(&P, s)
	if err := solveBLSG1(t, true, P, s, honest, nil); err != nil {
		t.Fatalf("fix must keep the honest scalar mul valid: %v", err)
	}

	// the ell=3 forgery is rejected by the subgroup binding
	ell := int64(3)
	sc := chosenScalar(blsLambda, ell, r)
	T := blsG1Torsion(ell)
	var h, forged bls.G1Affine
	h.ScalarMultiplication(&P, sc)
	forged.Add(&h, &T)
	vec := chosenVec(ell)
	if err := solveBLSG1(t, true, P, sc, forged, &vec); err == nil {
		t.Fatal("fix must REJECT the forged [s]P+T")
	}
	t.Log("FIX subgroup binding rejects the forged [s]P+T and keeps honest valid")
}

// ---- the subgroup-binding fix (ell=3 clearing, demonstrated on G1) ----

func assertInSubgroupBLSG1(api frontend.API, cr *sw_emulated.Curve[emparams.BLS12381Fp, emparams.BLS12381Fr], R *sw_emulated.AffinePoint[emparams.BLS12381Fp]) {
	// hint S = [3^{-1} mod r] R (twice, as two equal-but-distinct copies so the
	// [3]S doubling can use the complete addition without folding S.X - S.X),
	// then enforce S on-curve and [3]S == R with sound arithmetic.
	_, pre, _, err := emulated.NewVarGenericHint[emparams.BLS12381Fp, emparams.BLS12381Fr](
		api, 0, 4, 0, nil,
		[]*emulated.Element[emparams.BLS12381Fp]{&R.X, &R.Y}, nil, preimageHintBLSG1)
	if err != nil {
		panic(err)
	}
	S1 := &sw_emulated.AffinePoint[emparams.BLS12381Fp]{X: *pre[0], Y: *pre[1]}
	S2 := &sw_emulated.AffinePoint[emparams.BLS12381Fp]{X: *pre[2], Y: *pre[3]}
	cr.AssertIsEqual(S1, S2)
	cr.AssertIsOnCurve(S1)
	twoS := cr.AddUnified(S1, S2)
	threeS := cr.AddUnified(twoS, S1)
	cr.AssertIsEqual(threeS, R)
}

func preimageHintBLSG1(field *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
		base := hc.EmulatedModuli()[0]
		baseInputs, baseOutputs := hc.InputsOutputs(base)
		var R bls.G1Affine
		R.X.SetBigInt(baseInputs[0])
		R.Y.SetBigInt(baseInputs[1])
		einv := new(big.Int).ModInverse(big.NewInt(3), blsfr.Modulus())
		var S bls.G1Affine
		S.ScalarMultiplication(&R, einv)
		S.X.BigInt(baseOutputs[0])
		S.Y.BigInt(baseOutputs[1])
		S.X.BigInt(baseOutputs[2])
		S.Y.BigInt(baseOutputs[3])
		return nil
	})
}
