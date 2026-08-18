package attack

// BW6-761 G2 (cofactor small part 3 * 13). BW6-761's G2 lives over the base
// field Fp (a sextic twist), so its affine point has two coordinates. Exhibits
// chosen-scalar (ell in {3,13}) and any-scalar (ell=3) forgeries against the
// public sw_bw6761 G2 ScalarMul gadget, which routes through the same
// GLV+fake-GLV hinted output.

import (
	"math/big"
	"testing"

	bw "github.com/consensys/gnark-crypto/ecc/bw6-761"
	bwfp "github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	bwfr "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

func init() { solver.RegisterHint(preimageHintBWG2) }

// c' clears the reachable BW6-761 G2 cofactor torsion: 3 * 13.
var cBWG2 = cofactorClearing(map[int64]int{3: 1, 13: 1})

// bw6G2Params gives BW6-761's G2 (a sextic twist over Fp) as sw_emulated curve
// parameters, so we can reuse the prime-field on-curve/addition machinery for the
// fix. Only A and B (and a base point) matter here: the endomorphism is unused.
func bw6G2Params() sw_emulated.CurveParams {
	_, _, _, g := bw.Generators()
	var b, y2, x3 bwfp.Element
	y2.Square(&g.Y)
	x3.Square(&g.X).Mul(&x3, &g.X)
	b.Sub(&y2, &x3)
	return sw_emulated.CurveParams{
		A:  big.NewInt(0),
		B:  b.BigInt(new(big.Int)),
		Gx: g.X.BigInt(new(big.Int)),
		Gy: g.Y.BigInt(new(big.Int)),
	}
}

type bw6761G2Circuit struct {
	Q       sw_bw6761.G2Affine
	S       emulated.Element[emparams.BW6761Fr]
	R       sw_bw6761.G2Affine
	withFix bool
}

func (c *bw6761G2Circuit) Define(api frontend.API) error {
	g2, err := sw_bw6761.NewG2(api)
	if err != nil {
		return err
	}
	res := g2.ScalarMul(&c.Q, &c.S)
	if c.withFix {
		cr, err := sw_emulated.New[emparams.BW6761Fp, emparams.BW6761Fr](api, bw6G2Params())
		if err != nil {
			return err
		}
		assertInSubgroupG1(api, cr, &res.P, cBWG2, preimageHintBWG2)
	}
	g2.AssertIsEqual(res, &c.R)
	return nil
}

func preimageHintBWG2(field *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
		base := hc.EmulatedModuli()[0]
		baseIn, baseOut := hc.InputsOutputs(base)
		var R bw.G2Affine
		R.X.SetBigInt(baseIn[0])
		R.Y.SetBigInt(baseIn[1])
		cinv := new(big.Int).ModInverse(cBWG2, bwfr.Modulus())
		var S bw.G2Affine
		S.ScalarMultiplication(&R, cinv)
		S.X.BigInt(baseOut[0])
		S.Y.BigInt(baseOut[1])
		return nil
	})
}

func solveBWG2(t *testing.T, fix bool, Q bw.G2Affine, s *big.Int, out bw.G2Affine, vec *[4]*big.Int) error {
	key := "bwG2"
	if fix {
		key = "bwG2fix"
	}
	ccs := compileOnce(t, key, &bw6761G2Circuit{withFix: fix})
	w := &bw6761G2Circuit{Q: sw_bw6761.NewG2Affine(Q), S: emulated.ValueOf[emparams.BW6761Fr](s), R: sw_bw6761.NewG2Affine(out), withFix: fix}
	wit, err := frontend.NewWitness(w, scalarField())
	if err != nil {
		t.Fatal(err)
	}
	var opts []solver.Option
	if vec != nil {
		coords := []*big.Int{out.X.BigInt(new(big.Int)), out.Y.BigInt(new(big.Int))}
		hs := sw_bw6761.GetHints() // [finalExp, pairingCheck, scalarMulG2Hint, rationalReconstructExtG2]
		opts = []solver.Option{
			solver.OverrideHint(solver.GetHintID(hs[2]), forgeOutputHint(coords)),
			solver.OverrideHint(solver.GetHintID(hs[3]), forgeDecompHint(*vec)),
		}
	}
	return ccs.IsSolved(wit, opts...)
}

func TestBW6761G2(t *testing.T) {
	r := bwfr.Modulus()
	_, _, _, Q := bw.Generators()

	for _, ell := range []int64{3, 13} {
		s := chosenScalar(bwLambda, ell, r)
		T := bwG2Torsion(ell)
		var honest, forged bw.G2Affine
		honest.ScalarMultiplication(&Q, s)
		forged.Add(&honest, &T)
		vec := chosenVec(ell)
		if err := solveBWG2(t, false, Q, s, forged, &vec); err != nil {
			t.Fatalf("chosen-scalar ell=%d must be ACCEPTED (unpatched): %v", ell, err)
		}
		t.Logf("ATTACK chosen-scalar ell=%-6d accepted [s]Q+T as [s]Q", ell)
	}

	{
		ell := int64(3)
		s := anyScalar(r)
		vec := scaleDecomp(honestDecomp(s, r, bwLambda), ell)
		if maxAbsBits(vec) >= subScalarBits(r) {
			t.Fatalf("scaled decomposition overflows the sub-scalar range")
		}
		T := bwG2Torsion(ell)
		var honest, forged bw.G2Affine
		honest.ScalarMultiplication(&Q, s)
		forged.Add(&honest, &T)
		if err := solveBWG2(t, false, Q, s, forged, &vec); err != nil {
			t.Fatalf("any-scalar ell=%d must be ACCEPTED (unpatched): %v", ell, err)
		}
		t.Logf("ATTACK any-scalar   ell=%-6d accepted [s]Q+T as [s]Q (scaling)", ell)
	}

	// any-scalar via the eigen route (ell=13): the 13-torsion is 1-dimensional so
	// any 13-torsion point is a phi-eigenvector; the decomposition comes from the
	// index-13 sublattice v1+mu*v2 = 0.
	{
		ell := int64(13)
		s := anyScalar(r)
		T, mu := eigenBWG2(ell)
		vec := eigenRouteDecomp(s, r, bwLambda, ell, mu)
		if maxAbsBits(vec) >= subScalarBits(r) {
			t.Fatalf("eigen-route decomposition overflows the sub-scalar range")
		}
		var honest, forged bw.G2Affine
		honest.ScalarMultiplication(&Q, s)
		forged.Add(&honest, &T)
		if err := solveBWG2(t, false, Q, s, forged, &vec); err != nil {
			t.Fatalf("any-scalar (eigen) ell=%d must be ACCEPTED (unpatched): %v", ell, err)
		}
		t.Logf("ATTACK any-scalar   ell=%-6d accepted [s]Q+T as [s]Q (eigen route, mu=%d)", ell, mu)
	}
}

func TestBW6761G2Fix(t *testing.T) {
	r := bwfr.Modulus()
	_, _, _, Q := bw.Generators()

	s := anyScalar(r)
	var honest bw.G2Affine
	honest.ScalarMultiplication(&Q, s)
	if err := solveBWG2(t, true, Q, s, honest, nil); err != nil {
		t.Fatalf("fix must keep the honest scalar mul valid: %v", err)
	}

	for _, ell := range []int64{3, 13} {
		sc := chosenScalar(bwLambda, ell, r)
		T := bwG2Torsion(ell)
		var h, forged bw.G2Affine
		h.ScalarMultiplication(&Q, sc)
		forged.Add(&h, &T)
		vec := chosenVec(ell)
		if err := solveBWG2(t, true, Q, sc, forged, &vec); err == nil {
			t.Fatalf("fix must REJECT the forged [s]Q+T (ell=%d)", ell)
		}
		t.Logf("FIX subgroup binding rejects chosen-scalar forgery ell=%-6d", ell)
	}

	// the eigen-route any-scalar forgery is rejected too
	{
		ell := int64(13)
		T, mu := eigenBWG2(ell)
		vec := eigenRouteDecomp(s, r, bwLambda, ell, mu)
		var forged bw.G2Affine
		forged.Add(&honest, &T)
		if err := solveBWG2(t, true, Q, s, forged, &vec); err == nil {
			t.Fatal("fix must REJECT the eigen-route forgery (ell=13)")
		}
		t.Log("FIX subgroup binding rejects eigen-route forgery ell=13")
	}
}
