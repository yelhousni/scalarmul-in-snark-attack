package attack

// BW6-761 G1 (cofactor small part 2^2 * 127). Prime-field group handled by
// sw_emulated. Exhibits chosen-scalar (ell in {2,127}) and any-scalar (ell=2,
// both-zero route) forgeries against the public ScalarMul gadget.

import (
	"math/big"
	"testing"

	bw "github.com/consensys/gnark-crypto/ecc/bw6-761"
	bwfr "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

var bwLambda, _ = new(big.Int).SetString("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945", 10)

func init() { solver.RegisterHint(preimageHintBWG1) }

// c' clears the reachable BW6-761 G1 cofactor torsion: 2^2 * 127.
var cBWG1 = cofactorClearing(map[int64]int{2: 2, 127: 1})

type bw6761G1Circuit struct {
	P       sw_emulated.AffinePoint[emparams.BW6761Fp]
	S       emulated.Element[emparams.BW6761Fr]
	Q       sw_emulated.AffinePoint[emparams.BW6761Fp]
	withFix bool
}

func (c *bw6761G1Circuit) Define(api frontend.API) error {
	cr, err := sw_emulated.New[emparams.BW6761Fp, emparams.BW6761Fr](api, sw_emulated.GetBW6761Params())
	if err != nil {
		return err
	}
	res := cr.ScalarMul(&c.P, &c.S)
	if c.withFix {
		assertInSubgroupG1(api, cr, res, cBWG1, preimageHintBWG1)
	}
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

func preimageHintBWG1(field *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
		base := hc.EmulatedModuli()[0]
		baseIn, baseOut := hc.InputsOutputs(base)
		var R bw.G1Affine
		R.X.SetBigInt(baseIn[0])
		R.Y.SetBigInt(baseIn[1])
		cinv := new(big.Int).ModInverse(cBWG1, bwfr.Modulus())
		var S bw.G1Affine
		S.ScalarMultiplication(&R, cinv)
		S.X.BigInt(baseOut[0])
		S.Y.BigInt(baseOut[1])
		return nil
	})
}

func bwG1Point(p bw.G1Affine) sw_emulated.AffinePoint[emparams.BW6761Fp] {
	return sw_emulated.AffinePoint[emparams.BW6761Fp]{
		X: emulated.ValueOf[emparams.BW6761Fp](p.X),
		Y: emulated.ValueOf[emparams.BW6761Fp](p.Y),
	}
}

func solveBWG1(t *testing.T, fix bool, P bw.G1Affine, s *big.Int, out bw.G1Affine, vec *[4]*big.Int) error {
	key := "bwG1"
	if fix {
		key = "bwG1fix"
	}
	ccs := compileOnce(t, key, &bw6761G1Circuit{withFix: fix})
	w := &bw6761G1Circuit{P: bwG1Point(P), S: emulated.ValueOf[emparams.BW6761Fr](s), Q: bwG1Point(out), withFix: fix}
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

func TestBW6761G1(t *testing.T) {
	r := bwfr.Modulus()
	_, _, P, _ := bw.Generators()

	for _, ell := range []int64{2, 127} {
		s := chosenScalar(bwLambda, ell, r)
		T := bwG1Torsion(ell)
		var honest, forged bw.G1Affine
		honest.ScalarMultiplication(&P, s)
		forged.Add(&honest, &T)
		vec := chosenVec(ell)
		if err := solveBWG1(t, false, P, s, forged, &vec); err != nil {
			t.Fatalf("chosen-scalar ell=%d must be ACCEPTED (unpatched): %v", ell, err)
		}
		t.Logf("ATTACK chosen-scalar ell=%-6d accepted [s]P+T as [s]P", ell)
	}

	{
		ell := int64(2)
		s := anyScalar(r)
		vec := scaleDecomp(honestDecomp(s, r, bwLambda), ell)
		if maxAbsBits(vec) >= subScalarBits(r) {
			t.Fatalf("scaled decomposition overflows the sub-scalar range")
		}
		T := bwG1Torsion(ell)
		var honest, forged bw.G1Affine
		honest.ScalarMultiplication(&P, s)
		forged.Add(&honest, &T)
		if err := solveBWG1(t, false, P, s, forged, &vec); err != nil {
			t.Fatalf("any-scalar ell=%d must be ACCEPTED (unpatched): %v", ell, err)
		}
		t.Logf("ATTACK any-scalar   ell=%-6d accepted [s]P+T as [s]P", ell)
	}
}

func TestBW6761G1Fix(t *testing.T) {
	r := bwfr.Modulus()
	_, _, P, _ := bw.Generators()

	s := anyScalar(r)
	var honest bw.G1Affine
	honest.ScalarMultiplication(&P, s)
	if err := solveBWG1(t, true, P, s, honest, nil); err != nil {
		t.Fatalf("fix must keep the honest scalar mul valid: %v", err)
	}

	for _, ell := range []int64{2, 127} {
		sc := chosenScalar(bwLambda, ell, r)
		T := bwG1Torsion(ell)
		var h, forged bw.G1Affine
		h.ScalarMultiplication(&P, sc)
		forged.Add(&h, &T)
		vec := chosenVec(ell)
		if err := solveBWG1(t, true, P, sc, forged, &vec); err == nil {
			t.Fatalf("fix must REJECT the forged [s]P+T (ell=%d)", ell)
		}
		t.Logf("FIX subgroup binding rejects chosen-scalar forgery ell=%-6d", ell)
	}
}
