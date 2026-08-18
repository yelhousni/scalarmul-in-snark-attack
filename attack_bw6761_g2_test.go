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
	bwfr "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

type bw6761G2Circuit struct {
	Q sw_bw6761.G2Affine
	S emulated.Element[emparams.BW6761Fr]
	R sw_bw6761.G2Affine
}

func (c *bw6761G2Circuit) Define(api frontend.API) error {
	g2, err := sw_bw6761.NewG2(api)
	if err != nil {
		return err
	}
	res := g2.ScalarMul(&c.Q, &c.S)
	g2.AssertIsEqual(res, &c.R)
	return nil
}

func solveBWG2(t *testing.T, Q bw.G2Affine, s *big.Int, out bw.G2Affine, vec [4]*big.Int) error {
	ccs := compileOnce(t, "bwG2", &bw6761G2Circuit{})
	w := &bw6761G2Circuit{Q: sw_bw6761.NewG2Affine(Q), S: emulated.ValueOf[emparams.BW6761Fr](s), R: sw_bw6761.NewG2Affine(out)}
	wit, err := frontend.NewWitness(w, scalarField())
	if err != nil {
		t.Fatal(err)
	}
	coords := []*big.Int{out.X.BigInt(new(big.Int)), out.Y.BigInt(new(big.Int))}
	hs := sw_bw6761.GetHints() // [finalExp, pairingCheck, scalarMulG2Hint, rationalReconstructExtG2]
	return ccs.IsSolved(wit,
		solver.OverrideHint(solver.GetHintID(hs[2]), forgeOutputHint(coords)),
		solver.OverrideHint(solver.GetHintID(hs[3]), forgeDecompHint(vec)),
	)
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
		if err := solveBWG2(t, Q, s, forged, chosenVec(ell)); err != nil {
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
		if err := solveBWG2(t, Q, s, forged, vec); err != nil {
			t.Fatalf("any-scalar ell=%d must be ACCEPTED (unpatched): %v", ell, err)
		}
		t.Logf("ATTACK any-scalar   ell=%-6d accepted [s]Q+T as [s]Q", ell)
	}
}
