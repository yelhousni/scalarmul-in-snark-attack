package attack

// BN254 G2 (cofactor small part 10069; BN254 G1 is prime-order and immune). G2
// lives over Fp2. The sw_bn254 G2 ScalarMul routes through the same GLV+fake-GLV
// hinted output.
//
// chosen-scalar reaches ell=10069 (< 2^(N/4+2)). any-scalar is NOT reachable
// here: 10069 far exceeds the eigen-route bound rho^4 ~ 100 (10069^{1/4} ~ 10),
// so no in-range decomposition vanishes the residual for a fixed scalar.

import (
	"math/big"
	"testing"

	bn "github.com/consensys/gnark-crypto/ecc/bn254"
	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

var bnLambda, _ = new(big.Int).SetString("4407920970296243842393367215006156084916469457145843978461", 10)

type bn254G2Circuit struct {
	Q sw_bn254.G2Affine
	S emulated.Element[emparams.BN254Fr]
	R sw_bn254.G2Affine
}

func (c *bn254G2Circuit) Define(api frontend.API) error {
	g2, err := sw_bn254.NewG2(api)
	if err != nil {
		return err
	}
	res := g2.ScalarMul(&c.Q, &c.S)
	g2.AssertIsEqual(res, &c.R)
	return nil
}

func solveBNG2(t *testing.T, Q bn.G2Affine, s *big.Int, out bn.G2Affine, vec [4]*big.Int) error {
	ccs := compileOnce(t, "bnG2", &bn254G2Circuit{})
	w := &bn254G2Circuit{Q: sw_bn254.NewG2Affine(Q), S: emulated.ValueOf[emparams.BN254Fr](s), R: sw_bn254.NewG2Affine(out)}
	wit, err := frontend.NewWitness(w, scalarField())
	if err != nil {
		t.Fatal(err)
	}
	coords := []*big.Int{out.X.A0.BigInt(new(big.Int)), out.X.A1.BigInt(new(big.Int)), out.Y.A0.BigInt(new(big.Int)), out.Y.A1.BigInt(new(big.Int))}
	hs := sw_bn254.GetHints() // [...,3:scalarMulG2Hint,4:rationalReconstructExtG2]
	return ccs.IsSolved(wit,
		solver.OverrideHint(solver.GetHintID(hs[3]), forgeOutputHint(coords)),
		solver.OverrideHint(solver.GetHintID(hs[4]), forgeDecompHint(vec)),
	)
}

func TestBN254G2(t *testing.T) {
	r := bnfr.Modulus()
	_, _, _, Q := bn.Generators()

	ell := int64(10069)
	s := chosenScalar(bnLambda, ell, r)
	T := bnG2Torsion(ell)
	var honest, forged bn.G2Affine
	honest.ScalarMultiplication(&Q, s)
	forged.Add(&honest, &T)
	if err := solveBNG2(t, Q, s, forged, chosenVec(ell)); err != nil {
		t.Fatalf("chosen-scalar ell=%d must be ACCEPTED (unpatched): %v", ell, err)
	}
	t.Logf("ATTACK chosen-scalar ell=%-6d accepted [s]Q+T as [s]Q", ell)
	t.Log("any-scalar: not reachable on BN254 G2 (10069 >> rho^4 ~ 100)")
}
