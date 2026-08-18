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

// c' clears the reachable BN254 G2 cofactor torsion: 10069.
var cBNG2 = cofactorClearing(map[int64]int{10069: 1})

// BN254 G2 twist coefficient b' = Gy^2 - Gx^3 in Fp2 (Fp[u]/(u^2+1)).
var (
	bnG2B0, _ = new(big.Int).SetString("19485874751759354771024239261021720505790618469301721065564631296452457478373", 10)
	bnG2B1, _ = new(big.Int).SetString("266929791119991161246907387137283842545076965332900288569378510910307636690", 10)
)

type bn254G2Circuit struct {
	Q       sw_bn254.G2Affine
	S       emulated.Element[emparams.BN254Fr]
	R       sw_bn254.G2Affine
	withFix bool
	Spre    sw_bn254.G2Affine
	One     frontend.Variable
}

func (c *bn254G2Circuit) Define(api frontend.API) error {
	g2, err := sw_bn254.NewG2(api)
	if err != nil {
		return err
	}
	res := g2.ScalarMul(&c.Q, &c.S)
	if c.withFix {
		api.AssertIsEqual(c.One, 1)
		assertOnCurveBNG2(api, &c.Spre)
		g2.AssertIsEqual(mulConstBNG2(g2, c.One, cBNG2, &c.Spre, &c.Q), res)
	}
	g2.AssertIsEqual(res, &c.R)
	return nil
}

func mulConstBNG2(g2 *sw_bn254.G2, one frontend.Variable, c *big.Int, P, other *sw_bn254.G2Affine) *sw_bn254.G2Affine {
	var acc *sw_bn254.G2Affine
	started := false
	for i := c.BitLen() - 1; i >= 0; i-- {
		if started {
			acc = g2.AddUnified(acc, g2.Select(one, acc, other))
		}
		if c.Bit(i) == 1 {
			if started {
				acc = g2.AddUnified(acc, P)
			} else {
				acc = P
				started = true
			}
		}
	}
	return acc
}

// assertOnCurveBNG2 enforces y^2 = x^3 + b' in Fp2 (u^2 = -1), since sw_bn254 G2
// exposes no public on-curve check. Coordinates are read directly (the tower
// struct's fields are exported even though its type is not).
func assertOnCurveBNG2(api frontend.API, P *sw_bn254.G2Affine) {
	f, err := emulated.NewField[emparams.BN254Fp](api)
	if err != nil {
		panic(err)
	}
	x0, x1 := &P.P.X.A0, &P.P.X.A1
	y0, y1 := &P.P.Y.A0, &P.P.Y.A1
	x20 := f.Sub(f.Mul(x0, x0), f.Mul(x1, x1))
	x0x1 := f.Mul(x0, x1)
	x21 := f.Add(x0x1, x0x1)
	x30 := f.Sub(f.Mul(x20, x0), f.Mul(x21, x1))
	x31 := f.Add(f.Mul(x20, x1), f.Mul(x21, x0))
	y20 := f.Sub(f.Mul(y0, y0), f.Mul(y1, y1))
	y0y1 := f.Mul(y0, y1)
	y21 := f.Add(y0y1, y0y1)
	f.AssertIsEqual(y20, f.Add(x30, f.NewElement(bnG2B0)))
	f.AssertIsEqual(y21, f.Add(x31, f.NewElement(bnG2B1)))
}

func solveBNG2(t *testing.T, fix bool, Q bn.G2Affine, s *big.Int, out bn.G2Affine, vec *[4]*big.Int) error {
	key := "bnG2"
	if fix {
		key = "bnG2fix"
	}
	ccs := compileOnce(t, key, &bn254G2Circuit{withFix: fix})
	var Spre bn.G2Affine
	Spre.ScalarMultiplication(&out, new(big.Int).ModInverse(cBNG2, bnfr.Modulus()))
	w := &bn254G2Circuit{
		Q: sw_bn254.NewG2Affine(Q), S: emulated.ValueOf[emparams.BN254Fr](s),
		R: sw_bn254.NewG2Affine(out), withFix: fix,
		Spre: sw_bn254.NewG2Affine(Spre), One: 1,
	}
	wit, err := frontend.NewWitness(w, scalarField())
	if err != nil {
		t.Fatal(err)
	}
	var opts []solver.Option
	if vec != nil {
		coords := []*big.Int{out.X.A0.BigInt(new(big.Int)), out.X.A1.BigInt(new(big.Int)), out.Y.A0.BigInt(new(big.Int)), out.Y.A1.BigInt(new(big.Int))}
		hs := sw_bn254.GetHints() // [...,3:scalarMulG2Hint,4:rationalReconstructExtG2]
		opts = []solver.Option{
			solver.OverrideHint(solver.GetHintID(hs[3]), forgeOutputHint(coords)),
			solver.OverrideHint(solver.GetHintID(hs[4]), forgeDecompHint(*vec)),
		}
	}
	return ccs.IsSolved(wit, opts...)
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
	vec := chosenVec(ell)
	if err := solveBNG2(t, false, Q, s, forged, &vec); err != nil {
		t.Fatalf("chosen-scalar ell=%d must be ACCEPTED (unpatched): %v", ell, err)
	}
	t.Logf("ATTACK chosen-scalar ell=%-6d accepted [s]Q+T as [s]Q", ell)
	t.Log("any-scalar: not reachable on BN254 G2 (10069 >> rho^4 ~ 100)")
}

func TestBN254G2Fix(t *testing.T) {
	r := bnfr.Modulus()
	_, _, _, Q := bn.Generators()

	s := anyScalar(r)
	var honest bn.G2Affine
	honest.ScalarMultiplication(&Q, s)
	if err := solveBNG2(t, true, Q, s, honest, nil); err != nil {
		t.Fatalf("fix must keep the honest scalar mul valid: %v", err)
	}

	ell := int64(10069)
	sc := chosenScalar(bnLambda, ell, r)
	T := bnG2Torsion(ell)
	var h, forged bn.G2Affine
	h.ScalarMultiplication(&Q, sc)
	forged.Add(&h, &T)
	vec := chosenVec(ell)
	if err := solveBNG2(t, true, Q, sc, forged, &vec); err == nil {
		t.Fatalf("fix must REJECT the forged [s]Q+T (ell=%d)", ell)
	}
	t.Logf("FIX subgroup binding rejects chosen-scalar forgery ell=%-6d", ell)
}
