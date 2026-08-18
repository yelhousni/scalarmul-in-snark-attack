package attack

// BLS12-381 G2 (cofactor small part 13^2 * 23^2 * 2713 * 11953). G2 lives over
// Fp2, so its affine point has four coordinates (X.A0, X.A1, Y.A0, Y.A1). The
// sw_bls12381 G2 ScalarMul routes through the same GLV+fake-GLV hinted output,
// so the same two hint overrides forge a torsion-shifted output.
//
// chosen-scalar reaches every cofactor prime below 2^(N/4+2): 13, 23, 2713,
// 11953. any-scalar reaches ell=13 via the eigen route (13 = 1 mod 3, so phi has
// a rational eigenvalue) and ell=23 via the both-zero route (23 = 2 mod 3, no
// eigenvalue, so v1 = v2 = 0 mod 23; it lands right at the 66-bit range bound).
// The larger primes 2713, 11953 overflow the range by either route, so they are
// chosen-scalar only. See eigen.go.

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

// c' clears the reachable BLS12-381 G2 cofactor torsion: 13^2 * 23^2 * 2713 * 11953.
var cBLSG2 = cofactorClearing(map[int64]int{13: 2, 23: 2, 2713: 1, 11953: 1})

type bls12381G2Circuit struct {
	Q       sw_bls12381.G2Affine
	S       emulated.Element[emparams.BLS12381Fr]
	R       sw_bls12381.G2Affine
	withFix bool
	// fix witnesses: the hinted preimage Spre = [c'^{-1} mod r] R and a
	// constrained-to-one selector used to make sound in-place doublings.
	Spre sw_bls12381.G2Affine
	One  frontend.Variable
}

// mulConstBLSG2 returns [c]P via double-and-add. Doubling uses AddUnified on a
// distinct copy of the accumulator, produced by Select(one, acc, other) with a
// point other != acc so no coordinate folds to a constant.
func mulConstBLSG2(g2 *sw_bls12381.G2, one frontend.Variable, c *big.Int, P, other *sw_bls12381.G2Affine) *sw_bls12381.G2Affine {
	var acc *sw_bls12381.G2Affine
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

func (c *bls12381G2Circuit) Define(api frontend.API) error {
	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		return err
	}
	res := g2.ScalarMul(&c.Q, &c.S)
	if c.withFix {
		api.AssertIsEqual(c.One, 1)
		g2.AssertIsOnTwist(&c.Spre)
		g2.AssertIsEqual(mulConstBLSG2(g2, c.One, cBLSG2, &c.Spre, &c.Q), res)
	}
	g2.AssertIsEqual(res, &c.R)
	return nil
}

func solveBLSG2(t *testing.T, fix bool, Q bls.G2Affine, s *big.Int, out bls.G2Affine, vec *[4]*big.Int) error {
	key := "blsG2"
	if fix {
		key = "blsG2fix"
	}
	ccs := compileOnce(t, key, &bls12381G2Circuit{withFix: fix})
	// preimage S = [c'^{-1} mod r] out (subgroup point if out is honest)
	var Spre bls.G2Affine
	Spre.ScalarMultiplication(&out, new(big.Int).ModInverse(cBLSG2, blsfr.Modulus()))
	w := &bls12381G2Circuit{
		Q: sw_bls12381.NewG2Affine(Q), S: emulated.ValueOf[emparams.BLS12381Fr](s),
		R: sw_bls12381.NewG2Affine(out), withFix: fix,
		Spre: sw_bls12381.NewG2Affine(Spre), One: 1,
	}
	wit, err := frontend.NewWitness(w, scalarField())
	if err != nil {
		t.Fatal(err)
	}
	var opts []solver.Option
	if vec != nil {
		coords := []*big.Int{out.X.A0.BigInt(new(big.Int)), out.X.A1.BigInt(new(big.Int)), out.Y.A0.BigInt(new(big.Int)), out.Y.A1.BigInt(new(big.Int))}
		hs := sw_bls12381.GetHints() // [...,3:scalarMulG2Hint,4:rationalReconstructExtG2,...]
		opts = []solver.Option{
			solver.OverrideHint(solver.GetHintID(hs[3]), forgeOutputHint(coords)),
			solver.OverrideHint(solver.GetHintID(hs[4]), forgeDecompHint(*vec)),
		}
	}
	return ccs.IsSolved(wit, opts...)
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
		vec := chosenVec(ell)
		if err := solveBLSG2(t, false, Q, s, forged, &vec); err != nil {
			t.Fatalf("chosen-scalar ell=%d must be ACCEPTED (unpatched): %v", ell, err)
		}
		t.Logf("ATTACK chosen-scalar ell=%-6d accepted [s]Q+T as [s]Q", ell)
	}

	// any-scalar via the eigen route (ell=13): honest scalar, decomposition from
	// the index-13 sublattice v1+mu*v2 = 0, torsion-shifted by a phi-eigenvector.
	{
		ell := int64(13)
		s := anyScalar(r)
		T, mu := eigenBLSG2(ell)
		vec := eigenRouteDecomp(s, r, blsLambda, ell, mu)
		if maxAbsBits(vec) > subScalarBits(r) {
			t.Fatalf("eigen-route decomposition overflows the sub-scalar range")
		}
		var honest, forged bls.G2Affine
		honest.ScalarMultiplication(&Q, s)
		forged.Add(&honest, &T)
		if err := solveBLSG2(t, false, Q, s, forged, &vec); err != nil {
			t.Fatalf("any-scalar (eigen) ell=%d must be ACCEPTED (unpatched): %v", ell, err)
		}
		t.Logf("ATTACK any-scalar   ell=%-6d accepted [s]Q+T as [s]Q (eigen route, mu=%d)", ell, mu)
	}

	// any-scalar via the both-zero route (ell=23): 23 !≡ 1 mod 3 has no phi-eigen-
	// value, but the index-23^2 sublattice v1 = v2 = 0 mod 23 lands at exactly the
	// 66-bit range bound (|v| < 2^66 still passes the check).
	{
		ell := int64(23)
		s := anyScalar(r)
		vec := bothZeroDecomp(s, r, blsLambda, ell)
		if maxAbsBits(vec) > subScalarBits(r) {
			t.Fatalf("both-zero decomposition overflows the sub-scalar range")
		}
		T := blsG2Torsion(ell)
		var honest, forged bls.G2Affine
		honest.ScalarMultiplication(&Q, s)
		forged.Add(&honest, &T)
		if err := solveBLSG2(t, false, Q, s, forged, &vec); err != nil {
			t.Fatalf("any-scalar (both-zero) ell=%d must be ACCEPTED (unpatched): %v", ell, err)
		}
		t.Logf("ATTACK any-scalar   ell=%-6d accepted [s]Q+T as [s]Q (both-zero route)", ell)
	}
}

func TestBLS12381G2Fix(t *testing.T) {
	r := blsfr.Modulus()
	_, _, _, Q := bls.Generators()

	s := anyScalar(r)
	var honest bls.G2Affine
	honest.ScalarMultiplication(&Q, s)
	if err := solveBLSG2(t, true, Q, s, honest, nil); err != nil {
		t.Fatalf("fix must keep the honest scalar mul valid: %v", err)
	}

	for _, ell := range []int64{13, 23, 2713, 11953} {
		sc := chosenScalar(blsLambda, ell, r)
		T := blsG2Torsion(ell)
		var h, forged bls.G2Affine
		h.ScalarMultiplication(&Q, sc)
		forged.Add(&h, &T)
		vec := chosenVec(ell)
		if err := solveBLSG2(t, true, Q, sc, forged, &vec); err == nil {
			t.Fatalf("fix must REJECT the forged [s]Q+T (ell=%d)", ell)
		}
		t.Logf("FIX subgroup binding rejects chosen-scalar forgery ell=%-6d", ell)
	}

	// the eigen-route any-scalar forgery is rejected too
	{
		ell := int64(13)
		T, mu := eigenBLSG2(ell)
		vec := eigenRouteDecomp(s, r, blsLambda, ell, mu)
		var forged bls.G2Affine
		forged.Add(&honest, &T)
		if err := solveBLSG2(t, true, Q, s, forged, &vec); err == nil {
			t.Fatal("fix must REJECT the eigen-route forgery (ell=13)")
		}
		t.Log("FIX subgroup binding rejects eigen-route forgery ell=13")
	}
}
