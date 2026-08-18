package attack

// Off-circuit checks for the eigen-route machinery (fast, no SNARK compile):
// the eigenvector/eigenvalue construction, the LLL sublattice reduction fitting
// the sub-scalar range, and the vanishing of the certifying residual
// [v1]T + [v2]phi(T).

import (
	"math/big"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bw "github.com/consensys/gnark-crypto/ecc/bw6-761"
	bwfr "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
)

func TestEigenRouteOffCircuit(t *testing.T) {
	ell := int64(13)

	// BW6-761 G2
	{
		r := bwfr.Modulus()
		T, mu := eigenBWG2(ell)
		pT := psiBWG2(T)
		var m bw.G2Affine
		m.ScalarMultiplication(&T, big.NewInt(mu))
		if !m.Equal(&pT) {
			t.Fatal("BW6-761 G2: T is not a phi-eigenvector")
		}
		s := anyScalar(r)
		vec := eigenRouteDecomp(s, r, bwLambda, ell, mu)
		if b := maxAbsBits(vec); b >= subScalarBits(r) {
			t.Fatalf("BW6-761 G2: eigen decomp overflows range (%d >= %d)", b, subScalarBits(r))
		}
		// residual [v1]T + [v2]phi(T) == O  (reduce coeffs mod ell; T has order ell)
		v1 := new(big.Int).Mod(vec[2], big.NewInt(ell))
		v2 := new(big.Int).Mod(vec[3], big.NewInt(ell))
		var a, b, res bw.G2Affine
		a.ScalarMultiplication(&T, v1)
		b.ScalarMultiplication(&pT, v2)
		res.Add(&a, &b)
		if !res.IsInfinity() {
			t.Fatal("BW6-761 G2: residual [v1]T+[v2]phi(T) != O")
		}
		t.Logf("BW6-761 G2 eigen-route: mu=%d, max sub-scalar bits=%d (range %d)", mu, maxAbsBits(vec), subScalarBits(r))
	}

	// BLS12-381 G2
	{
		r := blsfr.Modulus()
		T, mu := eigenBLSG2(ell)
		pT := psiBLSG2(T)
		var m bls.G2Affine
		m.ScalarMultiplication(&T, big.NewInt(mu))
		if !m.Equal(&pT) {
			t.Fatal("BLS12-381 G2: T is not a phi-eigenvector")
		}
		s := anyScalar(r)
		vec := eigenRouteDecomp(s, r, blsLambda, ell, mu)
		if b := maxAbsBits(vec); b >= subScalarBits(r) {
			t.Fatalf("BLS12-381 G2: eigen decomp overflows range (%d >= %d)", b, subScalarBits(r))
		}
		v1 := new(big.Int).Mod(vec[2], big.NewInt(ell))
		v2 := new(big.Int).Mod(vec[3], big.NewInt(ell))
		var a, b, res bls.G2Affine
		a.ScalarMultiplication(&T, v1)
		b.ScalarMultiplication(&pT, v2)
		res.Add(&a, &b)
		if !res.IsInfinity() {
			t.Fatal("BLS12-381 G2: residual [v1]T+[v2]phi(T) != O")
		}
		t.Logf("BLS12-381 G2 eigen-route: mu=%d, max sub-scalar bits=%d (range %d)", mu, maxAbsBits(vec), subScalarBits(r))
	}
}
