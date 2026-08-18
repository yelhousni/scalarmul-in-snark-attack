package attack

// Sanity check for the torsion generators in torsion.go. Run with:
//
//	go test -run TestTorsion -v

import (
	"math/big"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bn "github.com/consensys/gnark-crypto/ecc/bn254"
	bw "github.com/consensys/gnark-crypto/ecc/bw6-761"
)

func TestTorsion(t *testing.T) {
	check := func(name string, ell int64, onCurve, orderOK bool) {
		if !onCurve || !orderOK {
			t.Fatalf("%s ell=%d: onCurve=%v orderExactlyEll=%v", name, ell, onCurve, orderOK)
		}
		t.Logf("%-16s ell=%-6d OK", name, ell)
	}
	for _, ell := range []int64{3, 11, 10177} {
		T := blsG1Torsion(ell)
		var c bls.G1Affine
		c.ScalarMultiplication(&T, big.NewInt(ell))
		check("BLS12-381 G1", ell, T.IsOnCurve(), c.IsInfinity() && !T.IsInfinity())
	}
	for _, ell := range []int64{2, 127} {
		T := bwG1Torsion(ell)
		var c bw.G1Affine
		c.ScalarMultiplication(&T, big.NewInt(ell))
		check("BW6-761 G1", ell, T.IsOnCurve(), c.IsInfinity() && !T.IsInfinity())
	}
	for _, ell := range []int64{3, 13} {
		T := bwG2Torsion(ell)
		var c bw.G2Affine
		c.ScalarMultiplication(&T, big.NewInt(ell))
		check("BW6-761 G2", ell, T.IsOnCurve(), c.IsInfinity() && !T.IsInfinity())
	}
	for _, ell := range []int64{13, 23, 2713, 11953} {
		T := blsG2Torsion(ell)
		var c bls.G2Affine
		c.ScalarMultiplication(&T, big.NewInt(ell))
		check("BLS12-381 G2", ell, T.IsOnCurve(), c.IsInfinity() && !T.IsInfinity())
	}
	{
		ell := int64(10069)
		T := bnG2Torsion(ell)
		var c bn.G2Affine
		c.ScalarMultiplication(&T, big.NewInt(ell))
		check("BN254 G2", ell, T.IsOnCurve(), c.IsInfinity() && !T.IsInfinity())
	}
}
