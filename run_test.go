package attack

// Shared test scaffolding: compile each ScalarMul circuit once (the circuit is
// independent of the exploited prime ell -- only the witness and the overridden
// hints change), and expose the sub-scalar range width for the any-scalar
// range-fit check.

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

var ccsCache = map[string]constraint.ConstraintSystem{}

func compileOnce(t *testing.T, key string, c frontend.Circuit) constraint.ConstraintSystem {
	t.Helper()
	if ccsCache[key] == nil {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
		if err != nil {
			t.Fatalf("compile %s: %v", key, err)
		}
		ccsCache[key] = ccs
	}
	return ccsCache[key]
}

// subScalarBits is the gadget's sub-scalar range width, N/4+2 bits with
// N = r.BitLen(): the fake-GLV LLL bound u_i,v_i < 2^((N+3)/4+2).
func scalarField() *big.Int { return ecc.BN254.ScalarField() }

func subScalarBits(r *big.Int) int {
	return (r.BitLen()+3)/4 + 2
}

// chosenVec is the forged decomposition (1,0,0,ell) of the chosen-scalar family.
func chosenVec(ell int64) [4]*big.Int {
	return [4]*big.Int{big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(ell)}
}
