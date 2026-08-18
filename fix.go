package attack

// The subgroup-binding fix, generalised to every impacted group.
//
// assertInSubgroup(R): hint a preimage S = [c'^{-1} mod r] R, assert S on-curve,
// and enforce [c'] S == R with a SOUND constant multiplication, where c' is the
// per-group cofactor-clearing constant (the product of the reachable cofactor
// prime powers). For honest R = [s]P in E[r], S = [s c'^{-1}]P exists and
// [c']S = [s]P = R. For a torsion-shifted R = [s]P + T with ord(T) | c', R is not
// in [c']E(F_p) (that image has trivial c'-part), so no on-curve S satisfies
// [c']S = R and the forgery is rejected.
//
// gnark's ScalarMul is itself the hinted (attackable) gadget, so the fix cannot
// use it. There is also no public Double. We therefore build [c']S from the
// public complete addition AddUnified via binary double-and-add, doubling a point
// P by hinting a distinct copy P2, constraining P2 == P, and forming
// AddUnified(P, P2) -- sound because P2 is fully determined by P, and distinct as
// circuit variables so the doubling does not fold P.X - P.X to a constant.

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() { solver.RegisterHint(copyPointHint) }

// cofactorClearing returns the product of the given prime powers ell^e.
func cofactorClearing(factors map[int64]int) *big.Int {
	c := big.NewInt(1)
	for ell, e := range factors {
		c.Mul(c, new(big.Int).Exp(big.NewInt(ell), big.NewInt(int64(e)), nil))
	}
	return c
}

// copyPointHint returns its input point coordinates unchanged: it materialises a
// distinct circuit copy of a point so AddUnified(P, copy) can double soundly.
func copyPointHint(field *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
		base := hc.EmulatedModuli()[0]
		baseIn, baseOut := hc.InputsOutputs(base)
		for i := range baseOut {
			baseOut[i].Set(baseIn[i])
		}
		return nil
	})
}

// ---- sound constant multiplication for prime-field groups (sw_emulated) ----

func dblG1[B, S emulated.FieldParams](api frontend.API, cr *sw_emulated.Curve[B, S], P *sw_emulated.AffinePoint[B]) *sw_emulated.AffinePoint[B] {
	_, cp, _, err := emulated.NewVarGenericHint[B, S](api, 0, 2, 0, nil,
		[]*emulated.Element[B]{&P.X, &P.Y}, nil, copyPointHint)
	if err != nil {
		panic(err)
	}
	P2 := &sw_emulated.AffinePoint[B]{X: *cp[0], Y: *cp[1]}
	cr.AssertIsEqual(P, P2)
	return cr.AddUnified(P, P2)
}

// mulConstG1 returns [c]P for a positive constant c, via MSB-first double-and-add.
func mulConstG1[B, S emulated.FieldParams](api frontend.API, cr *sw_emulated.Curve[B, S], c *big.Int, P *sw_emulated.AffinePoint[B]) *sw_emulated.AffinePoint[B] {
	var acc *sw_emulated.AffinePoint[B]
	started := false
	for i := c.BitLen() - 1; i >= 0; i-- {
		if started {
			acc = dblG1(api, cr, acc)
		}
		if c.Bit(i) == 1 {
			if started {
				acc = cr.AddUnified(acc, P)
			} else {
				acc = P
				started = true
			}
		}
	}
	return acc
}

// assertInSubgroupG1 enforces R in E[r] by the hinted-preimage binding above.
func assertInSubgroupG1[B, S emulated.FieldParams](api frontend.API, cr *sw_emulated.Curve[B, S], R *sw_emulated.AffinePoint[B], c *big.Int, preimage solver.Hint) {
	_, pre, _, err := emulated.NewVarGenericHint[B, S](api, 0, 2, 0, nil,
		[]*emulated.Element[B]{&R.X, &R.Y}, nil, preimage)
	if err != nil {
		panic(err)
	}
	S1 := &sw_emulated.AffinePoint[B]{X: *pre[0], Y: *pre[1]}
	cr.AssertIsOnCurve(S1)
	cr.AssertIsEqual(mulConstG1(api, cr, c, S1), R)
}
