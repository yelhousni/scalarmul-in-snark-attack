package attack

// Rational cofactor-torsion point generation for every impacted group.
//
// gnark-crypto's ScalarMultiplication reduces the scalar mod r (it assumes
// subgroup inputs and uses the GLV endomorphism), so it cannot multiply a
// full-curve point by a large scalar. We therefore provide a plain
// double-and-add (mul*Full) for the big steps and use gnark-crypto only for the
// small [ell] reductions.
//
// To obtain a point of order exactly ell (ell^v || N, the full group order):
//   U = [N / ell^v] W   lands in the ell-Sylow subgroup;
//   then repeatedly multiply by ell until the next product is O.
// This works whether the ell-Sylow is cyclic (Z/ell^v) or full (Z/ell x Z/ell).

import (
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bn "github.com/consensys/gnark-crypto/ecc/bn254"
	bnfp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bw "github.com/consensys/gnark-crypto/ecc/bw6-761"
	bwfp "github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	bwfr "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
)

// traceSearch returns N = p+1-t of a base-field elliptic group: t ≡ p+1 (mod r),
// |t| ≤ 2√p, chosen as the candidate that annihilates the probe point.
func traceSearch(p, r *big.Int, annihilate func(N *big.Int) bool) *big.Int {
	t0 := new(big.Int).Add(p, big.NewInt(1))
	t0.Mod(t0, r)
	bound := new(big.Int).Sqrt(p)
	bound.Lsh(bound, 1)
	km := new(big.Int).Div(bound, r)
	km.Add(km, big.NewInt(2))
	for k := int64(0); k <= km.Int64(); k++ {
		for _, sign := range []int64{-1, 1} {
			t := new(big.Int).Add(t0, new(big.Int).Mul(big.NewInt(sign*k), r))
			if t.CmpAbs(bound) > 0 {
				continue
			}
			N := new(big.Int).Sub(new(big.Int).Add(p, big.NewInt(1)), t)
			if new(big.Int).Mod(N, r).Sign() != 0 {
				continue
			}
			if annihilate(N) {
				return N
			}
		}
	}
	panic("traceSearch: no order found")
}

// ellCofree returns N / ell^v where ell^v || N (the ell-free part times ell^0),
// i.e. the multiplier that projects onto the ell-Sylow subgroup.
func ellSylowScalar(N *big.Int, ell int64) *big.Int {
	m := new(big.Int).Set(N)
	e := big.NewInt(ell)
	for new(big.Int).Mod(m, e).Sign() == 0 {
		m.Div(m, e)
	}
	return m
}

func polyBLSh2(x *big.Int) *big.Int {
	pow := func(n int64) *big.Int { return new(big.Int).Exp(x, big.NewInt(n), nil) }
	res := new(big.Int).Set(pow(8))
	res.Sub(res, new(big.Int).Mul(big.NewInt(4), pow(7)))
	res.Add(res, new(big.Int).Mul(big.NewInt(5), pow(6)))
	res.Sub(res, new(big.Int).Mul(big.NewInt(4), pow(4)))
	res.Add(res, new(big.Int).Mul(big.NewInt(6), pow(3)))
	res.Sub(res, new(big.Int).Mul(big.NewInt(4), pow(2)))
	res.Sub(res, new(big.Int).Mul(big.NewInt(4), x))
	res.Add(res, big.NewInt(13))
	res.Div(res, big.NewInt(9))
	return res
}

// ---------------- full-group double-and-add (no mod-r reduction) -------------

func mulBLSG1Full(W bls.G1Affine, s *big.Int) bls.G1Affine {
	var base, acc bls.G1Jac
	base.FromAffine(&W)
	started := false
	for i := s.BitLen() - 1; i >= 0; i-- {
		if started {
			acc.Double(&acc)
		}
		if s.Bit(i) == 1 {
			if started {
				acc.AddAssign(&base)
			} else {
				acc.Set(&base)
				started = true
			}
		}
	}
	var r bls.G1Affine
	r.FromJacobian(&acc)
	return r
}

func mulBWG1Full(W bw.G1Affine, s *big.Int) bw.G1Affine {
	var base, acc bw.G1Jac
	base.FromAffine(&W)
	started := false
	for i := s.BitLen() - 1; i >= 0; i-- {
		if started {
			acc.Double(&acc)
		}
		if s.Bit(i) == 1 {
			if started {
				acc.AddAssign(&base)
			} else {
				acc.Set(&base)
				started = true
			}
		}
	}
	var r bw.G1Affine
	r.FromJacobian(&acc)
	return r
}

func mulBWG2Full(W bw.G2Affine, s *big.Int) bw.G2Affine {
	var base, acc bw.G2Jac
	base.FromAffine(&W)
	started := false
	for i := s.BitLen() - 1; i >= 0; i-- {
		if started {
			acc.Double(&acc)
		}
		if s.Bit(i) == 1 {
			if started {
				acc.AddAssign(&base)
			} else {
				acc.Set(&base)
				started = true
			}
		}
	}
	var r bw.G2Affine
	r.FromJacobian(&acc)
	return r
}

func mulBLSG2Full(W bls.G2Affine, s *big.Int) bls.G2Affine {
	var base, acc bls.G2Jac
	base.FromAffine(&W)
	started := false
	for i := s.BitLen() - 1; i >= 0; i-- {
		if started {
			acc.Double(&acc)
		}
		if s.Bit(i) == 1 {
			if started {
				acc.AddAssign(&base)
			} else {
				acc.Set(&base)
				started = true
			}
		}
	}
	var r bls.G2Affine
	r.FromJacobian(&acc)
	return r
}

func mulBNG2Full(W bn.G2Affine, s *big.Int) bn.G2Affine {
	var base, acc bn.G2Jac
	base.FromAffine(&W)
	started := false
	for i := s.BitLen() - 1; i >= 0; i-- {
		if started {
			acc.Double(&acc)
		}
		if s.Bit(i) == 1 {
			if started {
				acc.AddAssign(&base)
			} else {
				acc.Set(&base)
				started = true
			}
		}
	}
	var r bn.G2Affine
	r.FromJacobian(&acc)
	return r
}

// ---------------- per-group order + random full-group point ------------------

func blsG1RandPoint(seed uint64) bls.G1Affine {
	var b blsfp.Element
	b.SetUint64(4)
	for i := seed * 1000003; ; i++ {
		var x, rhs blsfp.Element
		x.SetUint64(i)
		rhs.Exp(x, big.NewInt(3))
		rhs.Add(&rhs, &b)
		if rhs.Legendre() != 1 {
			continue
		}
		var y blsfp.Element
		y.Sqrt(&rhs)
		var W bls.G1Affine
		W.X, W.Y = x, y
		if W.IsOnCurve() {
			return W
		}
	}
}

func bwG1RandPoint(seed uint64) bw.G1Affine {
	var b bwfp.Element
	b.SetInt64(-1)
	for i := seed * 1000003; ; i++ {
		var x, rhs bwfp.Element
		x.SetUint64(i)
		rhs.Exp(x, big.NewInt(3))
		rhs.Add(&rhs, &b)
		if rhs.Legendre() != 1 {
			continue
		}
		var y bwfp.Element
		y.Sqrt(&rhs)
		var W bw.G1Affine
		W.X, W.Y = x, y
		if W.IsOnCurve() {
			return W
		}
	}
}

func bwG2RandPoint(seed uint64) bw.G2Affine {
	_, _, _, g2gen := bw.Generators()
	var b2, y2, x3 bwfp.Element
	y2.Exp(g2gen.Y, big.NewInt(2))
	x3.Exp(g2gen.X, big.NewInt(3))
	b2.Sub(&y2, &x3)
	for i := seed * 1000003; ; i++ {
		var x, rhs bwfp.Element
		x.SetUint64(i)
		rhs.Exp(x, big.NewInt(3))
		rhs.Add(&rhs, &b2)
		if rhs.Legendre() != 1 {
			continue
		}
		var y bwfp.Element
		y.Sqrt(&rhs)
		var W bw.G2Affine
		W.X, W.Y = x, y
		if W.IsOnCurve() {
			return W
		}
	}
}

func blsG2RandPoint(seed int64) bls.G2Affine {
	_, _, _, g2gen := bls.Generators()
	b2 := g2gen.Y
	{
		y2 := g2gen.Y
		y2.Exp(g2gen.Y, big.NewInt(2))
		x3 := g2gen.X
		x3.Exp(g2gen.X, big.NewInt(3))
		b2.Sub(&y2, &x3)
	}
	s := g2gen.X
	for i := int64(0); ; i++ {
		s.A0.SetInt64(seed*100003 + i)
		s.A1.SetInt64(seed*100003 + i + 1)
		rhs := g2gen.X
		rhs.Exp(s, big.NewInt(3))
		rhs.Add(&rhs, &b2)
		if rhs.Legendre() != 1 {
			continue
		}
		y := g2gen.X
		y.Sqrt(&rhs)
		var W bls.G2Affine
		W.X, W.Y = s, y
		if W.IsOnCurve() {
			return W
		}
	}
}

func bnG2RandPoint(seed int64) bn.G2Affine {
	_, _, _, g2gen := bn.Generators()
	b2 := g2gen.Y
	{
		y2 := g2gen.Y
		y2.Exp(g2gen.Y, big.NewInt(2))
		x3 := g2gen.X
		x3.Exp(g2gen.X, big.NewInt(3))
		b2.Sub(&y2, &x3)
	}
	s := g2gen.X
	for i := int64(0); ; i++ {
		s.A0.SetInt64(seed*100003 + i)
		s.A1.SetInt64(seed*100003 + i + 1)
		rhs := g2gen.X
		rhs.Exp(s, big.NewInt(3))
		rhs.Add(&rhs, &b2)
		if rhs.Legendre() != 1 {
			continue
		}
		y := g2gen.X
		y.Sqrt(&rhs)
		var W bn.G2Affine
		W.X, W.Y = s, y
		if W.IsOnCurve() {
			return W
		}
	}
}

// cached full-group orders
var orderCache = map[string]*big.Int{}

func blsG1Order() *big.Int {
	if orderCache["blsG1"] == nil {
		W := blsG1RandPoint(2)
		orderCache["blsG1"] = traceSearch(blsfp.Modulus(), blsfr.Modulus(), func(N *big.Int) bool {
			q := mulBLSG1Full(W, N)
			return q.IsInfinity()
		})
	}
	return orderCache["blsG1"]
}

func bwG1Order() *big.Int {
	if orderCache["bwG1"] == nil {
		W := bwG1RandPoint(2)
		orderCache["bwG1"] = traceSearch(bwfp.Modulus(), bwfr.Modulus(), func(N *big.Int) bool {
			q := mulBWG1Full(W, N)
			return q.IsInfinity()
		})
	}
	return orderCache["bwG1"]
}

func bwG2Order() *big.Int {
	if orderCache["bwG2"] == nil {
		W := bwG2RandPoint(2)
		orderCache["bwG2"] = traceSearch(bwfp.Modulus(), bwfr.Modulus(), func(N *big.Int) bool {
			q := mulBWG2Full(W, N)
			return q.IsInfinity()
		})
	}
	return orderCache["bwG2"]
}

func blsG2Order() *big.Int {
	if orderCache["blsG2"] == nil {
		x, _ := new(big.Int).SetString("-15132376222941642752", 10)
		orderCache["blsG2"] = new(big.Int).Mul(blsfr.Modulus(), polyBLSh2(x))
	}
	return orderCache["blsG2"]
}

func bnG2Order() *big.Int {
	if orderCache["bnG2"] == nil {
		r, p := bnfr.Modulus(), bnfp.Modulus()
		h2 := new(big.Int).Sub(new(big.Int).Lsh(p, 1), r) // 2p - r
		orderCache["bnG2"] = new(big.Int).Mul(r, h2)
	}
	return orderCache["bnG2"]
}

// ---------------- order-exactly-ell torsion points ---------------------------

func blsG1Torsion(ell int64) bls.G1Affine {
	m := ellSylowScalar(blsG1Order(), ell)
	e := big.NewInt(ell)
	for seed := uint64(2); ; seed++ {
		U := mulBLSG1Full(blsG1RandPoint(seed), m)
		if U.IsInfinity() {
			continue
		}
		for {
			var nxt bls.G1Affine
			nxt.ScalarMultiplication(&U, e)
			if nxt.IsInfinity() {
				return U
			}
			U = nxt
		}
	}
}

func bwG1Torsion(ell int64) bw.G1Affine {
	m := ellSylowScalar(bwG1Order(), ell)
	e := big.NewInt(ell)
	for seed := uint64(2); ; seed++ {
		U := mulBWG1Full(bwG1RandPoint(seed), m)
		if U.IsInfinity() {
			continue
		}
		for {
			var nxt bw.G1Affine
			nxt.ScalarMultiplication(&U, e)
			if nxt.IsInfinity() {
				return U
			}
			U = nxt
		}
	}
}

func bwG2Torsion(ell int64) bw.G2Affine {
	m := ellSylowScalar(bwG2Order(), ell)
	e := big.NewInt(ell)
	for seed := uint64(2); ; seed++ {
		U := mulBWG2Full(bwG2RandPoint(seed), m)
		if U.IsInfinity() {
			continue
		}
		for {
			var nxt bw.G2Affine
			nxt.ScalarMultiplication(&U, e)
			if nxt.IsInfinity() {
				return U
			}
			U = nxt
		}
	}
}

func blsG2Torsion(ell int64) bls.G2Affine {
	m := ellSylowScalar(blsG2Order(), ell)
	e := big.NewInt(ell)
	for seed := int64(3); ; seed += 2 {
		U := mulBLSG2Full(blsG2RandPoint(seed), m)
		if U.IsInfinity() {
			continue
		}
		for {
			var nxt bls.G2Affine
			nxt.ScalarMultiplication(&U, e)
			if nxt.IsInfinity() {
				return U
			}
			U = nxt
		}
	}
}

func bnG2Torsion(ell int64) bn.G2Affine {
	m := ellSylowScalar(bnG2Order(), ell)
	e := big.NewInt(ell)
	for seed := int64(3); ; seed += 2 {
		U := mulBNG2Full(bnG2RandPoint(seed), m)
		if U.IsInfinity() {
			continue
		}
		for {
			var nxt bn.G2Affine
			nxt.ScalarMultiplication(&U, e)
			if nxt.IsInfinity() {
				return U
			}
			U = nxt
		}
	}
}
