package attack

// Eigen-route any-scalar forgery for the G2 groups whose smallest reachable
// cofactor prime is too large for the simple ell-scaling (ell=13, since the
// gadget endomorphism phi is a cube root of unity so eigenvalues exist iff
// ell = 1 mod 3).
//
// Keeping the honest scalar s, the residual on a torsion-shifted output is
// [v1]T + [v2]phi(T). If T is a phi-eigenvector, phi(T) = [mu]T, so the residual
// is [v1 + mu*v2]T and vanishes iff v1 + mu*v2 = 0 (mod ell). We therefore search
// the index-ell sublattice
//
//	L' = { (u1,u2,v1,v2) : u1+lambda*u2+s*(v1+lambda*v2) = 0 (mod r)  AND
//	                       v1 + mu*v2 = 0 (mod ell) }
//
// for a short vector via LLL: its length is ~ ell^{1/4} times the honest one,
// which fits the sub-scalar range.
//
// gnark's G2 endomorphism is phi:(x,y)->(omega*x, y), omega = thirdRootOneG2 a
// cube root of unity; so phi(T) is computed off-circuit by scaling the
// x-coordinate by omega (the constant is unexported in gnark-crypto, hardcoded
// here from its source as thirdRootOneG1 squared).

import (
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	bw "github.com/consensys/gnark-crypto/ecc/bw6-761"
	bwfp "github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
)

// ---- endomorphism phi:(x,y) -> (omega*x, y) ----

var (
	blsOmegaG2 blsfp.Element // thirdRootOneG2 = thirdRootOneG1^2 (BLS12-381)
	bwOmegaG1  bwfp.Element  // thirdRootOneG1 (BW6-761 G1 endomorphism)
	bwOmegaG2  bwfp.Element  // thirdRootOneG2 = thirdRootOneG1^2 (BW6-761 G2)
)

func init() {
	var t1 blsfp.Element
	t1.SetString("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")
	blsOmegaG2.Square(&t1)
	var t2 bwfp.Element
	t2.SetString("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292650")
	bwOmegaG1.Set(&t2)
	bwOmegaG2.Square(&t2)
}

func psiBLSG2(T bls.G2Affine) bls.G2Affine {
	var res bls.G2Affine
	res.X.MulByElement(&T.X, &blsOmegaG2)
	res.Y = T.Y
	return res
}

func psiBWG2(T bw.G2Affine) bw.G2Affine {
	var res bw.G2Affine
	res.X.Mul(&T.X, &bwOmegaG2)
	res.Y = T.Y
	return res
}

func psiBWG1(T bw.G1Affine) bw.G1Affine {
	var res bw.G1Affine
	res.X.Mul(&T.X, &bwOmegaG1)
	res.Y = T.Y
	return res
}

// eigenBWG1 returns a rational ell-torsion phi-eigenvector on BW6-761 G1 and its
// eigenvalue. The reachable prime ell=127 divides the cofactor to the first power
// (1-dimensional torsion), so any ell-torsion point is an eigenvector.
func eigenBWG1(ell int64) (bw.G1Affine, int64) {
	T := bwG1Torsion(ell)
	pT := psiBWG1(T)
	for _, mu := range cubeRootsModEll(ell) {
		var m bw.G1Affine
		m.ScalarMultiplication(&T, big.NewInt(mu))
		if m.Equal(&pT) {
			return T, mu
		}
	}
	panic("eigenBWG1: no matching eigenvalue")
}

// ---- rational ell-torsion eigenvector and its eigenvalue mu ----

// eigenBWG2 returns a rational 13-torsion eigenvector of phi and its eigenvalue.
// BW6-761 G2's 13-torsion is 1-dimensional, so any 13-torsion point is an
// eigenvector; mu is whichever cube root of unity mod 13 matches phi(T).
func eigenBWG2(ell int64) (bw.G2Affine, int64) {
	T := bwG2Torsion(ell)
	pT := psiBWG2(T)
	for _, mu := range cubeRootsModEll(ell) {
		var m bw.G2Affine
		m.ScalarMultiplication(&T, big.NewInt(mu))
		if m.Equal(&pT) {
			return T, mu
		}
	}
	panic("eigenBWG2: no matching eigenvalue")
}

// eigenBLSG2 returns a rational 13-torsion eigenvector of phi and its eigenvalue.
// BLS12-381 G2's 13-torsion is 2-dimensional; a generic 13-torsion point T0 is
// not an eigenvector, so we project onto the mu=3 eigenspace via (phi - [9])T0.
func eigenBLSG2(ell int64) (bls.G2Affine, int64) {
	T0 := blsG2Torsion(ell)
	pT0 := psiBLSG2(T0)
	roots := cubeRootsModEll(ell) // {3, 9} for ell=13
	// already an eigenvector?
	for _, mu := range roots {
		var m bls.G2Affine
		m.ScalarMultiplication(&T0, big.NewInt(mu))
		if m.Equal(&pT0) {
			return T0, mu
		}
	}
	// project out the other eigenvalue: T = phi(T0) - [roots[1]]T0 lies in the
	// roots[0]-eigenspace.
	mu, other := roots[0], roots[1]
	var scaled, negScaled, T bls.G2Affine
	scaled.ScalarMultiplication(&T0, big.NewInt(other))
	negScaled.Neg(&scaled)
	T.Add(&pT0, &negScaled)
	if T.IsInfinity() {
		panic("eigenBLSG2: projection collapsed to O")
	}
	// verify phi(T) == [mu]T
	var chk bls.G2Affine
	chk.ScalarMultiplication(&T, big.NewInt(mu))
	pT := psiBLSG2(T)
	if !chk.Equal(&pT) {
		panic("eigenBLSG2: projected point is not an eigenvector")
	}
	return T, mu
}

// cubeRootsModEll returns the primitive cube roots of unity mod ell (roots of
// x^2+x+1), i.e. the possible phi-eigenvalues. Assumes ell = 1 mod 3.
func cubeRootsModEll(ell int64) []int64 {
	var roots []int64
	for m := int64(2); m < ell; m++ {
		if (m*m+m+1)%ell == 0 {
			roots = append(roots, m)
		}
	}
	return roots
}

// ---- short-decomposition search via LLL ----
//
// A cofactor prime ell is any-scalar reachable if EITHER sublattice of the
// identity lattice L_r = {(u1,u2,v1,v2): u1+lambda*u2+s*(v1+lambda*v2) = 0 mod r}
// has an in-range short vector:
//   - eigen route (index ell): v1 + mu*v2 = 0 mod ell, needs a phi-eigenvector
//     (mu a cube root of unity mod ell, i.e. ell = 3 or ell = 1 mod 3);
//   - both-zero route (index ell^2): v1 = v2 = 0 mod ell, works for any
//     ell-torsion but the vector is longer (~ell^{1/2} vs ell^{1/4}).
// The min-norm vector is picked over small combinations of the LLL-reduced basis.

// latticeRows returns the L_r basis, u1-entries centered mod r to stay small.
func latticeRows(s, r, lambda *big.Int) (b1, b2, b3, b4 []*big.Int) {
	b1 = []*big.Int{new(big.Int).Set(r), big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	b2 = []*big.Int{centeredMod(new(big.Int).Neg(lambda), r), big.NewInt(1), big.NewInt(0), big.NewInt(0)}
	b3 = []*big.Int{centeredMod(new(big.Int).Neg(s), r), big.NewInt(0), big.NewInt(1), big.NewInt(0)}
	sl := new(big.Int).Mul(s, lambda)
	b4 = []*big.Int{centeredMod(new(big.Int).Neg(sl), r), big.NewInt(0), big.NewInt(0), big.NewInt(1)}
	return
}

func reduceBasis(rows [][]*big.Int) [][]*big.Int {
	mat := toValueRows(rows)
	lllReduce(mat, len(mat)) // vendored gnark-crypto LLL
	return toPtrRows(mat)
}

// pickShortest returns the least infinity-norm signed vector (u1,u2,v1,v2) among
// small combinations of the reduced basis that lies in range (< 2^nbits), has a
// non-zero v-part, satisfies the gadget identity and the non-triviality check
// v1+lambda*v2 != 0 mod r, and passes the route-specific congruence vok(v1,v2).
func pickShortest(reduced [][]*big.Int, s, r, lambda *big.Int, vok func(v1, v2 *big.Int) bool) [4]*big.Int {
	bound := new(big.Int).Lsh(big.NewInt(1), uint(subScalarBits(r)))
	var best [4]*big.Int
	bestMax := new(big.Int) // 0 means "unset"
	rng := []int64{-2, -1, 0, 1, 2}
	for _, c0 := range rng {
		for _, c1 := range rng {
			for _, c2 := range rng {
				for _, c3 := range rng {
					if c0 == 0 && c1 == 0 && c2 == 0 && c3 == 0 {
						continue
					}
					v := combine(reduced, []int64{c0, c1, c2, c3})
					if v[2].Sign() == 0 && v[3].Sign() == 0 {
						continue
					}
					if !vok(v[2], v[3]) {
						continue
					}
					acc := new(big.Int).Set(v[0])
					acc.Add(acc, new(big.Int).Mul(lambda, v[1]))
					acc.Add(acc, new(big.Int).Mul(s, v[2]))
					acc.Add(acc, new(big.Int).Mul(new(big.Int).Mul(s, lambda), v[3]))
					if acc.Mod(acc, r).Sign() != 0 {
						continue
					}
					nt := new(big.Int).Add(v[2], new(big.Int).Mul(lambda, v[3]))
					if nt.Mod(nt, r).Sign() == 0 {
						continue
					}
					m := maxAbsVec(v)
					if m.Cmp(bound) >= 0 {
						continue
					}
					if bestMax.Sign() == 0 || m.Cmp(bestMax) < 0 {
						bestMax = m
						best = [4]*big.Int{v[0], v[1], v[2], v[3]}
					}
				}
			}
		}
	}
	if bestMax.Sign() == 0 {
		panic("pickShortest: no in-range decomposition found")
	}
	return best
}

// eigenRouteDecomp finds a short decomposition in the index-ell sublattice
// v1 + mu*v2 = 0 mod ell (residual [v1]T+[v2]phi(T) = [v1+mu*v2]T vanishes).
func eigenRouteDecomp(s, r, lambda *big.Int, ell, mu int64) [4]*big.Int {
	b1, b2, b3, b4 := latticeRows(s, r, lambda)
	reduced := reduceBasis([][]*big.Int{b1, b2, scaleVec(b3, big.NewInt(ell)), subVec(b4, scaleVec(b3, big.NewInt(mu)))})
	return pickShortest(reduced, s, r, lambda, func(v1, v2 *big.Int) bool {
		e := new(big.Int).Add(v1, new(big.Int).Mul(big.NewInt(mu), v2))
		return e.Mod(e, big.NewInt(ell)).Sign() == 0
	})
}

// bothZeroDecomp finds a short decomposition in the index-ell^2 sublattice
// v1 = v2 = 0 mod ell (residual vanishes for any ell-torsion T, no eigenvector).
func bothZeroDecomp(s, r, lambda *big.Int, ell int64) [4]*big.Int {
	b1, b2, b3, b4 := latticeRows(s, r, lambda)
	L := big.NewInt(ell)
	reduced := reduceBasis([][]*big.Int{b1, b2, scaleVec(b3, L), scaleVec(b4, L)})
	return pickShortest(reduced, s, r, lambda, func(v1, v2 *big.Int) bool {
		return new(big.Int).Mod(v1, L).Sign() == 0 && new(big.Int).Mod(v2, L).Sign() == 0
	})
}

// ---- integer-vector helpers and the (vendored) LLL reducer ----

func centeredMod(x, r *big.Int) *big.Int {
	m := new(big.Int).Mod(x, r)
	if new(big.Int).Lsh(m, 1).Cmp(r) > 0 {
		m.Sub(m, r)
	}
	return m
}

func scaleVec(v []*big.Int, k *big.Int) []*big.Int {
	out := make([]*big.Int, len(v))
	for i := range v {
		out[i] = new(big.Int).Mul(v[i], k)
	}
	return out
}

func subVec(a, b []*big.Int) []*big.Int {
	out := make([]*big.Int, len(a))
	for i := range a {
		out[i] = new(big.Int).Sub(a[i], b[i])
	}
	return out
}

func combine(basis [][]*big.Int, coeffs []int64) []*big.Int {
	d := len(basis[0])
	out := make([]*big.Int, d)
	for t := 0; t < d; t++ {
		out[t] = new(big.Int)
	}
	for i, c := range coeffs {
		if c == 0 {
			continue
		}
		ci := big.NewInt(c)
		for t := 0; t < d; t++ {
			out[t].Add(out[t], new(big.Int).Mul(ci, basis[i][t]))
		}
	}
	return out
}

func maxAbsVec(v []*big.Int) *big.Int {
	m := new(big.Int)
	for _, x := range v {
		a := new(big.Int).Abs(x)
		if a.Cmp(m) > 0 {
			m = a
		}
	}
	return m
}

func toValueRows(rows [][]*big.Int) [][]big.Int {
	out := make([][]big.Int, len(rows))
	for i, r := range rows {
		out[i] = make([]big.Int, len(r))
		for j := range r {
			out[i][j].Set(r[j])
		}
	}
	return out
}

func toPtrRows(rows [][]big.Int) [][]*big.Int {
	out := make([][]*big.Int, len(rows))
	for i := range rows {
		out[i] = make([]*big.Int, len(rows[i]))
		for j := range rows[i] {
			out[i][j] = new(big.Int).Set(&rows[i][j])
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// The LLL routine below is vendored verbatim from gnark-crypto
// (github.com/consensys/gnark-crypto, algebra/lattice/lattice.go, Apache-2.0):
// it is the exact reduction the fake-GLV hint's own decomposition uses, but the
// package exports only the RationalReconstruct* wrappers -- not the reducer --
// so we cannot call it and cannot express our extra sublattice congruence
// (v1+mu*v2 = 0 mod ell) through the wrappers. Copied so the eigen route reduces
// identically to the library.
// ---------------------------------------------------------------------------

var (
	bigOne = big.NewInt(1)
	bigTwo = big.NewInt(2)
)

// lazyRat represents num/den without automatic GCD normalization.
type lazyRat struct {
	num, den big.Int
}

func (r *lazyRat) setInt(x *big.Int) { r.num.Set(x); r.den.SetInt64(1) }
func (r *lazyRat) setInt64(x int64)  { r.num.SetInt64(x); r.den.SetInt64(1) }
func (r *lazyRat) sign() int         { return r.num.Sign() * r.den.Sign() }

func (r *lazyRat) add(a, b *lazyRat) {
	var t1, t2 big.Int
	t1.Mul(&a.num, &b.den)
	t2.Mul(&b.num, &a.den)
	r.num.Add(&t1, &t2)
	r.den.Mul(&a.den, &b.den)
}

func (r *lazyRat) sub(a, b *lazyRat) {
	var t1, t2 big.Int
	t1.Mul(&a.num, &b.den)
	t2.Mul(&b.num, &a.den)
	r.num.Sub(&t1, &t2)
	r.den.Mul(&a.den, &b.den)
}

func (r *lazyRat) mul(a, b *lazyRat) {
	r.num.Mul(&a.num, &b.num)
	r.den.Mul(&a.den, &b.den)
}

func (r *lazyRat) quo(a, b *lazyRat) {
	if b.num.Sign() == 0 {
		panic("lattice: division by zero in lazyRat.quo")
	}
	var newNum, newDen big.Int
	newNum.Mul(&a.num, &b.den)
	newDen.Mul(&a.den, &b.num)
	if newDen.Sign() < 0 {
		newNum.Neg(&newNum)
		newDen.Neg(&newDen)
	}
	r.num.Set(&newNum)
	r.den.Set(&newDen)
}

func (r *lazyRat) cmp(s *lazyRat) int {
	var lhs, rhs big.Int
	lhs.Mul(&r.num, &s.den)
	rhs.Mul(&s.num, &r.den)
	if r.den.Sign()*s.den.Sign() < 0 {
		return -lhs.Cmp(&rhs)
	}
	return lhs.Cmp(&rhs)
}

func (r *lazyRat) abs(a *lazyRat) { r.num.Abs(&a.num); r.den.Abs(&a.den) }

func (r *lazyRat) normalize() {
	if r.num.Sign() == 0 {
		r.den.SetInt64(1)
		return
	}
	var g big.Int
	g.GCD(nil, nil, &r.num, &r.den)
	if g.Sign() != 0 && g.Cmp(bigOne) != 0 {
		r.num.Quo(&r.num, &g)
		r.den.Quo(&r.den, &g)
	}
	if r.den.Sign() < 0 {
		r.num.Neg(&r.num)
		r.den.Neg(&r.den)
	}
}

func (r *lazyRat) roundToInt(dst *big.Int) *big.Int {
	var num, den, rem, rem2 big.Int
	num.Set(&r.num)
	den.Set(&r.den)
	if den.Sign() < 0 {
		num.Neg(&num)
		den.Neg(&den)
	}
	dst.DivMod(&num, &den, &rem)
	rem2.Mul(&rem, bigTwo)
	if rem2.Cmp(&den) >= 0 {
		dst.Add(dst, bigOne)
	}
	return dst
}

// lllReduceWithBound performs LLL reduction (delta = 99/100) with optional early
// termination on an m-row basis. Returns the index of a bound-satisfying row, or -1.
func lllReduceWithBound(basis [][]big.Int, m int, bound *big.Int, denCols []int) int {
	if m == 0 {
		return -1
	}
	n := len(basis[0])

	checkRow := func(row int) bool {
		if bound == nil {
			return false
		}
		hasNonZeroDen := false
		for _, col := range denCols {
			if basis[row][col].Sign() != 0 {
				hasNonZeroDen = true
				break
			}
		}
		if !hasNonZeroDen {
			return false
		}
		for j := 0; j < n; j++ {
			var absVal big.Int
			absVal.Abs(&basis[row][j])
			if absVal.Cmp(bound) > 0 {
				return false
			}
		}
		return true
	}

	if bound != nil {
		for i := 0; i < m; i++ {
			if checkRow(i) {
				return i
			}
		}
	}

	var delta lazyRat
	delta.num.SetInt64(99)
	delta.den.SetInt64(100)

	ortho := make([][]lazyRat, m)
	for i := range ortho {
		ortho[i] = make([]lazyRat, n)
	}
	muCache := make([][]lazyRat, m)
	for i := range muCache {
		muCache[i] = make([]lazyRat, m)
	}
	B := make([]lazyRat, m)
	var term, vi lazyRat

	updateGramSchmidtFrom := func(from int) {
		for i := from; i < m; i++ {
			for j := 0; j < n; j++ {
				ortho[i][j].setInt(&basis[i][j])
			}
			for j := 0; j < i; j++ {
				if B[j].sign() == 0 {
					muCache[i][j].setInt64(0)
					continue
				}
				muCache[i][j].setInt64(0)
				for l := 0; l < n; l++ {
					vi.setInt(&basis[i][l])
					term.mul(&vi, &ortho[j][l])
					muCache[i][j].add(&muCache[i][j], &term)
				}
				muCache[i][j].quo(&muCache[i][j], &B[j])
				muCache[i][j].normalize()
				for l := 0; l < n; l++ {
					term.mul(&muCache[i][j], &ortho[j][l])
					ortho[i][l].sub(&ortho[i][l], &term)
				}
			}
			B[i].setInt64(0)
			for l := 0; l < n; l++ {
				term.mul(&ortho[i][l], &ortho[i][l])
				B[i].add(&B[i], &term)
			}
			B[i].normalize()
			for l := 0; l < n; l++ {
				ortho[i][l].normalize()
			}
		}
	}

	updateGramSchmidtFrom(0)

	k := 1
	var half lazyRat
	half.num.SetInt64(1)
	half.den.SetInt64(2)
	var muSquared, threshold, rhs, absMu lazyRat
	var qScratch, tmp big.Int

	for k < m {
		for {
			reduced := false
			for j := k - 1; j >= 0; j-- {
				if B[j].sign() == 0 {
					continue
				}
				absMu.abs(&muCache[k][j])
				if absMu.cmp(&half) > 0 {
					q := muCache[k][j].roundToInt(&qScratch)
					for l := 0; l < n; l++ {
						tmp.Mul(q, &basis[j][l])
						basis[k][l].Sub(&basis[k][l], &tmp)
					}
					updateGramSchmidtFrom(k)
					reduced = true
					if checkRow(k) {
						return k
					}
				}
			}
			if !reduced {
				break
			}
		}

		if k > 0 && B[k-1].sign() == 0 {
			k++
			continue
		}

		muSquared.mul(&muCache[k][k-1], &muCache[k][k-1])
		threshold.sub(&delta, &muSquared)
		rhs.mul(&threshold, &B[k-1])

		if B[k].cmp(&rhs) >= 0 {
			k++
		} else {
			basis[k], basis[k-1] = basis[k-1], basis[k]
			updateGramSchmidtFrom(k - 1)
			if checkRow(k - 1) {
				return k - 1
			}
			if checkRow(k) {
				return k
			}
			if k > 1 {
				k--
			}
		}
	}
	return -1
}

// lllReduce performs in-place LLL reduction on an m-row basis.
func lllReduce(basis [][]big.Int, m int) {
	lllReduceWithBound(basis, m, nil, nil)
}
