package BERserk

import (
	"bytes"
	"errors"
	"log"
	"math/big"
)

var (
	MINUS_ONE = big.NewInt(-1)
	ONE       = big.NewInt(1)
	TWO       = big.NewInt(2)
	THREE     = big.NewInt(3)
)

type ErrRetry string

func (e ErrRetry) Error() string {
	return string(e)
}

func BigIntCubeRootFloor(n *big.Int) *big.Int {
	// http://math.stackexchange.com/a/263113
	cube, x := new(big.Int), new(big.Int)

	a := new(big.Int).Set(n) // TODO: optimize
	for cube.Exp(a, THREE, nil).Cmp(n) > 0 {
		// a = (2*a + n/a^2) / 3
		x.Div(n, x.Mul(a, a))
		x.Add(x.Add(x, a), a)
		a.Div(x, THREE)
	}

	return a
}

func BigIntSquareRootFloor(n *big.Int) *big.Int {
	// adapted from github.com/cznic/mathutil.SqrtBig
	px, nx, x := new(big.Int), new(big.Int), new(big.Int)
	x.SetBit(x, n.BitLen()/2+1, 1)
	for {
		nx.Rsh(nx.Add(x, nx.Div(n, x)), 1)
		if nx.Cmp(x) == 0 || nx.Cmp(px) == 0 {
			break
		}
		px.Set(x)
		x.Set(nx)
	}
	return x
}

func CubeRootSuffix(suffix []byte) ([]byte, error) {
	if suffix[len(suffix)-1]&1 == 0 {
		return nil, ErrRetry("suffix is even")
	}

	suffixInt := new(big.Int).SetBytes(suffix)
	resultInt := big.NewInt(1)
	resultCube := new(big.Int)

	for b := 0; b < len(suffix)*8; b++ {
		if resultCube.Exp(resultInt, THREE, nil).Bit(b) != suffixInt.Bit(b) {
			resultInt.SetBit(resultInt, b, 1)
		}
	}

	return resultInt.Bytes(), nil
}

func CubeRootPrefix(prefix []byte, bitLen int) ([]byte, error) {
	// This is much simpler than the papers but might not find the optimal
	// solution if c > 2^d-1. Anyway since the paper binary searches c it is
	// not guaranteed to work better.

	bitOffset := uint(bitLen - len(prefix)*8)

	// Calculate the cube upper limit (0xPREFIXfffffffff...)
	u := new(big.Int).SetBytes(prefix)
	u.Add(u.Lsh(u.Add(u, ONE), bitOffset), MINUS_ONE)

	// Calculate the cube lower limit (0xPREFIX000000000...)
	l := new(big.Int).SetBytes(prefix)
	l.Lsh(l, bitOffset)

	root := BigIntCubeRootFloor(u)

	cube := new(big.Int)
	if cube.Exp(root, THREE, nil).Cmp(l) < 0 {
		return nil, ErrRetry("root floor too low - implement the paper algo")
	} else if cube.Exp(root, THREE, nil).Cmp(u) > 0 {
		panic("root floor higher than original cube")
	}

	// Mask out as many bits as possible without touching the suffix
	for b := 0; b < root.BitLen(); b++ {
		root.SetBit(root, b, 0)
		if cube.Exp(root, THREE, nil).Cmp(l) < 0 {
			root.SetBit(root, b, 1)
			return root.Bytes(), nil
		}
	}

	return nil, ErrRetry("prefix search failed")
}

// high : result of CubeRootPrefix
// low : result of CubeRootSuffix
// target : bytes to bruteforce in the middle
// offset : offset of target from the end in bytes
func BruteforceMiddle(high, low, target []byte, offset int) ([]byte, error) {
	// This is terribly un-generic (number of rounds and offset of inc).
	// It's unused since it's not needed for 1024 and not enough for 2048.

	inc := new(big.Int).Lsh(ONE, uint(len(low)*8))

	root := new(big.Int).SetBytes(high)
	root.Add(root, new(big.Int).SetBytes(low))

	cube := new(big.Int)
	for i := 0; i < 0xffffff; i++ {
		res := cube.Exp(root, THREE, nil).Bytes()
		if bytes.Equal(res[len(res)-offset-len(target):len(res)-offset], target) {
			return root.Bytes(), nil
		}
		root.Add(root, inc)
	}

	return nil, ErrRetry("middle bruteforce failed")
}

func RSA2048SHA1Middle(high, low, target []byte, offset int) ([]byte, error) {
	// This is terribly specific, so make a couple assertions (TODO: needed?).
	if offset != 158 || len(target) != 6 {
		return nil, errors.New("incorrect use of RSA2048SHA1Middle")
	}

	highInt := new(big.Int).SetBytes(high)
	lowInt := new(big.Int).SetBytes(low)

	inc := new(big.Int).Lsh(ONE, 140/2*8)

	// 3m^2 * (h + l) + (h + l)^3 + 3(h + l)^2 * m -> target
	// 3(h + l)^2 * m is too small, ignore it (checked before returning)
	// Solve for m the other two: m = sqrt((target - (h + l)^3) / (3 * (h + l)))
	// V = m^2 = (target - (h + l)^3) / (3 * (h + l))

	mask := new(big.Int).Lsh(ONE, uint(len(target)+offset)*8)

	vNum, vDen, hl3, res, t := new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	for {
		highInt.Add(highInt, inc)

		// target - (h + l)^3
		hl3.Exp(hl3.Add(highInt, lowInt), THREE, nil)
		vNum.Lsh(vNum.SetBytes(target), uint(offset*8))
		vNum.Add(vNum, hl3.Neg(hl3))
		vNum.Mod(vNum, mask)
		if vNum.BitLen() > 1290 {
			continue
		}

		// log.Printf("hl3 = %x", hl3)
		// log.Printf("vNum = %v", vNum)

		// 3 * (h + l)
		vDen.Mod(vDen.Mul(vDen.Add(highInt, lowInt), THREE), mask)

		// log.Printf("vDen = %v", vDen)
		// log.Printf("vNum = %v", vNum)
		// v := new(big.Int).Div(vNum, vDen)
		// log.Printf("v.BitLen = %v", v.BitLen())
		// log.Printf("vDen.BitLen = %v", vDen.BitLen())
		// log.Printf("vNum.BitLen = %v", vNum.BitLen())

		m := BigIntSquareRootFloor(vDen.Div(vNum, vDen))
		// log.Printf("m = %x", m.Bytes())
		m.Lsh(m.Rsh(m, uint(len(low)*8)), uint(len(low)*8))
		// log.Printf("m = %x", m.Bytes())

		// log.Printf("l = %x", low)

		res.Add(res.Add(highInt, lowInt), m)
		cubeBytes := new(big.Int).Exp(res, THREE, nil).Bytes()
		if !bytes.Equal(target,
			cubeBytes[len(cubeBytes)-offset-len(target):len(cubeBytes)-offset]) {
			log.Printf("RITENTA SARAI PIU FORTUNATO %x",
				cubeBytes[len(cubeBytes)-offset-len(target):len(cubeBytes)-offset+1])

			// HACK
			m.Lsh(m.Add(m.Rsh(m, uint(len(low)*8)), ONE), uint(len(low)*8))
			res.Add(res.Add(highInt, lowInt), m)
			cubeBytes := new(big.Int).Exp(res, THREE, nil).Bytes()
			if !bytes.Equal(target,
				cubeBytes[len(cubeBytes)-offset-len(target):len(cubeBytes)-offset]) {
				log.Printf("RITENTA SARAI PIU FORTUNATO %x",
					cubeBytes[len(cubeBytes)-offset-len(target):len(cubeBytes)-offset+1])

				continue
			}
		}

		// Double check that the ignored term is not bleeding into our target:
		// 3(h + l)^2 * m
		tBytes := t.Mul(t.Mul(t.Exp(t.Add(highInt, lowInt), TWO, nil), THREE), m).Bytes()
		tBytes = tBytes[len(tBytes)-offset-len(target) : len(tBytes)-offset]
		if !bytes.Equal(tBytes, []byte{0, 0, 0, 0, 0, 0}) {
			continue
		}

		log.Printf("        (h + l)^3 = %x", hl3.Bytes())
		log.Printf("   3(h + l)^2 * m = %x", t.Bytes())
		tmp := new(big.Int).Exp(m, THREE, nil)
		log.Printf("              m^3 = %x", tmp.Bytes())
		tmp.Mul(tmp.Mul(tmp.Mul(THREE, m), m), new(big.Int).Add(highInt, lowInt))
		log.Printf("3 * m^2 * (h + l) = %x", tmp.Bytes())

		break
	}

	resBytes := make([]byte, 2048/8)
	copy(resBytes[len(resBytes)-len(res.Bytes()):], res.Bytes())

	return resBytes, nil
}
