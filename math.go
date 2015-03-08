package BERserk

import (
	"bytes"
	"errors"
	"math/big"
)

var (
	MINUS_ONE = big.NewInt(-1)
	ONE       = big.NewInt(1)
	TWO       = big.NewInt(2)
	THREE     = big.NewInt(3)
)

// ErrRetry is returned when a signature can't be generated for the specific
// input. Change the message and retry.
//
// Currently mostly happens because the hashed message is required to be odd.
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
		x.Quo(n, x.Mul(a, a))
		x.Add(x.Add(x, a), a)
		a.Quo(x, THREE)
	}

	return a
}

func BigIntSquareRootFloor(n *big.Int) *big.Int {
	// adapted from mini-gmp
	u, t := new(big.Int), new(big.Int)
	t.SetBit(t, n.BitLen()/2+1, 1)
	for {
		u.Set(t)
		t.Quo(n, u)
		t.Add(t, u)
		t.Rsh(t, 1)
		if t.Cmp(u) >= 0 {
			return u
		}
	}
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
	// Some precomputed values for the common pkcs1v15.go cases
	switch {
	case bytes.Equal([]byte{0x00, 0x01, 0xFF, 0x00, 0x30, 0xD9}, prefix) && bitLen == 1024:
		return []byte{0x01, 0x42, 0x54, 0x6f, 0x33, 0x80, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00}, nil
	case bytes.Equal([]byte{0x00, 0x01, 0x00, 0x30, 0xDB}, prefix) && bitLen == 2048:
		return []byte{0x28, 0x53, 0xd6, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, nil
	default:
		return cubeRootPrefix(prefix, bitLen)
	}
}

func cubeRootPrefix(prefix []byte, bitLen int) ([]byte, error) {
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

func BruteforceMiddle(high, low, target []byte, offset int) ([]byte, error) {
	// This is terribly un-generic (number of rounds and offset of inc).
	// It's unused since it's not needed for 1024 and not enough for 2048.

	// high : result of CubeRootPrefix
	// low : result of CubeRootSuffix
	// target : bytes to bruteforce in the middle
	// offset : offset of target from the end in bytes

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
	// This is terribly specific, so make a couple assertions.
	if offset != 158 || len(target) != 6 {
		return nil, errors.New("incorrect use of RSA2048SHA1Middle")
	}

	var (
		highInt   = new(big.Int).SetBytes(high)
		lowInt    = new(big.Int).SetBytes(low)
		targetInt = new(big.Int).SetBytes(target)

		inc = new(big.Int).Lsh(ONE, 140/2*8)

		vNum, vDen, hl3 = new(big.Int), new(big.Int), new(big.Int)
		res, cube       = new(big.Int), new(big.Int)
	)

	// 3m^2 * (h + l) + (h + l)^3 + 3(h + l)^2 * m -> target
	// 3(h + l)^2 * m is too small, we can ignore it
	// Solve for m the other two: m = sqrt((target - (h + l)^3) / (3 * (h + l)))
	// V = m^2 = (target - (h + l)^3) / (3 * (h + l))

	// Check if it worked, otherwise increase a low-ish position of h and retry

	maskV := new(big.Int).Lsh(ONE, uint(len(target)+offset)*8)
	maskV.Add(maskV, MINUS_ONE)
	maskTarget := new(big.Int).Lsh(ONE, uint(len(target))*8)
	maskTarget.Add(maskTarget, MINUS_ONE)

	for {
		highInt.Add(highInt, inc)

		// vNum = target - (h + l)^3
		hl3.Add(highInt, lowInt)
		hl3.Exp(hl3, THREE, nil)
		vNum.Lsh(vNum.SetBytes(target), uint(offset*8))
		vNum.Add(vNum, hl3.Neg(hl3))
		vNum.And(vNum, maskV)

		// vDen = 3 * (h + l)
		vDen.Mul(vDen.Add(highInt, lowInt), THREE)
		vDen.And(vDen, maskV)

		// m = sqrt(vNum/vDen) / 2^bitLen(l)
		vNum.Quo(vNum, vDen)
		m := BigIntSquareRootFloor(vNum)
		m.Lsh(m.Rsh(m, uint(len(low)*8)), uint(len(low)*8))

		res.Add(res.Add(highInt, lowInt), m)
		cube.Exp(res, THREE, nil)
		cube.And(cube.Rsh(cube, uint(offset*8)), maskTarget)
		if cube.Cmp(targetInt) == 0 {
			break
		}

		// try also rounding m up instead of truncating ti
		m.Lsh(m.Add(m.Rsh(m, uint(len(low)*8)), ONE), uint(len(low)*8))

		res.Add(res.Add(highInt, lowInt), m)
		cube.Exp(res, THREE, nil)
		cube.And(cube.Rsh(cube, uint(offset*8)), maskTarget)
		if cube.Cmp(targetInt) == 0 {
			break
		}
	}

	resBytes := make([]byte, 2048/8)
	copy(resBytes[len(resBytes)-len(res.Bytes()):], res.Bytes())

	return resBytes, nil
}
