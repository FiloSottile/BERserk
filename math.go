package BERserker

import (
	"bytes"
	"errors"
	"math/big"
)

var (
	MINUS_ONE = big.NewInt(-1)
	ONE       = big.NewInt(1)
	THREE     = big.NewInt(3)
)

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

func CubeRootSuffix(suffix []byte) ([]byte, error) {
	if suffix[len(suffix)-1]&1 == 0 {
		return nil, errors.New("suffix is even")
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
	// This is much simpler than the papers and works better,
	// there must be a catch. TODO: write feedback

	bitOffset := uint(bitLen - len(prefix)*8)

	// Calculate the cube upper limit (0xSUFFIXfffffffff...)
	u := new(big.Int).SetBytes(prefix)
	u.Add(u.Lsh(u.Add(u, ONE), bitOffset), MINUS_ONE)

	// Calculate the cube lower limit (0xSUFFIX000000000...)
	l := new(big.Int).SetBytes(prefix)
	l.Lsh(l, bitOffset)

	root := BigIntCubeRootFloor(u)

	cube := new(big.Int)
	if cube.Exp(root, THREE, nil).Cmp(l) < 0 {
		return nil, errors.New("root floor too low")
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

	return nil, errors.New("prefix search failed")
}

// high : result of CubeRootPrefix
// low : result of CubeRootSuffix
// target : bytes to bruteforce in the middle
// offset : offset of target from the end in bytes
func BruteforceMiddle(high, low, target []byte, offset int) ([]byte, error) {
	// This is terribly un-generic (number of rounds and offset of inc).
	// If it starts failing, it's time to make it generic.

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

	return nil, errors.New("middle bruteforce failed")
}
