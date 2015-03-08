package BERserk

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestCubeRootSuffixFixed(t *testing.T) {
	suffix, _ := hex.DecodeString("000000c3d093394e836b2a494f38512e0f57")
	res, err := CubeRootSuffix(suffix)
	if err != nil {
		t.Fatal(err)
	}
	cube := new(big.Int).Exp(new(big.Int).SetBytes(res), THREE, nil).Bytes()
	t.Logf("%x ^ 3 = %x", res, cube)
	if !bytes.Equal(suffix, cube[len(cube)-len(suffix):]) {
		t.Fail()
	}
}

func TestCubeRootSuffixPaper(t *testing.T) {
	suffix, _ := hex.DecodeString("48ACE9B7BC30CB37338419F7716D4E9F50AA0AD2A425BCF38C2A11669F85CFD5")
	expect, _ := hex.DecodeString("FA9AE7786889394783145E1191A9A4ACBD7BFCCB4DA07E9FFC60ADF24AC6A1CD")
	res, err := CubeRootSuffix(suffix)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res, expect) {
		t.Fatalf("%x != %x", res, expect)
	}
}

func TestCubeRootPrefixPaper(t *testing.T) {
	prefix, _ := hex.DecodeString("0001FFFFFFFFFFFFFFFF003031300D060960864801650304020105C3")
	// expect, _ := hex.DecodeString("32CBFD4A7ADC7905583D767520F51640759176D37826F2EF63B4B400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	expect, _ := hex.DecodeString("32CBFD4A7ADC7905583D767520F51640759176D37826F2EF63B4B800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	res, err := CubeRootPrefix(prefix, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res, expect) {
		t.Fatalf("%x != %x", res, expect)
	}
}

func TestBruteforceMiddlePaper(t *testing.T) {
	expect, _ := hex.DecodeString("32CBFD4A7ADC7905583D767520F51640759176D37826F2EF63B4B40000000000000000000000000000000000000000000000002C7AFA9AE7786889394783145E1191A9A4ACBD7BFCCB4DA07E9FFC60ADF24AC6A1CD")

	high, _ := hex.DecodeString("32CBFD4A7ADC7905583D767520F51640759176D37826F2EF63B4B400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	low, _ := hex.DecodeString("FA9AE7786889394783145E1191A9A4ACBD7BFCCB4DA07E9FFC60ADF24AC6A1CD")
	target, _ := hex.DecodeString("04FF")
	offset := 159

	sig, err := BruteforceMiddle(high, low, target, offset)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, expect) {
		t.Fatalf("%x != %x", sig, expect)
	}
}

func TestRSA2048SHA1MiddlePaper(t *testing.T) {
	sigHi, _ := hex.DecodeString("2853D660000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	sigLow, _ := hex.DecodeString("8677641705A29EBDB3067E5F212ABFF010C999CBAB522DA0BCB588C5E93DD2B31F7C41")
	res, err := RSA2048SHA1Middle(sigHi, sigLow, RSA2048SHA1DigestInfoTemplate.Middle, RSA2048SHA1DigestInfoTemplate.MiddleOffset+len(RSA2048SHA1DigestInfoTemplate.Suffix)+RSA2048SHA1DigestInfoTemplate.HashLen)
	if err != nil {
		t.Fatal(err)
	}
	cube := new(big.Int).Exp(new(big.Int).SetBytes(res), THREE, nil).Bytes()
	t.Logf("s: %x ^ 3 = %x", res, cube)
}
