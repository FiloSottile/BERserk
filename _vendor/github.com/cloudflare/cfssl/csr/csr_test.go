package csr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/FiloSottile/BERserk/_vendor/github.com/cloudflare/cfssl/errors"
)

// TestKeyRequest ensures that key generation returns the same type of
// key specified in the KeyRequest.
func TestKeyRequest(t *testing.T) {
	var kr = &KeyRequest{"ecdsa", 256}

	priv, err := kr.Generate()
	if err != nil {
		t.Fatalf("%v", err)
	}

	switch priv.(type) {
	case *rsa.PrivateKey:
		if kr.Algo != "rsa" {
			t.Fatal("RSA key generated, but expected", kr.Algo)
		}
	case *ecdsa.PrivateKey:
		if kr.Algo != "ecdsa" {
			t.Fatal("ECDSA key generated, but expected", kr.Algo)
		}
	}
}

// TestPKIXName validates building a pkix.Name structure from a
// CertificateRequest.
func TestPKIXName(t *testing.T) {
	var kr = KeyRequest{"ecdsa", 256}
	var cr = &CertificateRequest{
		CN: "Test Common Name",
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare, Inc.",
				OU: "Systems Engineering",
			},
			{
				C:  "GB",
				ST: "London",
				L:  "London",
				O:  "CloudFlare, Inc",
				OU: "Systems Engineering",
			},
		},
		Hosts:      []string{"cloudflare.com", "www.cloudflare.com"},
		KeyRequest: &kr,
	}

	name := cr.Name()
	if len(name.Country) != 2 {
		t.Fatal("Expected two countries in SubjInfo.")
	} else if len(name.Province) != 2 {
		t.Fatal("Expected two states in SubjInfo.")
	} else if len(name.Locality) != 2 {
		t.Fatal("Expected two localities in SubjInfo.")
	} else if len(name.Country) != 2 {
		t.Fatal("Expected two countries in SubjInfo.")
	} else if len(name.Organization) != 2 {
		t.Fatal("Expected two organization in SubjInfo.")
	} else if len(name.OrganizationalUnit) != 2 {
		t.Fatal("Expected two organizational units in SubjInfo.")
	}
}

// TestParseRequest ensures that a valid certificate request does not
// error.
func TestParseRequest(t *testing.T) {
	var kr = KeyRequest{"ecdsa", 256}
	var cr = &CertificateRequest{
		CN: "Test Common Name",
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare, Inc.",
				OU: "Systems Engineering",
			},
			{
				C:  "GB",
				ST: "London",
				L:  "London",
				O:  "CloudFlare, Inc",
				OU: "Systems Engineering",
			},
		},
		Hosts:      []string{"cloudflare.com", "www.cloudflare.com"},
		KeyRequest: &kr,
	}

	_, _, err := ParseRequest(cr)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func whichCurve(sz int) elliptic.Curve {
	switch sz {
	case 256:
		return elliptic.P256()
	case 384:
		return elliptic.P384()
	case 521:
		return elliptic.P521()
	}
	return nil
}

// TestECGeneration ensures that the proper curve is used depending on
// the bit size specified in a key request and that an appropriate
// signature algorithm is returned.
func TestECGeneration(t *testing.T) {
	var eckey *ecdsa.PrivateKey

	for _, sz := range []int{256, 384, 521} {
		kr := &KeyRequest{Algo: "ecdsa", Size: sz}
		priv, err := kr.Generate()
		if err != nil {
			t.Fatalf("%v", err)
		}
		eckey = priv.(*ecdsa.PrivateKey)
		if eckey.Curve != whichCurve(sz) {
			t.Fatal("Generated key has wrong curve.")
		}
		if sa := kr.SigAlgo(); sa == x509.UnknownSignatureAlgorithm {
			t.Fatal("Invalid signature algorithm!")
		}
	}
}

func TestRSAKeyGeneration(t *testing.T) {
	var rsakey *rsa.PrivateKey

	for _, sz := range []int{2048, 3072, 4096} {
		kr := &KeyRequest{Algo: "rsa", Size: sz}
		priv, err := kr.Generate()
		if err != nil {
			t.Fatalf("%v", err)
		}
		rsakey = priv.(*rsa.PrivateKey)
		if rsakey.PublicKey.N.BitLen() != kr.Size {
			t.Fatal("Generated key has wrong size.")
		}
		if sa := kr.SigAlgo(); sa == x509.UnknownSignatureAlgorithm {
			t.Fatal("Invalid signature algorithm!")
		}
	}
}

// TestBadKeyRequest ensures that generating a key from a KeyRequest
// fails with an invalid algorithm, or an invalid RSA or ECDSA key
// size. An invalid ECDSA key size is any size other than 256, 384, or
// 521; an invalid RSA key size is any size less than 2048 bits.
func TestBadKeyRequest(t *testing.T) {
	kr := &KeyRequest{Algo: "yolocrypto", Size: 1024}
	if _, err := kr.Generate(); err == nil {
		t.Fatal("Key generation should fail with invalid algorithm")
	} else if sa := kr.SigAlgo(); sa != x509.UnknownSignatureAlgorithm {
		t.Fatal("The wrong signature algorithm was returned from SigAlgo!")
	}

	kr.Algo = "ecdsa"
	if _, err := kr.Generate(); err == nil {
		t.Fatal("Key generation should fail with invalid key size")
	} else if sa := kr.SigAlgo(); sa != x509.ECDSAWithSHA1 {
		t.Fatal("The wrong signature algorithm was returned from SigAlgo!")
	}

	kr.Algo = "rsa"
	if _, err := kr.Generate(); err == nil {
		t.Fatal("Key generation should fail with invalid key size")
	} else if sa := kr.SigAlgo(); sa != x509.SHA1WithRSA {
		t.Fatal("The wrong signature algorithm was returned from SigAlgo!")
	}

}

// TestDefaultKeyRequest makes sure that certificate requests without
// explicit key requests fall back to the default key request.
func TestDefaultKeyRequest(t *testing.T) {
	var req = &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:    "cloudflare.com",
		Hosts: []string{"cloudflare.com", "www.cloudflare.com"},
	}
	_, priv, err := ParseRequest(req)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// If the default key type changes, this will need to be changed.
	block, _ := pem.Decode(priv)
	if block == nil {
		t.Fatal("Bad private key was generated!")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		if DefaultKeyRequest.Algo != "rsa" {
			t.Fatal("Invalid default key request.")
		}
	case "EC PRIVATE KEY":
		if DefaultKeyRequest.Algo != "ecdsa" {
			t.Fatal("Invalid default key request.")
		}
	}
}

// TestRSACertRequest validates parsing a certificate request with an
// RSA key.
func TestRSACertRequest(t *testing.T) {
	var req = &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:    "cloudflare.com",
		Hosts: []string{"cloudflare.com", "www.cloudflare.com"},
		KeyRequest: &KeyRequest{
			Algo: "rsa",
			Size: 2048,
		},
	}
	_, _, err := ParseRequest(req)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

// TestBadCertRequest checks for failure conditions of ParseRequest.
func TestBadCertRequest(t *testing.T) {
	var req = &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:    "cloudflare.com",
		Hosts: []string{"cloudflare.com", "www.cloudflare.com"},
		KeyRequest: &KeyRequest{
			Algo: "yolo-crypto",
			Size: 2048,
		},
	}
	_, _, err := ParseRequest(req)
	if err == nil {
		t.Fatal("ParseRequest should fail with a bad key algorithm.")
	}
}

// testValidator is a stripped-down validator that checks to make sure
// the request has a common name. It should mimic some of the
// functionality expected in an actual validator.
func testValidator(req *CertificateRequest) error {
	if req.CN == "" {
		return errors.NewBadRequestMissingParameter("CN")
	}

	return nil
}

// TestGenerator ensures that a valid request is processed properly
// and returns a certificate request and key.
func TestGenerator(t *testing.T) {
	g := &Generator{testValidator}
	var req = &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:    "cloudflare.com",
		Hosts: []string{"cloudflare.com", "www.cloudflare.com"},
		KeyRequest: &KeyRequest{
			Algo: "rsa",
			Size: 2048,
		},
	}

	_, _, err := g.ProcessRequest(req)
	if err != nil {
		t.Fatalf("%v", err)
	}

}

// TestBadGenerator ensures that a request that fails the validator is
// not processed.
func TestBadGenerator(t *testing.T) {
	g := &Generator{testValidator}
	missingCN := &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		// Missing CN
		Hosts: []string{"cloudflare.com", "www.cloudflare.com"},
		KeyRequest: &KeyRequest{
			Algo: "rsa",
			Size: 2048,
		},
	}

	_, _, err := g.ProcessRequest(missingCN)
	if err == nil {
		t.Fatalf("Request should have failed.")
	}
}

func TestWeakCSR(t *testing.T) {
	weakKey := &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:    "cloudflare.com",
		Hosts: []string{"cloudflare.com", "www.cloudflare.com"},
		KeyRequest: &KeyRequest{
			Algo: "rsa",
			Size: 1024,
		},
	}
	g := &Generator{testValidator}

	_, _, err := g.ProcessRequest(weakKey)
	if err == nil {
		t.Fatalf("Request should have failed.")
	}
}
