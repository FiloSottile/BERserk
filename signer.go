package BERserk

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
)

type Signer struct {
	publicKey *rsa.PublicKey
}

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

	switch {
	case pub.N.BitLen() == 1024 || pub.N.BitLen() == 2048:
		return &Signer{publicKey: pub}, x509.SHA1WithRSA, nil
	default:
		return nil, 0, errors.New("unsupported public key length")
	}
}

func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *Signer) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	switch {
	case s.publicKey.N.BitLen() == 2048 && opts.HashFunc() == crypto.SHA1:
		fallthrough
	case s.publicKey.N.BitLen() == 1024 && opts.HashFunc() == crypto.SHA1:
		return SignPKCS1v15(s.publicKey.N.BitLen(), opts.HashFunc(), msg)
	default:
		return nil, errors.New("wrong opts.HashFunc()")
	}
}
