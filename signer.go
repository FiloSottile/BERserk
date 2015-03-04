package BERserker

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

func New(ca *x509.Certificate) (*Signer, error) {
	if ca.PublicKeyAlgorithm != x509.RSA {
		return nil, errors.New("only RSA is supported")
	}

	pub, ok := ca.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to get certificate RSA key")
	}

	if pub.N.BitLen() > 1024 {
		return nil, errors.New("only RSA 1024 is supported")
	}
	if pub.E != 3 {
		return nil, errors.New("only RSA e = 3 is supported")
	}

	return &Signer{publicKey: pub}, nil
}

func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *Signer) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return SignPKCS1v15(s.publicKey, opts.HashFunc(), msg)
}
