package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/FiloSottile/BERserk"

	"github.com/FiloSottile/BERserk/_vendor/github.com/cloudflare/cfssl/cli"
	"github.com/FiloSottile/BERserk/_vendor/github.com/cloudflare/cfssl/cli/genkey"
	"github.com/FiloSottile/BERserk/_vendor/github.com/cloudflare/cfssl/csr"
	"github.com/FiloSottile/BERserk/_vendor/github.com/cloudflare/cfssl/helpers"
	"github.com/FiloSottile/BERserk/_vendor/github.com/cloudflare/cfssl/signer"
	"github.com/FiloSottile/BERserk/_vendor/github.com/cloudflare/cfssl/signer/local"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: BERserker CA.pem csr.json")
		fmt.Fprintln(os.Stderr, "see github.com/cloudflare/cfssl for csr.json format")
		os.Exit(1)
	}
	caCertFile := os.Args[1]
	csrJSONFile := os.Args[2]

	csrJSONFileBytes, err := cli.ReadStdin(csrJSONFile)
	if err != nil {
		log.Fatal(err)
	}

	var req csr.CertificateRequest
	err = json.Unmarshal(csrJSONFileBytes, &req)
	if err != nil {
		log.Fatal(err)
	}

	var key, csrBytes []byte
	g := &csr.Generator{Validator: genkey.Validator}
	csrBytes, key, err = g.ProcessRequest(&req)
	if err != nil {
		log.Fatal(err)
	}

	s, err := NewSigner(caCertFile)
	if err != nil {
		log.Fatal(err)
	}

	var cert []byte
	sigReq := signer.SignRequest{
		Request: string(csrBytes),
		Subject: &signer.Subject{
			CN:    req.CN,
			Names: req.Names,
			Hosts: req.Hosts,
		},
	}

	for i := 0; i < 5; i++ {
		cert, err = s.Sign(sigReq)
		if _, ok := err.(BERserk.ErrRetry); ok {
			log.Print("Attempt failed, retrying: ", err)
			continue
		}
		if err != nil {
			log.Fatal(err)
		}
		break
	}
	if err != nil {
		log.Fatal(err)
	}

	cli.PrintCert(key, csrBytes, cert)
}

func NewSigner(caCertFile string) (signer.Signer, error) {
	certData, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return nil, err
	}

	cert, err := helpers.ParseCertificatePEM(certData)
	if err != nil {
		return nil, err
	}

	priv, err := BERserk.New(cert)
	if err != nil {
		return nil, err
	}

	return local.NewSigner(priv, cert, x509.SHA1WithRSA, nil)
}
