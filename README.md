# BERserk

A Go implementation of the BERserk attack against Mozilla NSS ASN.1 parsing of PKCS#1 RSA signatures with e = 3.  
Complete of a certificate generation tool, works with CAs in the trust store.

## The attack

The attack exploits Yet Another ASN.1 Parsing Bug in NSS, affecting Firefox 32 and Chrome 37. tl;dr: you can hide garbage in the long length fields of ASN.1 and leverage that to **generate fake signatures for keys with e = 3**. [Bleichenbacher '06](https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html) never dies.

You can go read the original [Intel Security papers](http://www.intelsecurity.com/advanced-threat-research/berserk.html), but be warned that the first is completely generic (even if well detailed) and the second is focused on the vulnerability but glosses over some crucial points. At least in my experience.

You can read what [Adam Langley](https://www.imperialviolet.org/2014/09/26/pkcs1.html) or [Mozilla](https://blog.mozilla.org/security/2014/09/24/rsa-signature-forgery-in-nss/) have to say.

## This work

BERserk was big but it happened on the same day as ShellShock and no one noticed. So much that there isn't neither a live test for it nor a tool to exploit it. So here we are.

`github.com/FiloSottile/BERserk.Signer` is a Go `crypto.Signer` that, given a RSA public key with e = 3 and length 1024 or 2048, will generate (SHA1) PKCS#1 signatures that exploit BERserk without knowledge of the private key.

## The tool

There's also a command line tool that generates a HTTPS certificate given a fitting CA and a CSR in [cfssl](https://github.com/cloudflare/cfssl) format.

There are a few e = 3 root CAs, so exploitation is possible in the wild (against affected versions). A signature is generated in less that 1s so live MitM is also possible.

![screenshot](https://cloud.githubusercontent.com/assets/1225294/6548038/aea465d0-c5e3-11e4-9908-b44c1f8a3600.png)

Install with

```
go get github.com/FiloSottile/BERserk/BERserker
```

Use like

```
BERserker CA.pem csr.json | cfssljson -bare
```

**NOTE**: in order to use a custom `crypto.Signer` for x509 signing BERserker relies on a recent change in Go stdlib. It's not in 1.4, it'll probably be in 1.5, or you can compile Go tip. Otherwise, you'll get this error:

```
x509: only RSA and ECDSA private keys supported
```

## Authors

* Filippo Valsorda [@FiloSottile](https://twitter.com/FiloSottile)
* Anna Bernardi [@AnnaOpss](https://twitter.com/AnnaOpss)
