package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"github.com/yhat/yaml"
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage: certdump [certfile]
`)
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() != 1 {
		usage()
	}

	log.SetPrefix("certdump: ")

	data, err := ioutil.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	found := false
	defer func() {
		if !found {
			log.Println("No certificates found.")
		}
	}()
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return
		}
		found = true
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("failed to parse certificate: %v", err)
		}

		c := PrintableCertificate(cert)
		out, err := yaml.Marshal(c)
		if err != nil {
			log.Fatalf("could not marshal cerficate: %v", err)
		}
		fmt.Println(string(out))
	}
}

type Certificate struct {
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	Version            int
	SerialNumber       string

	Issuer              string
	NotBefore, NotAfter string
	KeyUsage            []string

	ExtKeyUsage []string
	IsCA        bool

	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
}

func PrintableCertificate(cert *x509.Certificate) *Certificate {
	c := &Certificate{
		SignatureAlgorithm: SignatureAlgorithmString(cert.SignatureAlgorithm),
		PublicKeyAlgorithm: PublicKeyAlgorithmString(cert.PublicKeyAlgorithm),
		Version:            cert.Version,
		SerialNumber:       cert.SerialNumber.String(),

		NotBefore: cert.NotBefore.Format(time.UnixDate),
		NotAfter:  cert.NotAfter.Format(time.UnixDate),
		KeyUsage:  KeyUsageStrings(cert.KeyUsage),

		ExtKeyUsage: ExtKeyUsageStrings(cert.ExtKeyUsage),
		IsCA:        cert.IsCA,

		DNSNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
		IPAddresses:    cert.IPAddresses,
	}
	if len(cert.Issuer.Organization) == 1 {
		c.Issuer = cert.Issuer.Organization[0]
	}
	return c
}

var signatureAlgorithmNames = map[x509.SignatureAlgorithm]string{
	x509.UnknownSignatureAlgorithm: "UnknownSignatureAlgorithm",
	x509.MD2WithRSA:                "MD2WithRSA",
	x509.MD5WithRSA:                "MD5WithRSA",
	x509.SHA1WithRSA:               "SHA1WithRSA",
	x509.SHA256WithRSA:             "SHA256WithRSA",
	x509.SHA384WithRSA:             "SHA384WithRSA",
	x509.SHA512WithRSA:             "SHA512WithRSA",
	x509.DSAWithSHA1:               "DSAWithSHA1",
	x509.DSAWithSHA256:             "DSAWithSHA256",
	x509.ECDSAWithSHA1:             "ECDSAWithSHA1",
	x509.ECDSAWithSHA256:           "ECDSAWithSHA256",
	x509.ECDSAWithSHA384:           "ECDSAWithSHA384",
	x509.ECDSAWithSHA512:           "ECDSAWithSHA512",
}

func SignatureAlgorithmString(v x509.SignatureAlgorithm) string {
	s, ok := signatureAlgorithmNames[v]
	if !ok {
		s = "SignatureAlgorithmUNKOWN"
	}
	return s
}

var publicKeyAlgorithmNames = map[x509.PublicKeyAlgorithm]string{
	x509.UnknownPublicKeyAlgorithm: "UnknownPublicKeyAlgorithm",
	x509.RSA:                       "RSA",
	x509.DSA:                       "DSA",
	x509.ECDSA:                     "ECDSA",
}

func PublicKeyAlgorithmString(v x509.PublicKeyAlgorithm) string {
	s, ok := publicKeyAlgorithmNames[v]
	if !ok {
		s = "PublicKeyAlgorithmUNKOWN"
	}
	return s
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                        "ExtKeyUsageAny",
	x509.ExtKeyUsageServerAuth:                 "ExtKeyUsageServerAuth",
	x509.ExtKeyUsageClientAuth:                 "ExtKeyUsageClientAuth",
	x509.ExtKeyUsageCodeSigning:                "ExtKeyUsageCodeSigning",
	x509.ExtKeyUsageEmailProtection:            "ExtKeyUsageEmailProtection",
	x509.ExtKeyUsageIPSECEndSystem:             "ExtKeyUsageIPSECEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                "ExtKeyUsageIPSECTunnel",
	x509.ExtKeyUsageIPSECUser:                  "ExtKeyUsageIPSECUser",
	x509.ExtKeyUsageTimeStamping:               "ExtKeyUsageTimeStamping",
	x509.ExtKeyUsageOCSPSigning:                "ExtKeyUsageOCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "ExtKeyUsageMicrosoftServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "ExtKeyUsageNetscapeServerGatedCrypto",
}

func ExtKeyUsageString(v x509.ExtKeyUsage) string {
	s, ok := extKeyUsageNames[v]
	if !ok {
		s = "ExtKeyUsageUNKOWN"
	}
	return s
}

func ExtKeyUsageStrings(vv []x509.ExtKeyUsage) []string {
	vals := make([]string, len(vv))
	for i, v := range vv {
		vals[i] = ExtKeyUsageString(v)
	}
	return vals
}

var keyUsageNames = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  "KeyUsageDigitalSignature",
	x509.KeyUsageContentCommitment: "KeyUsageContentCommitment",
	x509.KeyUsageKeyEncipherment:   "KeyUsageKeyEncipherment",
	x509.KeyUsageDataEncipherment:  "KeyUsageDataEncipherment",
	x509.KeyUsageKeyAgreement:      "KeyUsageKeyAgreement",
	x509.KeyUsageCertSign:          "KeyUsageCertSign",
	x509.KeyUsageCRLSign:           "KeyUsageCRLSign",
	x509.KeyUsageEncipherOnly:      "KeyUsageEncipherOnly",
	x509.KeyUsageDecipherOnly:      "KeyUsageDecipherOnly",
}

func KeyUsageStrings(usages x509.KeyUsage) []string {
	vals := []string{}
	for k, v := range keyUsageNames {
		if k&usages != 0 {
			vals = append(vals, v)
		}
	}
	return vals
}
