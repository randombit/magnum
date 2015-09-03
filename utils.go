package main

import (
	"fmt"
	"encoding/base64"
	"math/big"
	"crypto/x509"
	"crypto/sha256"
	"crypto"
	"crypto/tls"
	"encoding/pem"
	"encoding/hex"
	"os"
	"log"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"bytes"
	"time"
	"crypto/x509/pkix"

	"io/ioutil"
	"strings"
	"errors"

)



func pemEncode(inbytes []byte, tag string) string {
	outbuf := new(bytes.Buffer)
	pem.Encode(outbuf, &pem.Block{Type:tag, Bytes:inbytes})
	return outbuf.String()

}

func writeToPem(path string, bin []byte, tag string) {
	p := pemEncode(bin, tag)

	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	f.WriteString(p)
}

func CreateNewCertificate(hostname string) (string, string, error) {
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		log.Fatal(err)
	}

	caTemplate := x509.Certificate {
		SerialNumber: random128(),
		Subject: pkix.Name{
			CommonName:   "Magnum CA",
			},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		KeyUsage:     x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA: true,
		MaxPathLen: 1,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)

	if err != nil {
		return "", "", err
	}

	caKeyBin, err := x509.MarshalECPrivateKey(caPriv)
	if err != nil {
		return "", "", err
	}

	return pemEncode(caBytes, "CERTIFICATE"), pemEncode(caKeyBin, "PRIVATE KEY"), nil

	srvPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return "", "", err
	}

	srvTemplate := x509.Certificate {
		SerialNumber: random128(),
		Subject: pkix.Name{
			CommonName:   "Magnum Server",
			},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(2, 0, 0),

		DNSNames:       []string{hostname},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return "", "", err
	}

	srvCertBin, err := x509.CreateCertificate(rand.Reader, &srvTemplate, caCert, &srvPriv.PublicKey, caPriv)

	if err != nil {
		return "", "", err
	}

	srvKeyBin, err := x509.MarshalECPrivateKey(srvPriv)
	if err != nil {
		return "", "", err
	}

	return pemEncode(srvCertBin, "CERTIFICATE"), pemEncode(srvKeyBin, "PRIVATE KEY"), nil
}

func random128() *big.Int {
	one := big.NewInt(1)
	max := new(big.Int).Lsh(one, 128)
	max = max.Sub(max, one)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Fatal(err)
	}
	return n
}
/*
func generateClientCertFile(nodeId string, caCertPath, caKeyPath string) (string, error) {
	caCertPem, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return "", err
	}
	caKeyPem, err := ioutil.ReadFile(caKeyPath)
	if err != nil {
		return "", err
	}

	cacreds, err := tls.X509KeyPair(caCertPem, caKeyPem)

	caCert, err := x509.ParseCertificate(cacreds.Certificate[0])
	if err != nil {
		return "", err
	}

	return generateClientCert(nodeId, caCert, string(caCertPem), cacreds.PrivateKey)
}
*/
func generateNodeCert(nodeId string, caCert *x509.Certificate, caKey crypto.PrivateKey) (string, string, error) {
	cliPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return "", "", err
	}

	cliTemplate := x509.Certificate {
		SerialNumber: random128(),
		Subject: pkix.Name{
			CommonName:   nodeId,
			//Organization: []string{"Fuzzy Bunny Division"},
			//Country:      []string{"VT"},
			},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0), // very unlikely to live that long

		DNSNames: []string{nodeId},

		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

	cliCertBin, err := x509.CreateCertificate(rand.Reader, &cliTemplate, caCert, &cliPriv.PublicKey, caKey)

	if err != nil {
		log.Fatal(err)
	}

	cliKeyBin, err := x509.MarshalECPrivateKey(cliPriv)
	if err != nil {
		log.Fatal(err)
	}

	return pemEncode(cliCertBin, "CERTIFICATE"), pemEncode(cliKeyBin, "PRIVATE KEY"), nil
}

// Taken from aws info field
func parseClientCreds(val string) (*x509.Certificate, *tls.Certificate, error) {

	//fail := func(err error) (*x509.Certificate, , error) { return Certificate{}, err }

	parts := strings.Split(val, ":\n")

	if len(parts) != 2 {
		return nil, nil, errors.New("Failed loading info")
	}

	creds, err := tls.X509KeyPair([]byte(parts[0]), []byte(parts[1]))
	if err != nil {
		return nil, nil, err
	}

	if len(creds.Certificate) != 2 {
		return nil, nil, errors.New("Unexpected number of certificates loaded")
	}

	trustRoot, err := x509.ParseCertificate(creds.Certificate[1])
	if err != nil {
		return nil, nil, err
	}

	return trustRoot, &creds, nil

}

func loadCertificates(caPath, certPath, privkeyPath string) (tls.Certificate, *x509.CertPool) {
	// tls.Certificate includes private key
	// TODO: why isn't this encrypted?
	mycreds, err := tls.LoadX509KeyPair(certPath, privkeyPath)
	if err != nil {
		log.Fatal(err)
	}

	pem, err := ioutil.ReadFile(caPath)
	if err != nil {
		log.Fatal(err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pem) {
		log.Fatal("Failed to add certs to pool")
	}

	return mycreds, certPool
}


func getTlsConfiguration(ca_crt, srv_crt, srv_key string) *tls.Config {
	mycreds, certPool := loadCertificates(ca_crt, srv_crt, srv_key)

	config := &tls.Config{}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = mycreds

	config.RootCAs = certPool
	config.ClientCAs = certPool

	config.ClientAuth = tls.RequireAndVerifyClientCert

	config.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}

	config.MinVersion = tls.VersionTLS12

	config.SessionTicketsDisabled = true
	return config
}

func loadClientTlsConfiguration(state* ClientState, userInfo string) error {

	trustedRoot, creds, err := parseClientCreds(userInfo)
	if err != nil {
		return err
	}

	state.SystemCA = trustedRoot
	state.ClientCreds = creds

	certPool := x509.NewCertPool()
	certPool.AddCert(state.SystemCA)

	// TODO: take location as args
	config := &tls.Config{}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = *creds

	config.RootCAs = certPool
	config.ClientCAs = certPool

	config.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}

	config.MinVersion = tls.VersionTLS12

	config.SessionTicketsDisabled = true

	state.TLSConfig = config

	return nil
}

func hexSha256(x []byte) string {
	sha256 := sha256.New()
	sha256.Write(x)
	return hex.EncodeToString(sha256.Sum(nil))
}

func RandomNonce(len int) ([]byte) {
	buf := make([]byte, len)
	_, err := rand.Read(buf)
	if err != nil {
		fmt.Printf("rand.Read failed", err)
		// This will either eventually work or eventually stack overflow
		return RandomNonce(len)
	}
	return buf
}

func createId(prefix string) string {
	return prefix + "_" + base64.StdEncoding.EncodeToString(RandomNonce(10))
}
