package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"time"

	"tls10proxy/internal/logger"
)

const (
	RootCertLifetime   time.Duration = 365 * 24 * time.Hour
	ServerCertLifetime time.Duration = 30 * 24 * time.Hour
	RootCertDER                      = "ca.der"
	RootCertPrivateKey               = "ca.key"
)

func newPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func newRandomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)

	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random serial number: %w", err)
	}

	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}

	return serial, nil
}

func newCA(caKey *rsa.PrivateKey) (*x509.Certificate, error) {
	serialNumber, err := newRandomSerialNumber()
	if err != nil {
		return nil, err
	}

	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "TLS10Proxy CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(RootCertLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA1WithRSA, // Force SHA-1 for legacy compatibility
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, err
	}

	return caCert, nil
}

func saveCA(caCert *x509.Certificate, caKey *rsa.PrivateKey) error {
	if err := os.WriteFile(RootCertDER, caCert.Raw, 0600); err != nil {
		return err
	}

	logger.Debugf("CA cert written to %s", RootCertDER)

	encodedKey, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return err
	}

	if err = os.WriteFile(RootCertPrivateKey, encodedKey, 0600); err != nil {
		return err
	}

	logger.Debugf("CA private key written to %s", RootCertPrivateKey)

	return nil
}

func loadCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	caCertDER, err := os.ReadFile(RootCertDER)
	if err != nil {
		return nil, nil, err
	}

	logger.Debugf("CA cert loaded from %s", RootCertDER)

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, nil, err
	}

	key, err := os.ReadFile(RootCertPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}

	privateRSAKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not an RSA private key")
	}

	logger.Debugf("CA private key loaded from %s", RootCertPrivateKey)

	return caCert, privateRSAKey, nil
}

func Init() (*x509.Certificate, *rsa.PrivateKey, error) {
	caCert, privateKey, err := loadCA()
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("CA certificate not found, generating new one")
			privateKey, err = newPrivateKey()
			if err != nil {
				return nil, nil, err
			}

			caCert, err = newCA(privateKey)
			if err != nil {
				return nil, nil, err
			}

			if err = saveCA(caCert, privateKey); err != nil {
				return nil, nil, err
			}

			return caCert, privateKey, nil
		}

		return nil, nil, err
	}

	logger.Infof("CA certificate and private key successfully loaded")

	return caCert, privateKey, nil
}

func GenerateServerCert(hostname string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumber, err := newRandomSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		DNSNames:           []string{hostname},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(ServerCertLifetime),
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm: x509.SHA1WithRSA, // Force SHA-1 for legacy compatibility
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER, caCert.Raw},
		PrivateKey:  key,
		Leaf:        template,
	}

	return cert, nil
}
