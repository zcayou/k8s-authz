package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Material is a certificate and its private key, parsed and PEM encoded.
type Material struct {
	Certificate    *x509.Certificate
	Key            *ecdsa.PrivateKey
	CertificatePEM []byte
	KeyPEM         []byte
	TLS            tls.Certificate
}

// TLSFiles names the PEM files WriteTLSFiles wrote.
type TLSFiles struct {
	Certificate string
	Key         string
	Authority   string
}

// NewAuthority creates a self-signed CA valid from an hour before now until
// a day after it.
func NewAuthority(now time.Time) (Material, error) {
	template := &x509.Certificate{Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	return issue(template, nil)
}

// Issue signs a leaf certificate for name with the authority's validity. Each
// host becomes an IP or DNS subject alternative name.
func (m Material) Issue(name string, usages []x509.ExtKeyUsage, hosts ...string) (Material, error) {
	template := &x509.Certificate{Subject: pkix.Name{CommonName: name}, NotBefore: m.Certificate.NotBefore, NotAfter: m.Certificate.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	return issue(template, &m)
}

// WriteTLSFiles issues a certificate for server and client authentication
// on hosts and writes it, its key and its authority below directory.
func WriteTLSFiles(directory string, hosts ...string) (TLSFiles, error) {
	authority, err := NewAuthority(time.Now())
	if err != nil {
		return TLSFiles{}, err
	}
	certificate, err := authority.Issue("tls", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, hosts...)
	if err != nil {
		return TLSFiles{}, err
	}
	files := TLSFiles{Certificate: filepath.Join(directory, "tls.crt"), Key: filepath.Join(directory, "tls.key"), Authority: filepath.Join(directory, "ca.crt")}
	for path, data := range map[string][]byte{files.Certificate: certificate.CertificatePEM, files.Key: certificate.KeyPEM, files.Authority: authority.CertificatePEM} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return TLSFiles{}, fmt.Errorf("write %s: %w", path, err)
		}
	}
	return files, nil
}

func issue(template *x509.Certificate, parent *Material) (Material, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Material{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Material{}, err
	}
	template.SerialNumber = serial
	issuer, signer := template, key
	if parent != nil {
		issuer, signer = parent.Certificate, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signer)
	if err != nil {
		return Material{}, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return Material{}, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Material{}, err
	}
	result := Material{Certificate: certificate, Key: key, CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})}
	result.TLS, err = tls.X509KeyPair(result.CertificatePEM, result.KeyPEM)
	return result, err
}
