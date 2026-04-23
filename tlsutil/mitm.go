package tlsutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MITMManager generates a CA certificate and per-domain TLS certificates
// for MITM TLS interception. The CA is stored on disk; domain certs are
// cached in memory.
type MITMManager struct {
	mu        sync.RWMutex
	caDir     string
	caKey     *rsa.PrivateKey
	caCert    *x509.Certificate
	caCertPEM []byte
	certCache map[string]*tls.Config
}

// NewMITMManager creates or loads a CA from caDir.
func NewMITMManager(caDir string) (*MITMManager, error) {
	if caDir == "" {
		home, _ := os.UserHomeDir()
		caDir = filepath.Join(home, ".mattlab_ca")
	}

	m := &MITMManager{
		caDir:     caDir,
		certCache: make(map[string]*tls.Config),
	}

	keyPath := filepath.Join(caDir, "ca.key")
	certPath := filepath.Join(caDir, "ca.crt")

	if fileExists(keyPath) && fileExists(certPath) {
		if err := m.loadCA(keyPath, certPath); err != nil {
			return nil, fmt.Errorf("load CA: %w", err)
		}
	} else {
		if err := m.createCA(keyPath, certPath); err != nil {
			return nil, fmt.Errorf("create CA: %w", err)
		}
	}

	return m, nil
}

// CACertPath returns the path to the CA certificate file.
func (m *MITMManager) CACertPath() string {
	return filepath.Join(m.caDir, "ca.crt")
}

// GetTLSConfig returns a *tls.Config for serving TLS with a cert valid
// for the given domain. Results are cached.
func (m *MITMManager) GetTLSConfig(domain string) *tls.Config {
	m.mu.RLock()
	if cfg, ok := m.certCache[domain]; ok {
		m.mu.RUnlock()
		return cfg
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if cfg, ok := m.certCache[domain]; ok {
		return cfg
	}

	cfg := m.generateDomainConfig(domain)
	m.certCache[domain] = cfg
	return cfg
}

func (m *MITMManager) loadCA(keyPath, certPath string) error {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}
	m.caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	m.caCertPEM = certData
	block, _ = pem.Decode(certData)
	if block == nil {
		return fmt.Errorf("failed to decode CA cert PEM")
	}
	m.caCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	return nil
}

func (m *MITMManager) createCA(keyPath, certPath string) error {
	if err := os.MkdirAll(m.caDir, 0700); err != nil {
		return err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	m.caKey = key

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Mattlab Domain Fronting CA",
			Organization: []string{"Mattlab"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}

	m.caCert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}

	// Write key
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}

	// Write cert
	m.caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, m.caCertPEM, 0644); err != nil {
		return err
	}

	return nil
}

func (m *MITMManager) generateDomainConfig(domain string) *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// Build SAN entries
	var sanNames []string
	var sanIPs []net.IP

	if ip := net.ParseIP(domain); ip != nil {
		sanIPs = append(sanIPs, ip)
	} else {
		sanNames = append(sanNames, domain)
		// Add wildcard for parent domain
		parts := strings.Split(domain, ".")
		if len(parts) > 2 && !strings.HasPrefix(domain, "*.") {
			parent := strings.Join(parts[len(parts)-2:], ".")
			sanNames = append(sanNames, "*."+parent)
		} else if len(parts) == 2 && !strings.HasPrefix(domain, "*.") {
			sanNames = append(sanNames, "*."+domain)
		}
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              sanNames,
		IPAddresses:           sanIPs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	// Combine domain cert + CA cert for full chain
	fullChain := append(certPEM, m.caCertPEM...)

	tlsCert, err := tls.X509KeyPair(fullChain, keyPEM)
	if err != nil {
		return nil
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
