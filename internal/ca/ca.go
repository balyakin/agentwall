package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type Manager struct {
	dir      string
	certPath string
	keyPath  string

	mu      sync.Mutex
	tlsCert tls.Certificate
	loaded  bool
}

func New(dir string) *Manager {
	return &Manager{
		dir:      dir,
		certPath: filepath.Join(dir, "ca.pem"),
		keyPath:  filepath.Join(dir, "ca.key"),
	}
}

func (m *Manager) Ensure() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	if err := m.ensureFiles(); err != nil {
		return err
	}
	if err := m.loadLocked(); err != nil {
		return err
	}
	return nil
}

func (m *Manager) ensureFiles() error {
	_, certErr := os.Stat(m.certPath)
	_, keyErr := os.Stat(m.keyPath)
	if certErr == nil && keyErr == nil {
		return nil
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "AgentWall Local CA",
			Organization: []string{"AgentWall"},
		},
		NotBefore:             now.Add(-10 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	if err := os.WriteFile(m.certPath, certPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(m.keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	return nil
}

func (m *Manager) loadLocked() error {
	if m.loaded {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(m.certPath, m.keyPath)
	if err != nil {
		return err
	}
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			cert.Leaf = leaf
		}
	}
	m.tlsCert = cert
	m.loaded = true
	return nil
}

func (m *Manager) TLSCertificate() (tls.Certificate, error) {
	if err := m.Ensure(); err != nil {
		return tls.Certificate{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tlsCert, nil
}

func (m *Manager) CertPath() string { return m.certPath }
func (m *Manager) KeyPath() string  { return m.keyPath }

func (m *Manager) Install() error {
	if err := m.Ensure(); err != nil {
		return err
	}
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", m.certPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("security add-trusted-cert: %w (%s)", err, string(out))
		}
		return nil
	case "linux":
		target := "/usr/local/share/ca-certificates/agentwall-local-ca.crt"
		raw, err := os.ReadFile(m.certPath)
		if err != nil {
			return fmt.Errorf("read CA cert: %w", err)
		}
		if err := os.WriteFile(target, raw, 0o644); err != nil {
			return fmt.Errorf("copy cert to trust store (%s): %w", target, err)
		}
		cmd := exec.Command("update-ca-certificates")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("update-ca-certificates: %w (%s)", err, string(out))
		}
		return nil
	case "windows":
		cmd := exec.Command("certutil", "-addstore", "Root", m.certPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("certutil addstore: %w (%s)", err, string(out))
		}
		return nil
	default:
		return fmt.Errorf("unsupported OS for install")
	}
}

func (m *Manager) Uninstall() error {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("security", "delete-certificate", "-c", "AgentWall Local CA", "/Library/Keychains/System.keychain")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("security delete-certificate: %w (%s)", err, string(out))
		}
		return nil
	case "windows":
		cmd := exec.Command("certutil", "-delstore", "Root", "AgentWall Local CA")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("certutil delstore: %w (%s)", err, string(out))
		}
		return nil
	case "linux":
		target := "/usr/local/share/ca-certificates/agentwall-local-ca.crt"
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", target, err)
		}
		cmd := exec.Command("update-ca-certificates", "--fresh")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("update-ca-certificates --fresh: %w (%s)", err, string(out))
		}
		return nil
	default:
		return fmt.Errorf("automatic uninstall not supported on this OS")
	}
}
