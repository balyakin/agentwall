package ca

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureGeneratesCA(t *testing.T) {
	dir := t.TempDir()
	m := New(dir)
	if err := m.Ensure(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); err != nil {
		t.Fatalf("ca.pem missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("ca.key missing: %v", err)
	}

	certRaw, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certRaw)
	if block == nil {
		t.Fatalf("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.IsCA {
		t.Fatalf("expected generated cert to be CA")
	}
	if cert.Subject.CommonName != "AgentWall Local CA" {
		t.Fatalf("unexpected CN: %s", cert.Subject.CommonName)
	}
}
