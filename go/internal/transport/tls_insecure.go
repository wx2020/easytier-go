// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Self-signed TLS for the wss transport.
//
// Rust reference: easytier/src/tunnel/insecure_tls.rs. The oracle serves
// wss listeners with an ephemeral self-signed certificate generated for
// "localhost" and dials wss with a verifier that accepts any certificate
// (documented there as MITM-vulnerable but convenient). This file provides
// the same behavior: listeners auto-provision a self-signed certificate,
// dialers default to skipping server verification, and the SNI name for
// IP-address hosts is rewritten to "localhost" to avoid IP-blocking
// middleboxes (the oracle's websocket connector does the same).
package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"time"
)

var (
	wssSelfSignedOnce sync.Once
	wssSelfSignedCert tls.Certificate
	wssSelfSignedErr  error
)

// SelfSignedWSSCertificate returns the process-wide ephemeral self-signed
// certificate used by wss listeners that were not given explicit key
// material. The certificate covers "localhost" and the loopback addresses.
func SelfSignedWSSCertificate() (tls.Certificate, error) {
	wssSelfSignedOnce.Do(func() {
		wssSelfSignedCert, wssSelfSignedErr = generateSelfSignedWSSCertificate()
	})
	return wssSelfSignedCert, wssSelfSignedErr
}

func generateSelfSignedWSSCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// InsecureWSSClientConfig returns a client TLS configuration that accepts
// any server certificate, mirroring the oracle's SkipServerVerification.
// The caller must not share the returned value across dials that need
// distinct ServerName overrides.
func InsecureWSSClientConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

// wssServerName mirrors the oracle's SNI rewrite: a URL without a domain
// (an IP literal) presents "localhost" so middleboxes do not block IP SNI.
// host must be the URL hostname without port or brackets.
func wssServerName(host string) string {
	if host == "" {
		return "localhost"
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "localhost"
	}
	return host
}
