/*
Copyright The vArmor Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	// leafValidityYears is the validity period for leaf certificates.
	leafValidityYears = 10

	// leafOrganization is the O used for leaf certificates.
	leafOrganization = "vArmor MITM"

	// leafCommonName is the fallback CN when the first SAN entry is not a
	// hostname (for example, an IP literal).
	//
	// Modern TLS verifiers (RFC 6125 §6.4.4) ignore the CN when SAN is
	// present, so this value is purely informational.
	leafCommonName = "vArmor MITM Leaf"
)

// LeafCertificate holds the PEM-encoded leaf certificate and private key
// produced by the MITM PKI.
type LeafCertificate struct {
	// CertPEM is the PEM-encoded leaf certificate.
	CertPEM []byte
	// KeyPEM is the PEM-encoded leaf private key (ECDSA P-256).
	KeyPEM []byte
}

// MITMMaterial is the complete MITM artefact set produced for a policy
// during reconcile. All fields are PEM-encoded bytes ready to be written
// to the policy's unified Secret.
//
// Bundle is the Mozilla trust bundle with the policy CA appended; it is
// exposed to the application container via a projected Secret volume so
// that application code trusts both the public internet PKI and the
// policy-scoped MITM CA. The CA private key is deliberately excluded
// from this projection and is retained only inside MITMMaterial.CA for
// the controller to persist alongside the leaf material.
type MITMMaterial struct {
	CA     *CACertificate
	Leaf   *LeafCertificate
	Bundle []byte
}

// SignLeafCertificate creates a single leaf certificate whose SAN list
// contains every entry in domains, signed by the given CA.
//
// Entries are classified as they are written into the certificate:
//
//   - IP literals (parsed by net.ParseIP) become IPAddresses entries;
//   - anything else — bare hostnames and wildcard names such as
//     "*.openai.com" — become DNSNames entries.
//
// Wildcard matching happens at the verifier side per RFC 6125: a
// wildcard matches exactly one DNS label and does not match the bare
// parent domain. Callers who need both must include both entries in
// domains explicitly.
//
// A single certificate with multiple SANs is used instead of one
// certificate per domain to minimise the Secret size and to keep the
// Envoy configuration simple (every MITM filter_chain references the
// same DownstreamTlsContext cert/key pair).
func SignLeafCertificate(ca *CACertificate, domains []string) (*LeafCertificate, error) {
	return SignLeafCertificateAt(ca, domains, time.Now())
}

// SignLeafCertificateAt is SignLeafCertificate with an explicit "now"
// anchor. The leaf's NotBefore is set to now - 5 minutes and NotAfter
// to now + 10 years. Tests use this to obtain deterministic validity
// windows; production callers use the wall-clock wrapper above.
func SignLeafCertificateAt(ca *CACertificate, domains []string, now time.Time) (*LeafCertificate, error) {
	if ca == nil || ca.Cert == nil || ca.Key == nil {
		return nil, fmt.Errorf("CA certificate and key must not be nil")
	}

	dnsNames, ipAddrs, err := classifyDomains(domains)
	if err != nil {
		return nil, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf private key: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf serial number: %w", err)
	}

	// Pick a CN that is informative in openssl output. Prefer the first
	// DNS name; fall back to a fixed string when every entry is an IP
	// (RFC 5280 requires CN to be a printable string, not an IP).
	commonName := leafCommonName
	if len(dnsNames) > 0 {
		commonName = dnsNames[0]
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{leafOrganization},
		},
		DNSNames:    dnsNames,
		IPAddresses: ipAddrs,
		NotBefore:   now.Add(-clockSkewTolerance),
		NotAfter:    now.AddDate(leafValidityYears, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &leafKey.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create leaf certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal leaf private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return &LeafCertificate{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// GenerateMITMMaterial generates the complete MITM artefact set for a
// policy: a fresh CA, a leaf certificate signed by that CA with the
// given domains as SANs, and a CA bundle (Mozilla trust bundle with the
// new CA appended).
//
// Use this on policy create, on the MITM feature being switched on, or
// when an existing CA has expired. When only the set of MITM domains
// changes and the CA is still valid, prefer RenewLeaf instead so that
// the trust bundle seen by application containers does not churn.
func GenerateMITMMaterial(domains []string) (*MITMMaterial, error) {
	return GenerateMITMMaterialAt(domains, time.Now())
}

// GenerateMITMMaterialAt is GenerateMITMMaterial with an explicit "now"
// anchor so that tests can pin NotBefore/NotAfter deterministically.
func GenerateMITMMaterialAt(domains []string, now time.Time) (*MITMMaterial, error) {
	ca, err := GenerateCAAt(now)
	if err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}

	leaf, err := SignLeafCertificateAt(ca, domains, now)
	if err != nil {
		return nil, fmt.Errorf("sign leaf certificate: %w", err)
	}

	bundle, err := BuildCABundle(ca.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("build CA bundle: %w", err)
	}

	return &MITMMaterial{CA: ca, Leaf: leaf, Bundle: bundle}, nil
}

// RenewLeaf re-signs the leaf certificate for the given domains using
// an existing CA. The CA itself is not rotated, which means the CA
// bundle exposed to application containers does not change and in-flight
// connections that pre-loaded the bundle remain valid.
//
// Use this when MITMConfig.Domains is edited on an existing policy.
func RenewLeaf(ca *CACertificate, domains []string) (*LeafCertificate, error) {
	return RenewLeafAt(ca, domains, time.Now())
}

// RenewLeafAt is RenewLeaf with an explicit "now" anchor.
func RenewLeafAt(ca *CACertificate, domains []string, now time.Time) (*LeafCertificate, error) {
	if ca == nil {
		return nil, fmt.Errorf("existing CA is required to renew the leaf")
	}
	return SignLeafCertificateAt(ca, domains, now)
}

// classifyDomains splits the user-supplied SAN inputs into DNS names
// and IP addresses. It rejects empty entries and duplicates so that the
// controller never writes a malformed certificate or a Secret whose
// content depends on the order in which deduplication happens later.
//
// Syntactic checks beyond "non-empty and unique" live in the webhook
// validator; this function stays deliberately tolerant because it is
// the last stop before DER encoding and must not diverge from what the
// admission layer already accepted.
func classifyDomains(domains []string) (dns []string, ips []net.IP, err error) {
	if len(domains) == 0 {
		return nil, nil, fmt.Errorf("at least one domain is required")
	}

	dns = make([]string, 0, len(domains))
	ips = make([]net.IP, 0)
	seen := make(map[string]struct{}, len(domains))

	for _, raw := range domains {
		d := strings.TrimSpace(raw)
		if d == "" {
			return nil, nil, fmt.Errorf("empty domain entry")
		}
		if _, dup := seen[d]; dup {
			return nil, nil, fmt.Errorf("duplicate domain entry: %q", d)
		}
		seen[d] = struct{}{}

		if ip := net.ParseIP(d); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dns = append(dns, d)
	}

	return dns, ips, nil
}
