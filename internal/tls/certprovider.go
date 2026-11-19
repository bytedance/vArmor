// Copyright 2026 vArmor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tls

import (
	"crypto/tls"
	"fmt"
	"sync/atomic"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
)

// CertProvider serves the webhook server's current TLS certificate and
// supports lock-free hot reload when the TLS pair Secret rotates.
//
// The provider is safe for concurrent use: the parsed *tls.Certificate is
// stored atomically and Go's crypto/tls calls GetCertificate on every
// handshake, so a rotated pair takes effect without restarting the process.
// When an update carries a malformed pair the last-good certificate is
// retained, so a transiently bad Secret write cannot take the webhook offline.
type CertProvider struct {
	current atomic.Value // *tls.Certificate
	log     logr.Logger
}

// NewCertProvider builds a provider seeded with the given PEM pair. The
// initial pair must parse successfully; later failures are handled
// gracefully through Update.
func NewCertProvider(initial *PemPair, log logr.Logger) (*CertProvider, error) {
	if initial == nil {
		return nil, fmt.Errorf("cannot build a CertProvider from a nil PEM pair")
	}
	p := &CertProvider{log: log}
	if err := p.Update(initial); err != nil {
		return nil, fmt.Errorf("failed to load initial webhook certificate: %w", err)
	}
	return p, nil
}

// Update parses the PEM pair and atomically swaps it in as the served
// certificate. A malformed pair leaves the previously loaded certificate in
// place and returns an error describing the parse failure.
func (p *CertProvider) Update(pair *PemPair) error {
	if pair == nil {
		return fmt.Errorf("cannot update the webhook certificate from a nil PEM pair")
	}
	cert, err := tls.X509KeyPair(pair.Certificate, pair.PrivateKey)
	if err != nil {
		return err
	}
	p.current.Store(&cert)
	return nil
}

// GetCertificate implements crypto/tls.Config.GetCertificate. The constructor
// guarantees an initial pair and Update keeps the last-good pair on failure,
// so the loaded value is always a *tls.Certificate in practice.
func (p *CertProvider) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cert, ok := p.current.Load().(*tls.Certificate); ok {
		return cert, nil
	}
	return nil, fmt.Errorf("webhook certificate has not been loaded yet")
}

// HandleSecret applies an update from the watched TLS pair Secret.
//
// Secrets other than tlsPairSecretName and updates with empty key material
// are ignored. A malformed pair is logged and rejected without dropping the
// last-good certificate. It reports whether the served certificate changed.
func (p *CertProvider) HandleSecret(secret *v1.Secret, tlsPairSecretName string) bool {
	if secret == nil || secret.Name != tlsPairSecretName {
		return false
	}

	pair := &PemPair{
		Certificate: secret.Data[v1.TLSCertKey],
		PrivateKey:  secret.Data[v1.TLSPrivateKeyKey],
	}
	if len(pair.Certificate) == 0 || len(pair.PrivateKey) == 0 {
		p.log.V(3).Info("ignoring TLS pair Secret update with empty key material", "secret", secret.Name)
		return false
	}

	if err := p.Update(pair); err != nil {
		// Keep serving the last-good certificate; the next Secret write will
		// be retried through the informer handler.
		p.log.Error(err, "failed to hot-reload webhook certificate, keeping the last-good one", "secret", secret.Name)
		return false
	}

	p.log.Info("webhook TLS certificate hot-reloaded", "secret", secret.Name)
	return true
}
