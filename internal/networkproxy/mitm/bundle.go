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
	_ "embed"
	"fmt"
)

// mozillaCABundle is the Mozilla CA certificate bundle (PEM), embedded
// into the vArmor manager binary at compile time. The controller uses
// it to build the full CA trust store written to the policy's unified
// Secret so that application containers, mounted through a projected
// Secret volume, trust both the public internet PKI and the vArmor
// MITM CA simultaneously.
//
// Updating the bundle: run `make update-mozilla-bundle`, which fetches
// the latest cacert.pem from https://curl.se/ca/cacert.pem and writes
// it to internal/networkproxy/mitm/certs/mozilla.pem.
//
//go:embed certs/mozilla.pem
var mozillaCABundle []byte

// MozillaCABundle returns the embedded Mozilla CA certificate bundle.
//
// The returned slice aliases the embedded data; callers must not
// mutate it.
func MozillaCABundle() []byte {
	return mozillaCABundle
}

// BuildCABundle concatenates the embedded Mozilla CA bundle with the
// provided vArmor MITM CA certificate to produce a complete trust store
// suitable for consumption by application containers.
//
// The output is PEM and can be written verbatim into the policy's
// unified Secret as the ca-bundle.crt key; that key is projected into
// the application container at a stable path and referenced through
// SSL_CERT_FILE, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS and
// CURL_CA_BUNDLE.
//
// A single newline is inserted between the two sections when the
// embedded bundle does not already end with one; no trailing newline
// is added so that repeated invocations with the same inputs produce
// byte-identical output (relevant for Secret update semantics).
func BuildCABundle(caCertPEM []byte) ([]byte, error) {
	if len(caCertPEM) == 0 {
		return nil, fmt.Errorf("CA certificate PEM must not be empty")
	}
	if len(mozillaCABundle) == 0 {
		return nil, fmt.Errorf("embedded Mozilla CA bundle is empty (build error)")
	}

	// Guard against integer overflow before allocation.
	mozLen, caLen := len(mozillaCABundle), len(caCertPEM)
	total := mozLen + caLen
	if total < mozLen || total < caLen {
		return nil, fmt.Errorf("CA bundle size overflow")
	}

	bundle := make([]byte, 0, total+1)
	bundle = append(bundle, mozillaCABundle...)
	if mozillaCABundle[len(mozillaCABundle)-1] != '\n' {
		bundle = append(bundle, '\n')
	}
	bundle = append(bundle, caCertPEM...)

	return bundle, nil
}
