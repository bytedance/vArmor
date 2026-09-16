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

package profile

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	// SDS files contain leaf key material and must only be projected into Envoy.
	MITMCertSDSFile          = "mitm-cert-sds.yaml"
	MITMValidationSDSFile    = "mitm-validation-sds.yaml"
	MITMCertSDSPath          = "/etc/envoy/tls/" + MITMCertSDSFile
	MITMValidationSDSPath    = "/etc/envoy/tls/" + MITMValidationSDSFile
	MITMCertSecretName       = "varmor-mitm-certificate"
	MITMValidationSecretName = "varmor-mitm-validation"
)

// GenerateTLSSecrets creates file-based SDS DiscoveryResponses. Inline material
// makes each certificate/key pair an atomic file update, including Kubernetes
// Secret projection. No CA signing key is included. The two responses can load
// independently: this does not provide a distributed atomic CA rotation.
func GenerateTLSSecrets(cert, key, bundle []byte) (certificate, validation []byte, err error) {
	if _, err := tls.X509KeyPair(cert, key); err != nil {
		return nil, nil, fmt.Errorf("invalid MITM certificate/key pair: %w", err)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(bundle) {
		return nil, nil, fmt.Errorf("MITM trust bundle contains no certificates")
	}
	inline := func(b []byte) *corev3.DataSource {
		return &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: string(b)}}
	}
	certificate, err = marshalTLSSecret(&tlsv3.Secret{Name: MITMCertSecretName, Type: &tlsv3.Secret_TlsCertificate{TlsCertificate: &tlsv3.TlsCertificate{
		CertificateChain: inline(cert), PrivateKey: inline(key),
	}}})
	if err != nil {
		return nil, nil, err
	}
	validation, err = marshalTLSSecret(&tlsv3.Secret{Name: MITMValidationSecretName, Type: &tlsv3.Secret_ValidationContext{ValidationContext: &tlsv3.CertificateValidationContext{TrustedCa: inline(bundle)}}})
	if err != nil {
		return nil, nil, err
	}
	return certificate, validation, nil
}

func marshalTLSSecret(secret *tlsv3.Secret) ([]byte, error) {
	resource, err := anypb.New(secret)
	if err != nil {
		return nil, err
	}
	// Content-based versions also change when the policy generation is unchanged.
	digest := sha256.Sum256(resource.Value)
	return (protojson.MarshalOptions{UseProtoNames: true}).Marshal(&discoveryv3.DiscoveryResponse{
		VersionInfo: fmt.Sprintf("%x", digest), Resources: []*anypb.Any{resource},
		TypeUrl: "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
	})
}
