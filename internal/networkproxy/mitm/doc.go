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

// Package mitm generates TLS MITM certificate material for the
// NetworkProxy enforcer.
//
// The controller invokes this package during VarmorPolicy /
// VarmorClusterPolicy reconcile and writes the resulting bytes into the
// policy's unified Secret. Three artefacts are produced per policy:
//
//   - A self-signed ECDSA P-256 CA certificate and private key, with
//     10-year validity and NotBefore back-dated by five minutes to
//     tolerate node clock skew. The CA is dedicated to a single policy
//     (per-policy granularity bounds blast radius on key leak).
//
//   - A single leaf certificate and private key signed by the above CA,
//     whose SubjectAlternativeName list contains every entry in
//     MITMConfig.Domains. Hostname-style entries are emitted as DNS SANs
//     (wildcards such as "*.openai.com" are written verbatim; RFC 6125
//     matching happens at the TLS verifier); entries that parse as IP
//     literals are emitted as IP SANs.
//
//   - A CA bundle: the embedded Mozilla trusted-root bundle with the
//     above CA certificate appended. The bundle is intended to be
//     mounted into the application container via a projected Secret
//     volume and exposed through SSL_CERT_FILE / REQUESTS_CA_BUNDLE /
//     NODE_EXTRA_CA_CERTS / CURL_CA_BUNDLE, so that applications trust
//     both the public internet PKI and the MITM CA.
//
// Entry points used by the controller reconcile path:
//
//   - GenerateMITMMaterial generates a fresh CA, leaf and bundle in one
//     call. Use this on policy create, MITM being toggled on, or when
//     the existing CA has expired.
//
//   - RenewLeaf re-signs the leaf certificate for a new set of domains
//     using an existing, still-valid CA. The CA and the bundle remain
//     unchanged, which keeps the trust store seen by applications
//     stable across edits to MITMConfig.Domains.
//
// Callers construct these artefacts and publish them alongside the
// Envoy xDS configuration; the package itself does not interact with
// the Kubernetes API.
package mitm
