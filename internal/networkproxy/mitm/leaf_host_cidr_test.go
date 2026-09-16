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

package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"reflect"
	"testing"
)

func TestLeafHostCIDRSAN(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name              string
		domains, dns, ips []string
		wantErr           bool
	}{
		{name: "ipv4", domains: []string{"172.31.0.185/32"}, ips: []string{"172.31.0.185"}},
		{name: "ipv6", domains: []string{"2001:db8::1/128"}, ips: []string{"2001:db8::1"}},
		{name: "mixed", domains: []string{"api.example.com", "*.svc.example.com", "172.31.0.185/32", "2001:db8::1/128"}, dns: []string{"api.example.com", "*.svc.example.com"}, ips: []string{"172.31.0.185", "2001:db8::1"}},
		{name: "ipv4_aliases", domains: []string{"172.31.0.185", "172.31.0.185/32", "172.31.0.185/32", "::ffff:172.31.0.185/128"}, ips: []string{"172.31.0.185"}},
		{name: "ipv6_aliases", domains: []string{"2001:0DB8:0:0:0:0:0:1/128", "2001:db8::1", "2001:db8::1/128"}, ips: []string{"2001:db8::1"}},
		{name: "bare_ips", domains: []string{"172.31.0.185", "2001:db8::1"}, ips: []string{"172.31.0.185", "2001:db8::1"}},
		{name: "wide_ipv4", domains: []string{"172.31.0.185/24"}, wantErr: true},
		{name: "wide_ipv6", domains: []string{"2001:db8::1/64"}, wantErr: true},
		{name: "wide_mapped", domains: []string{"::ffff:172.31.0.185/120"}, wantErr: true},
		{name: "invalid_ipv4_prefix", domains: []string{"172.31.0.185/33"}, wantErr: true},
		{name: "invalid_ipv6_prefix", domains: []string{"2001:db8::1/129"}, wantErr: true},
		{name: "invalid_address", domains: []string{"999.0.0.1/32"}, wantErr: true},
		{name: "invalid_dns_cidr", domains: []string{"api.example.com/32"}, wantErr: true},
		{name: "duplicate_dns", domains: []string{"api.example.com", "api.example.com"}, wantErr: true},
		{name: "empty", domains: []string{" "}, wantErr: true},
	}
	for _, renew := range []bool{false, true} {
		method := "sign"
		if renew {
			method = "renew"
		}
		for _, tc := range cases {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				var leaf *LeafCertificate
				var err error
				if renew {
					leaf, err = RenewLeaf(ca, tc.domains)
				} else {
					leaf, err = SignLeafCertificate(ca, tc.domains)
				}
				if tc.wantErr {
					if err == nil {
						t.Fatal("expected rejection of invalid certificate identity")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				pair, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
				if err != nil {
					t.Fatal(err)
				}
				cert, err := x509.ParseCertificate(pair.Certificate[0])
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(cert.DNSNames, tc.dns) {
					t.Errorf("DNS SANs=%v want %v", cert.DNSNames, tc.dns)
				}
				if len(cert.IPAddresses) != len(tc.ips) {
					t.Errorf("IP SANs=%v want %v", cert.IPAddresses, tc.ips)
				}
				roots := x509.NewCertPool()
				roots.AddCert(ca.Cert)
				for i, host := range tc.ips {
					if i < len(cert.IPAddresses) && !cert.IPAddresses[i].Equal(net.ParseIP(host)) {
						t.Errorf("IP SAN[%d]=%s want %s", i, cert.IPAddresses[i], host)
					}
					if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
						t.Errorf("verify IP %s: %v", host, err)
					}
				}
				for _, host := range []string{"api.example.com", "test.svc.example.com"} {
					if len(tc.dns) > 0 {
						if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
							t.Errorf("verify DNS %s: %v", host, err)
						}
					}
				}
				for _, host := range []string{"172.31.0.186", "2001:db8::2"} {
					if cert.VerifyHostname(host) == nil {
						t.Errorf("certificate unexpectedly verifies unrelated IP %s", host)
					}
				}
			})
		}
	}
}
