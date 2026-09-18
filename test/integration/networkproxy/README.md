# NetworkProxy Envoy integration tests

This directory owns cross-package tests of generated proxy configuration,
real Envoy traffic, SDS rotation and the production ALS audit consumer.
Auditor parsing/classification unit tests remain in the auditor package;
renderer and TLS-material unit tests remain in the profile package.

- `harness_test.go`: Envoy discovery, startup/shutdown, readiness, loopback ALS
  collection, captured logs, temporary ports and atomic file publication.
- `tls_fixtures_test.go`: TLS certificates and SDS fixtures shared by scenarios.
- `method_case_integration_test.go`: literal policy method case, mixed-case and
  multiple spellings across HTTP chains/protocols and the eight-row audit matrix.
- `custom_methods_integration_test.go`: production bootstrap runtime settings,
  custom and standard methods across HTTP/IP-MITM/TLS/h2c/HTTP2 audit matrices,
  exact method matching, fragmented request lines and non-HTTP TCP fallback.
- `mitm_ip_selection_integration_test.go`: IP MITM plaintext HTTP and overlapping
  DNS/IP TLS selection, including eight-row HTTP/L4 audit matrices.
- `ipv6_l4_integration_test.go`: exact IPv6 host matching in TCP RBAC,
  same-prefix neighbor rejection, explicit `/128` controls and audit results.
- `mapped_cidr_integration_test.go`: IPv4-mapped IPv6 subnet matching in HTTP
  and TCP, prefix boundaries and execution/shadow audit matrices.
- `mitm_ip_reload_integration_test.go`: live addition/removal of MITM IP targets,
  HTTP/1.1, h2c, HTTP/2 TLS, domain/header boundaries and raw TCP fallback.
- `mitm_identity_integration_test.go`: reject equivalent MITM identities before
  publication, then verify a corrected live update enforces and audits denial.
- `*_integration_test.go`: audit matrices, IPv6/HTTP matching, path handling,
  LDS/CDS reload ordering and TLS Secret rotation assertions.

Run from the Go module root (the `guard` directory for VigilArmor):

```sh
ENVOY_BINARY=/absolute/path/to/envoy make test-networkproxy-integration
# Select a scenario or enable the race detector:
ENVOY_BINARY=/absolute/path/to/envoy go test -tags=envoyintegration -race -count=1 ./test/integration/networkproxy -run TestMITMEgressEnvoyAudit
```

The `envoyintegration` build tag enables both these tests and a small adapter
in the auditor package that constructs its real ALS service with an in-memory
output. It neither reimplements audit classification nor opens host log files,
kernel collectors or Docker clients. The adapter is absent from normal builds.
The ordinary `make test` target continues to run unit tests; setting
`ENVOY_BINARY` alone no longer opts these integration tests in.

Tests use temporary directories and local TCP/Unix sockets. No Kubernetes,
Docker daemon, iptables changes or running guard instance is required. IPv6
scenarios require loopback IPv6. TLS tests require the Envoy extensions used
by the product; the source regression uses Envoy 1.38.4; local port validation also covers Envoy 1.38.3.

Some transport details are adapted for local execution (for example,
ORIGINAL_DST clusters are redirected to test servers). Assertions on generated
routing/RBAC, audit outcomes and TLS reload behavior remain intact. Pure SDS
rotation tests validate upstream TLS, while routing/audit fixtures may substitute
plain HTTP upstream servers. Kubernetes Secret projection is simulated with
atomic symlink switches, not a running kubelet.
