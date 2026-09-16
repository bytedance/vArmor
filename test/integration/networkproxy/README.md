# NetworkProxy Envoy integration tests

This directory owns cross-package tests of generated proxy configuration,
real Envoy traffic, SDS rotation and the production ALS audit consumer.
Auditor parsing/classification unit tests remain in the auditor package;
renderer and TLS-material unit tests remain in the profile package.

- `harness_test.go`: Envoy discovery, startup/shutdown, readiness, loopback ALS
  collection, captured logs, temporary ports and atomic file publication.
- `tls_fixtures_test.go`: TLS certificates and SDS fixtures shared by scenarios.
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
by the product; the validated local version is Envoy 1.38.3.

Some transport details are adapted for local execution (for example,
ORIGINAL_DST clusters are redirected to test servers). Assertions on generated
routing/RBAC, audit outcomes and TLS reload behavior remain intact. Pure SDS
rotation tests validate upstream TLS, while routing/audit fixtures may substitute
plain HTTP upstream servers. Kubernetes Secret projection is simulated with
atomic symlink switches, not a running kubelet.
