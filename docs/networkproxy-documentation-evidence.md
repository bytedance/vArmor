# NetworkProxy website evidence ledger

This is a maintainer record for the website documentation work, not a public
support matrix. The website describes v0.10.5 behavior; historical test results
are scoped to their actual implementation and environment.

## Release baseline

- Open-source release: `v0.10.5`, commit
  `d995bdb923405790c36ab518af88bb382270fc82`.
- Starting documentation branch: `9e131ed`, which changes MITM example comments.
- No difference from the release tag was found in `internal/networkproxy`,
  `internal/policy`, `internal/webhooks`, `pkg/auditor` or `cmd/networkproxy`.
- English and Chinese stable guides target v0.10.5 within the v0.10 series.
  They must not imply all v0.10 patch versions share these behaviors.

## Historical cluster evidence reviewed

The following reports are maintained in the sibling VKE repository under
`docs/todo/`. They are not included in public website navigation and are not
represented as new test runs for this documentation change.

| Report | Evidence used | Limits |
| --- | --- | --- |
| `networkproxy-e2e-20260918-latest.md` | 870 formal requests, 629 audit records; rule/audit and dynamic behavior | VKE baseline; IPv4, owned endpoints |
| `networkproxy-e2e-20260921.md` | 1,302 formal requests, 863 audit records, 50 admission checks; eight-row matrix, method case, chain selection, header injection, Secret failure/recovery, dynamic rules | VKE `e653a429`; startup defect recorded separately; not a universal pass |
| `networkproxy-security-context-retest-20260921.md` | 240 requests and audits; new Pod and first Deployment injection; explicit old-template repair followed by recreation | VKE `f16d8c8`; ordinary HTTP-rule update did not repair the old template |
| `networkproxy-oss-smoke-20260922.md` | Failure with actual Envoy UID101 versus configured UID1337; UID101 control passed | Open-source `d995bdb`; cached image contract mismatch, not application UID conflict |
| `networkproxy-new-envoy-smoke-20260922.md` | Matching custom image at default UID1337: HTTP/1.1, h2c, MITM HTTP/1.1 and HTTP/2 allow/deny; 8 requests, backend and 8 audits agreed | Small OSS smoke only; no dynamic, SecretRef, IPv6, micro-VM or capacity coverage |

Do not add these counts together into a single release certification. The
historical tests used isolated owned backends and correlated client, backend
and audit evidence. L4 correlation was Pod/destination/time-window based, not
unique HTTP request attribution.

## Open-source implementation checks

| Website contract | Source / tests checked |
| --- | --- |
| Mode defaults and no-rule fallback | `internal/networkproxy/profile/facade.go` |
| Rule AND/OR, deny priority, L4 alternatives, passthrough host/port only | `profile/translator.go`, `audit_semantics_test.go`, `mitm_egress_test.go` |
| IP/DNS chain selection and scoped virtual hosts | `profile/translator_mitm.go`, `mitm_ip_selection_test.go`, `mitm_wildcard_test.go` |
| Path normalization, case-sensitive methods, port matching | `profile/renderer.go`, `path_normalization_test.go`, `http_method_case_test.go`, `http_default_port_test.go` |
| SecretRef inlining and input validation | `apis/varmor/v1beta1/networkproxy.go`, `profile/mitm_resolver.go`, `internal/policy/validate.go` |
| Real spec update triggers reconciliation, metadata-only updates do not | `internal/policy/policy_controller.go`, `clusterpolicy_controller.go` |
| Failed Secret update preserves old configuration; size and CA recovery boundaries | `internal/networkproxy/networkproxy.go`, `mitm_secret_value_test.go`, `size_guard_test.go` |
| Security context, mounts, TCP/UID/loopback exemptions | `internal/webhooks/mutation.go`, `internal/policy/update.go` |
| Custom entrypoint and ALS consumers | `cmd/networkproxy/entrypoint.sh`, `docs/guides/networkproxy_audit_upgrade.md` |

Paths abbreviated as `profile/` are relative to `internal/networkproxy/`.

Operational constraints were cross-checked against the VKE operating-constraints,
chain-selection, security-context and recovery documents. TODO proposals are
not advertised as implemented guarantees. `hostNetwork`, arbitrary mesh
coexistence, universal TLS-library integration and exhaustive IPv6/micro-VM
support are not claimed based on these results.

## Validation of this documentation change

The final batch records website builds, links, YAML checks and any tutorial
execution separately in `website-documentation-validation.md`.

At batch B, `CGO_ENABLED=0 go test ./internal/networkproxy/profile
./internal/networkproxy/mitm` passed in the open-source checkout. This does not
replace the historical cluster evidence or a full Linux test run.

`make test` was attempted and failed in the pre-existing local controller-gen
binary. `make vet` was attempted and failed on unavailable Linux-specific
constants and libseccomp. The user explicitly approved documentation-specific
validation for the four commits. No product source was changed to work around
these environment failures.
