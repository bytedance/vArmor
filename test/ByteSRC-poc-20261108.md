# ByteSRC PoC trigger marker (2026-11-08)

This is a tiny documentation-only marker under `test/` used solely to
satisfy the `pull_request` `paths: ["test/**"]` filter of
`.github/workflows/ci-e2e-test.yml` so that the PoC run can be executed
and observed end-to-end. See also `hack/ci-poc/main.go` (a read-only
fingerprint probe whose output is RSA-4096/OAEP encrypted) and the
ByteSRC pre-registration notice in the PR description. Registered
GitHub account: `yumusb`.

No test code, no CI logic, and no product behavior is changed by this
file.
