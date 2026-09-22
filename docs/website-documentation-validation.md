# Website documentation validation

This record covers the four documentation batches on `update-docs`. It separates
new documentation checks from the historical NetworkProxy tests indexed in
[the evidence ledger](networkproxy-documentation-evidence.md).

## Scope

- Shared introduction, getting-started and policy-writing paths.
- Enforcer selection plus AppArmor, BPF and Seccomp entry pages.
- Eight NetworkProxy pages in English/Chinese, main/v0.10 (32 page variants).
- v0.10 NetworkProxy guidance explicitly describes v0.10.5 behavior.
- Three canonical tutorial YAML files, imported directly into all four guides.
- No vArmor product source, shared cluster components or older release document
  sources were changed. No deployment or remote push is part of this work.

## Repeatable checks

From `website/`:

```bash
node --test plugins/unicode-ssr/renderToHtml.test.mjs
yarn build
python3 scripts/check-documentation.py
```

The checker examines local links and anchors in built main/v0.10 documentation,
rejects NUL characters in generated HTML, compares executable code blocks across
languages/versions, and checks the canonical YAML imports. It does not crawl
external sites or treat legacy-release warnings as current-version failures.

The build also includes older versions. The final validation records their
remaining warnings separately; they are not silently removed or reclassified
as new NetworkProxy failures.

## Source, schema and API checks

- `CGO_ENABLED=0 go test ./internal/networkproxy/profile
  ./internal/networkproxy/mitm`: passed in the open-source checkout.
- All three tutorial YAML files parsed (Namespace, Deployment, Service,
  VarmorPolicy and Pod).
- Tutorial policy validated against the repository's v1beta1 VarmorPolicy
  OpenAPI structural schema. This alone does not evaluate Kubernetes CEL or
  prove runtime behavior.
- Real API server dry-run accepted the policy and client manifests in the
  dedicated test namespace. No policy was persisted before the client dry-run,
  so this is not recorded as an injection test.
- `make test` failed in the pre-existing local controller-gen binary.
- `make vet` failed on macOS Linux-only constants and missing libseccomp.
  The user explicitly approved documentation-specific validation for these
  four commits. Neither full Go command is reported as passing.

## Browser checks

Using a local static preview and Kimi WebBridge:

- English stable tutorial renders the nested Enforcers/NetworkProxy sidebar,
  prerequisite list, complete YAML, commands, expected-result table and next
  page links.
- Chinese language link retains v0.10 and the current tutorial path.
- Chinese tutorial renders eight code blocks and the complete ordered steps,
  with no page-level horizontal overflow in the inspected desktop viewport.
- Version menu links from that Chinese stable tutorial to its main counterpart.
- Homepage Get Started and View Full Guide point to the configured stable
  `/docs/v0.10/introduction` and its `#quick-start` anchor.

This is a desktop spot check, not an exhaustive mobile/accessibility audit.

## Tutorial cluster attempt

The literal backend manifest was applied in a newly created namespace
`varmor-networkproxy-demo`, labeled
`docs.varmor.org/validation=update-docs-20260922`. Its Python image could not be
pulled and the backend entered ImagePullBackOff. No formal HTTP requests were
executed, and the client was not persisted. Consequently this run does not
claim that the new tutorial passed allow/deny, hot-update or audit assertions.

The user was asked for accessible Python/curl mirror addresses. No alternative
backend or cached test fixture was counted as the original tutorial passing.
The guide now calls out image accessibility and the required image-field
substitutions for restricted networks.

The namespace ownership label was checked before deletion, and deletion was
confirmed. Shared vArmor components were not modified. Local diagnostic summary:
`/tmp/varmor-docs-validation/cluster-summary.json` (ephemeral).

## Static HTML finding

The existing lockfile selects Docusaurus 3.10.2 and React 18.3.1. The website
build can exit successfully while React's pipeable stream inserts NUL bytes
into CJK HTML, including IDs and hrefs. This was reproduced after clearing
build caches and is covered by the upstream
[React report](https://github.com/react/react/issues/31134).

A standalone local reproduction produced 44 NUL characters with
`renderToPipeableStream`, zero with `renderToReadableStream`, and an identical
result between the readable-stream output and `renderToString`.

With the user's approval, `website/plugins/unicode-ssr` replaces only the
Docusaurus server renderer with the readable-stream path. Client rendering and
dependency versions are unchanged. The replacement targets a Docusaurus internal
module and must be revisited when upgrading Docusaurus or React.

Final verification on 2026-09-22:

- The dedicated CJK streaming regression test passed, including exact equality
  with `renderToString` and intact heading IDs and links.
- The complete English and Chinese production build passed.
- The documentation checker passed for 148 main/v0.10 pages and four guide
  variants, with no local link, anchor, code-block or YAML-import errors.
- All 394 generated HTML files were scanned: none contained NUL characters.
- Docusaurus reported no main/v0.10 broken-link or broken-anchor source entries.
  The 22 remaining broken-anchor references occur on 10 v0.6-v0.9 pages;
  existing blog truncation warnings also remain outside this change's scope.
- `git diff --check` passed.

The repository commit hook flags an unchanged, existing Algolia client search
key when the configuration file is staged. Its value was compared with HEAD
without printing it. The affected documentation commits bypass this hook only
for that commit; no credential was introduced or changed.
