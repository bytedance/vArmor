# Website

This website is built using [Docusaurus](https://docusaurus.io/), a modern static website generator.

### Installation

Use npm 11.12.0 and Node.js 22.23.4, as declared in `package.json` and
`.node-version`. The supported Node.js range is 20.17+ (20.x) or 22.9+.
Run these commands from `website/`:

```bash
npm ci --include=dev
```

Commit `package.json` and `package-lock.json` together. Use `npm install` only
when intentionally updating dependencies; clean installs and CI use `npm ci`.
Do not use Yarn to install this project: the security overrides below are npm
configuration, and `yarn.lock` is not tracked.

### Local Development

```bash
npm run start
```

This command starts a local development server and opens up a browser window. Most changes are reflected live without having to restart the server.

### Build

```bash
npm run build
```

This command generates static content into the `build` directory and can be served using any static contents hosting service.

### Deployment

The production website is deployed by the Cloudflare Pages Git integration.
GitHub reports its result as the **Cloudflare Pages** check. The website does
not use the repository's Go build workflows or a `gh-pages` push to publish.

The Pages project should use `main` as its production branch, `website` as its
root directory, `npm run build` as its build command, and `build` as its output
directory. Automatic production deployments must remain enabled. Build-time
dependencies, including `docusaurus-plugin-llms`, must be installed.

With those settings, merging into `main` triggers the build and publication;
there is no local deployment command to run. Check the Cloudflare Pages result
for the merged commit before considering it published. Build settings and
environment variables are managed in Cloudflare, outside this repository.
Cloudflare supports `.node-version` in the project root to select Node.js;
check for conflicting dashboard overrides when troubleshooting. GitHub's Pages
check links to the deployment logs, which require access to the Cloudflare
project. Its public summary does not include the build command or Node version.

The `ci-website` GitHub Actions workflow separately checks clean installation,
known dependency vulnerabilities, plugin tests, the bilingual production build,
and generated documentation. It validates changes but does not publish them or
gate Cloudflare's independent deployment automatically.

### Dependency maintenance

Keep all direct `@docusaurus/*` packages at the same exact version. The npm
`overrides` in `package.json` replace vulnerable transitive dependencies:

| Dependency | Override | Reason |
| --- | --- | --- |
| `serialize-javascript` | `7.1.3` | Fix CPU exhaustion and function serialization XSS advisories. |
| `docusaurus-plugin-llms` → `minimatch`, `yaml` | `9.0.7`, `2.8.3` | Replace the plugin's exact vulnerable pins without downgrading the plugin. |
| `@docusaurus/core` → `tinypool` | `2.1.2` | Fix prototype-pollution gadget advisories. |
| `@coze/api`, `sockjs` → `uuid` | `11.1.1` | Fix buffer bounds checking while retaining CommonJS support. |
| `postcss-selector-parser` | `7.1.7` | Fix quadratic selector parsing; use an unconditional override for npm 10/11 compatibility. |

Do not apply `npm audit fix --force` blindly: it can downgrade
`docusaurus-plugin-llms` and break the Markdown paths expected by our adapter.
Review upstream releases and remove overrides when their dependency ranges
include patched versions. Cross-major overrides still need compatibility
review; a clean audit alone is not a functional test.

After dependency changes, run:

```bash
npm ci --include=dev
npm audit
npm test
npm run build
npm run check:docs
```

## Documentation validation

After a production build, run:

```bash
python3 scripts/check-documentation.py
node --test plugins/unicode-ssr/renderToHtml.test.mjs
```

The standard-library-only checker validates local links and anchors in the
English/Chinese main and v0.10 output, rejects NUL characters in generated HTML,
and checks NetworkProxy guide/example parity. It requires a full build of both
locales. Legacy documentation warnings and external URLs need separate review.

The NetworkProxy Quick Start renders the canonical files under
`static/examples/networkproxy/v0.10.5/` through Webpack's `asset/source` support.
Edit those files instead of keeping independent YAML copies in translations.
Policy schema/admission checks and cluster requests are separate from a website
build; record actual execution and any environment blockers.

The `unicode-ssr` plugin replaces only Docusaurus's server HTML renderer with
React's readable-stream implementation. This avoids the React 18 pipeable-stream
NUL issue described in https://github.com/react/react/issues/31134 without
changing client React or package versions. Its interception is intentionally
limited to the current Docusaurus renderer module: when upgrading Docusaurus or
React, revisit/remove this compatibility layer and run the HTML checker again.

## AI documentation exports

`docusaurus-plugin-llms` is pinned in `package.json` and adapted by
`plugins/llms/index.cjs`. A production build generates `/llms.txt` and
`/zh-cn/llms.txt`, with separate indexes under `docs/main/` and
`docs/v0.10/` in each language. Each index links to individual `.md`
pages. Older versions and blog posts are not included in these indexes.

Edit the existing Markdown/MDX documentation and canonical YAML examples.
Do not maintain a second AI documentation tree. The adapter uses Docusaurus
page metadata for translated sources and actual routes, expands raw YAML
imports, replaces documentation cards and themed images, and rewrites links.
Temporary inputs stay in `.docusaurus/`; exported pages and image copies stay
in `build/`. No external AI service or API key is used.

Validate after building both languages:

```bash
node --test plugins/llms/index.test.cjs
node scripts/check-llms.cjs
python3 scripts/check-documentation.py
```

The checks cover page counts, index version/language boundaries, local links,
unresolved MDX, and exact tutorial YAML preservation. Preview the generated
files with `npm run serve`; they are build outputs and are not available from
`npm run start` alone. Full-document bundles are intentionally disabled so
agents can fetch the pages they need without mixing versions or languages.
