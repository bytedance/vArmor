# Website

This website is built using [Docusaurus](https://docusaurus.io/), a modern static website generator.

### Installation

```
$ yarn
```

### Local Development

```
$ yarn start
```

This command starts a local development server and opens up a browser window. Most changes are reflected live without having to restart the server.

### Build

```
$ yarn build
```

This command generates static content into the `build` directory and can be served using any static contents hosting service.

### Deployment

Using SSH:

```
$ USE_SSH=true yarn deploy
```

Not using SSH:

```
$ GIT_USER=<Your GitHub username> yarn deploy
```

If you are using GitHub pages for hosting, this command is a convenient way to build the website and push to the `gh-pages` branch.

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
