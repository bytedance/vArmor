// Copyright 2026 vArmor Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const llms = require('docusaurus-plugin-llms').default;

const trimRoute = (route) => route.replace(/\/$/, '');
const sourcePath = (siteDir, source) => path.resolve(siteDir, source.replace(/^@site\//, ''));

// Preserve examples literally: transforms apply only outside Markdown fences.
function outsideFences(text, transform) {
  return text.split(/(^[ \t]*(`{3,}|~{3,})[^\n]*\n[\s\S]*?^[ \t]*\2[ \t]*(?:\n|$))/m)
    .filter((part, index) => index % 3 !== 2)
    .map((part, index) => index % 2 === 0 ? transform(part) : part).join('');
}

async function prepareDocument(doc, docs, context) {
  const file = sourcePath(context.siteDir, doc.source);
  let text = (await fs.readFile(file, 'utf8')).replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '');
  const imports = new Map();
  outsideFences(text, (body) => {
    for (const match of body.matchAll(/^import\s+(\w+)\s+from\s+['"](@site\/[^'"]+\?raw)['"];?\s*$/gm)) {
      imports.set(match[1], match[2]);
    }
    return body;
  });
  const raw = new Map();
  for (const [name, source] of imports) {
    const resolved = sourcePath(context.siteDir, source.replace(/\?raw$/, ''));
    if (!resolved.startsWith(path.join(context.siteDir, 'static') + path.sep)) {
      throw new Error(`Raw example must be under static/: ${source}`);
    }
    raw.set(name, await fs.readFile(resolved, 'utf8'));
  }
  text = outsideFences(text, (body) => body.replace(
    /<CodeBlock\b[^>]*>\s*\{(\w+)\}\s*<\/CodeBlock>/g,
    (_, name) => {
      if (!raw.has(name)) throw new Error(`Unresolved CodeBlock ${name} in ${file}`);
      const value = raw.get(name).trimEnd();
      const fence = '`'.repeat(Math.max(3, ...[...value.matchAll(/`+/g)].map(m => m[0].length + 1)));
      return `${fence}yaml\n${value}\n${fence}`;
    }));
  const bySource = new Map(docs.map(d => [sourcePath(context.siteDir, d.source), d]));
  const images = new Map();
  const imageRefs = [];
  outsideFences(text, body => {
    imageRefs.push(...[...body.matchAll(/!\[[^\]\n]*\]\(([^\s)]+)\)/g)].map(m => m[1]));
    return body;
  });
  for (const href of imageRefs) {
    if (/^(?:[a-z]+:|\/|#)/i.test(href)) continue;
    const data = await fs.readFile(path.resolve(path.dirname(file), href));
    const name = crypto.createHash('sha256').update(data).digest('hex').slice(0, 16) + path.extname(href);
    const dest = path.join(context.outDir, 'ai-assets', name);
    await fs.mkdir(path.dirname(dest), {recursive: true});
    await fs.writeFile(dest, data);
    images.set(href, context.siteConfig.url + context.siteConfig.baseUrl + 'ai-assets/' + name);
  }
  text = outsideFences(text, (body) => {
    body = body.replace(/^import\s+[^\n]+\s+from\s+['"][^'"]+['"];?\s*$/gm, '');
    body = body.replace(/<br\s*\/?>/gi, '; ');
    body = body.replace(/<ThemeImage\b[\s\S]*?\/>/g, (tag) => {
      const src = tag.match(/lightSrc="([^"]+)"/)?.[1];
      const alt = tag.match(/alt="([^"]*)"/)?.[1] || '';
      if (!src) throw new Error(`Missing ThemeImage source in ${file}`);
      return `![${alt}](${new URL(src, context.siteConfig.url).href})`;
    });
    body = body.replace(/<DocCardList\s*\/>/g, () => {
      const dir = path.dirname(file);
      return docs.filter(d => {
        const target = sourcePath(context.siteDir, d.source);
        return target !== file && (path.dirname(target) === dir ||
          (path.dirname(path.dirname(target)) === dir && /\/index\.mdx?$/.test(target)));
      }).map(d => `- [${d.title}](${context.siteConfig.url}${trimRoute(d.permalink)}.md)`).join('\n');
    });
    // Source-relative links must resolve against the source, not the output slug.
    return body.replace(/(!?\[[^\]\n]*\]\()([^\s)]+)(\))/g, (all, start, href, end) => {
      if (images.has(href)) return `${start}${images.get(href)}${end}`;
      if (/^(?:[a-z]+:|\/\/|#)/i.test(href)) return all;
      const [pathname, fragment] = href.split('#');
      const resolved = path.resolve(path.dirname(file), pathname);
      const target = [resolved, `${resolved}.md`, `${resolved}.mdx`, path.join(resolved, 'index.md')]
        .map(p => bySource.get(p)).find(Boolean);
      if (target) return `${start}${context.siteConfig.url}${trimRoute(target.permalink)}.md${fragment ? '#' + fragment : ''}${end}`;
      if (href.startsWith('/')) return `${start}${new URL(href, context.siteConfig.url).href}${end}`;
      return all;
    });
  });
  // Only metadata is authored here; the body always comes from existing docs.
  let removedTitle = false;
  text = outsideFences(text, body => body.replace(/^# [^\n]+\n/m, heading => {
    if (removedTitle) return heading;
    removedTitle = true;
    return '';
  }));
  const paragraphs = [];
  outsideFences(text, body => {
    paragraphs.push(...body.split(/\n\s*\n/).map(p => p.trim()));
    return body;
  });
  // Docusaurus may infer descriptions from explicit heading anchor IDs.
  // Prefer an authored description, otherwise use an actual prose paragraph.
  const description = (doc.frontMatter?.description ||
    paragraphs.find(p => /^[\p{L}\p{N}]/u.test(p) && !p.includes('|')) || doc.title)
    .replace(/<[^>]+>/g, '').replace(/!?\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/[`*_]/g, '').replace(/\s+/g, ' ').trim();
  const summary = !description || description.includes('|') ? doc.title : description;
  return `---\ntitle: ${JSON.stringify(doc.title)}\ndescription: ${JSON.stringify(summary)}\n---\n\n${text}`;
}

module.exports = function varmorLLMs(context) {
  let versions;
  return {
    name: 'varmor-llms',
    allContentLoaded({allContent}) {
      versions = allContent['docusaurus-plugin-content-docs'].default.loadedVersions;
    },
    async postBuild() {
      const locale = context.i18n.currentLocale;
      const selected = versions.filter(v => v.versionName === 'current' || v.versionName === 'v0.10');
      if (selected.length !== 2) throw new Error('Expected main and v0.10 documentation');
      const entries = [];
      for (const version of selected) {
        const name = version.versionName === 'current' ? 'main' : version.versionName;
        const docs = version.docs.filter(d => !d.draft && !d.unlisted);
        const scratch = path.join(context.generatedFilesDir, 'llms-sources', locale, name);
        await fs.rm(scratch, {recursive: true, force: true});
        await fs.mkdir(scratch, {recursive: true});
        const base = context.siteConfig.baseUrl;
        for (const doc of docs) {
          const relativeRoute = trimRoute(doc.permalink).slice(base.length);
          const dest = path.join(scratch, `${relativeRoute}.md`);
          await fs.mkdir(path.dirname(dest), {recursive: true});
          await fs.writeFile(dest, await prepareDocument(doc, docs, context));
        }
        const prefix = `docs/${name}`;
        await fs.mkdir(path.join(context.outDir, prefix), {recursive: true});
        const generator = llms(context, {
          docsDir: [{path: path.relative(context.siteDir, scratch), routeBasePath: '/'}],
          title: `vArmor ${name} (${locale})`,
          description: locale === 'zh-cn' ? 'vArmor 安装、强制访问控制器、策略、API 与排障文档。' : 'vArmor installation, enforcers, policies, API reference and troubleshooting.',
          version: name,
          rootContent: locale === 'zh-cn'
            ? (name === 'main' ? '开发版文档。已发布版本请优先阅读 v0.10 文档。' : 'v0.10 稳定版文档。请使用同一版本的示例与 API 参考。')
            : (name === 'main' ? 'Development documentation. Prefer v0.10 for released deployments.' : 'Stable v0.10 documentation. Keep examples and API references within this version.'),
          generateMarkdownFiles: true,
          generateLLMsFullTxt: false,
          llmsTxtFilename: `${prefix}/llms.txt`,
          excludeImports: true,
          includeOrder: ['**/introduction.md', '**/getting-started.md', '**/getting_started/**', '**/guides/enforcers.md', '**/guides/enforcers/networkproxy.md', '**/guides/enforcers/networkproxy/quick-start.md', '**/guides/enforcers/**'],
          logLevel: 'quiet',
        });
        await generator.postBuild();
        // Upstream logs individual conversion errors; make omissions fatal.
        for (const doc of docs) {
          await fs.access(path.join(context.outDir, trimRoute(doc.permalink).slice(base.length) + '.md'));
        }
        entries.push(`- [${name === 'main' ? 'main — development' : 'v0.10 — stable'}](${context.siteConfig.url}${base}${prefix}/llms.txt)`);
      }
      entries.sort((a, b) => Number(a.includes('main —')) - Number(b.includes('main —')));
      const languageLinks = ['- [English](https://www.varmor.org/llms.txt)', '- [简体中文](https://www.varmor.org/zh-cn/llms.txt)'];
      await fs.writeFile(path.join(context.outDir, 'llms.txt'), `# vArmor documentation\n\n> Official installation, policy, enforcer and API documentation.\n\nUse v0.10 for the current stable release. main describes development behavior. Follow links to individual Markdown pages; do not mix versions.\n\n## Versions\n\n${entries.join('\n')}\n\n## Languages\n\n${languageLinks.join('\n')}\n`);
    },
  };
};
module.exports.prepareDocument = prepareDocument;
module.exports.outsideFences = outsideFences;
