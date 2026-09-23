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
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {prepareDocument, outsideFences} = require('./index.cjs');

test('rewrites prose without modifying fenced YAML or code imports', () => {
  const input = 'before\n```yaml\nimport example from "sample";\n[link](index.md)\n```\nafter\n';
  assert.equal(outsideFences(input, s => s.replace(/before|after/g, 'changed')),
    'changed\n```yaml\nimport example from "sample";\n[link](index.md)\n```\nchanged\n');
});

test('expands canonical YAML and resolves translated links using real slugs', async () => {
  const siteDir = await fs.mkdtemp(path.join(os.tmpdir(), 'varmor-llms-'));
  try {
    await fs.mkdir(path.join(siteDir, 'docs'), {recursive: true});
    await fs.mkdir(path.join(siteDir, 'static'));
    const yaml = 'apiVersion: v1\nkind: Pod\n# [keep](index.md)\n';
    await fs.writeFile(path.join(siteDir, 'static/client.yaml'), yaml);
    await fs.writeFile(path.join(siteDir, 'docs/quick.mdx'), `---\ntitle: Tutorial\n---\nimport example from '@site/static/client.yaml?raw';\n<CodeBlock language="yaml">{example}</CodeBlock>\n[入门](index.md#start)\n\nIntroductory prose for the tutorial.\n\n| Field | Value |\n| --- | --- |\n| name<br />type | a<br/>b |\n<ThemeImage lightSrc="/img/demo.svg" alt="Diagram" />\n`);
    const doc = {source: '@site/docs/quick.mdx', title: '教程', description: 'quick-start-anchor}', permalink: '/zh-cn/docs/v0.10/quick'};
    const target = {source: '@site/docs/index.md', title: '入门', permalink: '/zh-cn/docs/v0.10/overview'};
    const result = await prepareDocument(doc, [doc, target], {siteDir, siteConfig: {url: 'https://www.varmor.org'}});
    assert.ok(result.includes('description: \"Introductory prose for the tutorial.\"'));
    assert.ok(!result.includes('quick-start-anchor}'));
    assert.ok(result.includes('| name; type | a; b |'));
    assert.ok(result.includes('```yaml\n' + yaml + '```'));
    assert.ok(result.includes('[入门](https://www.varmor.org/zh-cn/docs/v0.10/overview.md#start)'));
    assert.ok(result.includes('![Diagram](https://www.varmor.org/img/demo.svg)'));
    assert.ok(!result.includes('<CodeBlock') && !result.includes('import example'));
    await fs.writeFile(path.join(siteDir, 'docs/quick.mdx'), '<CodeBlock>{missing}</CodeBlock>');
    await assert.rejects(prepareDocument(doc, [doc], {siteDir, siteConfig: {url: 'https://www.varmor.org'}}), /Unresolved CodeBlock/);
  } finally {
    await fs.rm(siteDir, {recursive: true, force: true});
  }
});
