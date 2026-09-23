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
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const {outsideFences} = require('../plugins/llms/index.cjs');
const site = path.resolve(__dirname, '..');
const build = path.join(site, 'build');
const prefixes = ['docs/main', 'docs/v0.10', 'zh-cn/docs/main', 'zh-cn/docs/v0.10'];
let pages = 0, links = 0;
function checkLinks(text, route) {
  outsideFences(text, body => {
    for (const match of body.matchAll(/!?\[[^\]\n]*\]\(([^\s)]+)\)/g)) {
      const url = new URL(match[1], 'https://www.varmor.org/' + route);
      if (url.hostname !== 'www.varmor.org') continue;
      const file = path.join(build, decodeURIComponent(url.pathname));
      assert.ok([file, file + '.html', path.join(file, 'index.html')].some(p => fs.existsSync(p)), `${route}: missing ${match[1]}`);
      links++;
    }
    return body;
  });
}
for (const prefix of prefixes) {
  const files = fs.readdirSync(path.join(build, prefix), {recursive: true});
  const markdown = files.filter(f => f.endsWith('.md'));
  const html = files.filter(f => f.endsWith('.html'));
  assert.equal(markdown.length, html.length, `${prefix}: Markdown/HTML page count`);
  const index = fs.readFileSync(path.join(build, prefix, 'llms.txt'), 'utf8');
  assert.ok(!/: [a-z0-9-]+}\s*$/m.test(index), `${prefix}: heading ID leaked into index summary`);
  checkLinks(index, prefix + '/llms.txt');
  for (const match of index.matchAll(/^- \[.*?\]\((https:\/\/www.varmor.org[^)]+)\)/gm)) {
    assert.ok(new URL(match[1]).pathname.startsWith('/' + prefix + '/'), `${prefix}: version/locale leak`);
  }
  for (const file of markdown) {
    const text = fs.readFileSync(path.join(build, prefix, file), 'utf8');
    assert.ok(!/^> [a-z0-9-]+}\s*$/m.test(text), `${file}: heading ID leaked into summary`);
    assert.ok(!text.includes('\0'), `${file}: NUL`);
    outsideFences(text, body => {
      assert.ok(!/<(?:CodeBlock|ThemeImage|DocCardList)\b|^import\s.+from\s/m.test(body), `${file}: unresolved MDX`);
      return body;
    });
    checkLinks(text, prefix + '/' + file);
    pages++;
  }
  const tutorial = fs.readFileSync(path.join(build, prefix, 'guides/enforcers/networkproxy/quick-start.md'), 'utf8');
  for (const example of ['backend', 'policy', 'client']) {
    const yaml = fs.readFileSync(path.join(site, 'static/examples/networkproxy/v0.10.5', example + '.yaml'), 'utf8').trimEnd();
    assert.ok(tutorial.includes('```yaml\n' + yaml + '\n```'), `${prefix}: ${example}.yaml differs from canonical example`);
  }
}
for (const route of ['llms.txt', 'zh-cn/llms.txt']) checkLinks(fs.readFileSync(path.join(build, route), 'utf8'), route);
console.log(JSON.stringify({markdownPagesChecked: pages, localLinksChecked: links, guideVariants: prefixes.length, errors: []}, null, 2));
