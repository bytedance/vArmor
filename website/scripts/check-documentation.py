#!/usr/bin/env python3
# Copyright 2026 vArmor Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Check built current/stable docs, locale parity and tutorial source imports.

Run after `yarn build`: python3 scripts/check-documentation.py
Uses only the Python standard library. Does not contact external sites.
"""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit
import json
import re


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.ids = set()
        self.links = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            self.ids.add(attrs['id'])
        if tag == 'a' and attrs.get('href'):
            self.links.append(attrs['href'])


def main():
    site = Path(__file__).resolve().parents[1]
    build = site / 'build'
    prefixes = ['/docs/main/', '/docs/v0.10/',
                '/zh-cn/docs/main/', '/zh-cn/docs/v0.10/']
    errors = []
    cache = {}
    checked = 0

    def target_file(path):
        candidate = build / unquote(path).lstrip('/')
        for p in (candidate, candidate / 'index.html',
                  Path(str(candidate) + '.html')):
            if p.is_file():
                return p
        return None

    def read_page(path):
        if path not in cache:
            source = path.read_text()
            if '\x00' in source:
                errors.append(f'NUL characters in generated HTML: {path.relative_to(build)}')
            cache[path] = Page(source)
        return cache[path]

    for prefix in prefixes:
        pages = sorted((build / prefix.lstrip('/')).rglob('*.html'))
        if not pages:
            errors.append(f'Missing built docs: {prefix}')
        for file in pages:
            checked += 1
            route = '/' + str(file.relative_to(build)).removesuffix('index.html')
            if route.endswith('.html'):
                route = route[:-5]
            page = read_page(file)
            for href in page.links:
                url = urlsplit(urljoin('https://documentation.invalid' + route, href))
                if url.netloc != 'documentation.invalid' or url.scheme != 'https':
                    continue
                target = target_file(url.path)
                if not target:
                    errors.append(f'{route}: missing target {href}')
                elif url.fragment and target.suffix == '.html':
                    if unquote(url.fragment) not in read_page(target).ids:
                        errors.append(f'{route}: missing anchor {href}')

    roots = [site / 'docs', site / 'versioned_docs/version-v0.10',
             site / 'i18n/zh-cn/docusaurus-plugin-content-docs/current',
             site / 'i18n/zh-cn/docusaurus-plugin-content-docs/version-v0.10']
    relative = Path('guides/enforcers/networkproxy')
    expected = {p.name for p in (roots[0] / relative).iterdir() if p.is_file()}
    if len(expected) != 8:
        errors.append('Expected eight NetworkProxy guide pages')
    for root in roots:
        names = {p.name for p in (root / relative).iterdir() if p.is_file()}
        if names != expected:
            errors.append(f'Guide page mismatch: {root}')
        for name in expected:
            canonical = (roots[0] / relative / name).read_text()
            translated = (root / relative / name).read_text()
            fences = lambda s: re.findall(r'```[^\n]*\n(.*?)```', s, re.S)
            if fences(canonical) != fences(translated):
                errors.append(f'Code example mismatch: {root / relative / name}')
        quick_start = (root / relative / 'quick-start.mdx').read_text()
        for name in ['backend', 'policy', 'client']:
            source = f'static/examples/networkproxy/v0.10.5/{name}.yaml'
            if f"@site/{source}?raw" not in quick_start or not (site / source).is_file():
                errors.append(f'Missing canonical YAML import: {root}, {name}')

    print(json.dumps({'builtPagesChecked': checked, 'guideVariants': len(roots),
                      'errors': errors}, ensure_ascii=False, indent=2))
    raise SystemExit(bool(errors))


if __name__ == '__main__':
    main()
