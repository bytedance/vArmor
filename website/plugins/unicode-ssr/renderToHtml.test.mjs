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

import assert from 'node:assert/strict';
import test from 'node:test';
import React from 'react';
import {renderToString} from 'react-dom/server';
import {renderToHtml} from './renderToHtml.mjs';

test('preserves CJK text and anchors across streaming chunk boundaries', async () => {
  const app = React.createElement('main', null,
    Array.from({length: 300}, (_,i) => React.createElement('section', {key: i},
      React.createElement('h2', {id: `配置与验证-${i}`}, '配置与验证'),
      React.createElement('p', null, '这是用于验证中文静态文档输出的句子。'.repeat(3)),
      React.createElement('a', {href: `#配置与验证-${i}`}, '章节链接'),
    )),
  );
  const actual = await renderToHtml(app);
  assert.equal(actual.includes('\0'), false);
  assert.equal(actual, renderToString(app));
});
