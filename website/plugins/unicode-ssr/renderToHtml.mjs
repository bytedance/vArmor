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

import {renderToReadableStream} from 'react-dom/server.browser';
import {text} from 'node:stream/consumers';

// Use React's Web Stream renderer to avoid the React 18 pipeable-stream bug:
// https://github.com/react/react/issues/31134
export async function renderToHtml(app) {
  const stream = await renderToReadableStream(app);
  await stream.allReady;
  return text(stream);
}
