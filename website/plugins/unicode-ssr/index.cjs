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

const path = require('node:path');

// React 18's Node pipeable stream can insert NULs between CJK characters.
// Limit the workaround to Docusaurus's server renderer; client React and
// dependency versions stay unchanged. Revisit when upgrading React/Docusaurus.
module.exports = function unicodeSSR() {
  return {
    name: 'unicode-ssr',
    configureWebpack(_config, isServer, {currentBundler}) {
      if (!isServer) return {};
      const original = require.resolve('@docusaurus/core/lib/client/renderToHtml.js');
      return {
        plugins: [
          new currentBundler.instance.NormalModuleReplacementPlugin(
            /renderToHtml(?:\.js)?$/,
            (resource) => {
              const requested = path.resolve(resource.context, resource.request);
              if (requested === original || `${requested}.js` === original) {
                resource.request = require.resolve('./renderToHtml.mjs');
              }
            },
          ),
        ],
      };
    },
  };
};
