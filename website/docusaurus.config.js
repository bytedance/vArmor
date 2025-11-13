// @ts-check
// `@type` JSDoc annotations allow editor autocompletion and type checking
// (when paired with `@ts-check`).
// There are various equivalent ways to declare your Docusaurus config.
// See: https://docusaurus.io/docs/api/docusaurus-config

import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'vArmor',
  tagline: 'vArmor Documentation Site',
  favicon: 'img/favicon.ico',

  // Set the production url of your site here
  url: 'https://www.varmor.org',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'bytedance', // Usually your GitHub org/user name.
  projectName: 'vArmor', // Usually your repo name.

  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'warn',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en', 'zh-cn'],
    localeConfigs: {
      'en': {
        label: 'English',
      },
      'zh-cn': {
        label: '中文',
      },
    },
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          lastVersion: 'v0.9',
          versions: {
            current: {
              label: 'main',
              path: 'main',
              banner: 'unreleased',
            },
            'v0.6': {
              label: 'v0.6',
              path: 'v0.6',
              banner: 'unmaintained',
            },
            'v0.7': {
              label: 'v0.7',
              path: 'v0.7',
              banner: 'unmaintained',
            },
            'v0.8': {
              label: 'v0.8',
              path: 'v0.8',
              banner: 'none',
            },
            'v0.9': {
              label: 'v0.9',
              path: 'v0.9',
              banner: 'none',
            }
          },
          sidebarPath: './sidebars.js',
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: 'https://github.com/bytedance/vArmor/tree/main/website',
        },
        blog: {
          showReadingTime: true,
          feedOptions: {
            type: ['rss', 'atom'],
            xslt: true,
          },
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: 'https://github.com/bytedance/vArmor/tree/main/website',
          // Useful options to enforce blogging best practices
          onInlineTags: 'warn',
          onInlineAuthors: 'warn',
          onUntruncatedBlogPosts: 'warn',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      // Replace with your project's social card
      image: 'img/docusaurus-social-card.jpg',
      algolia: {
        // The application ID provided by Algolia
        appId: 'MDINZ25Y9F',

        // Public API key: it is safe to commit it
        apiKey: '8e6b02b9a17a365e906d6d84c5059cc2',

        indexName: 'varmor',

        // Optional: see doc section below
        contextualSearch: true,


        // // Optional: Replace parts of the item URLs from Algolia. Useful when using the same search index for multiple deployments using a different baseUrl. You can use regexp or string in the `from` param. For example: localhost:3000 vs myCompany.com/docs
        // replaceSearchResultPathname: {
        //   from: '/docs/', // or as RegExp: /\/docs\//
        //   to: '/',
        // },

        // Optional: Algolia search parameters
        searchParameters: {},

        // Optional: path for search page that enabled by default (`false` to disable it)
        searchPagePath: 'search',

        // Optional: whether the insights feature is enabled or not on Docsearch (`false` by default)
        insights: false,

        //... other Algolia params
      },
      navbar: {
        title: 'vArmor',
        logo: {
          alt: 'vArmor Logo',
          src: 'img/logo.svg',
        },
        items: [
          {
            to: 'index.html', 
            label: 'About', 
            position: 'right'
          },
          {
            type: 'docSidebar',
            sidebarId: 'tutorialSidebar',
            position: 'right',
            label: 'Documentation',
          },
          {
            to: '/blog', 
            label: 'Blog', 
            position: 'right'
          },
          {
            type: 'docsVersionDropdown',
            position: 'right',
            dropdownActiveClassDisabled: true,
          },
          {
            type: 'localeDropdown',
            position: 'right',
          },
          {
            href: 'https://github.com/bytedance/vArmor',
            position: 'right',
            className: 'header-github-link',
            'aria-label': 'GitHub repository',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Community',
            items: [
              {
                label: 'Lark Group',
                href: 'https://applink.larkoffice.com/client/chat/chatter/add_by_link?link_token=ae5pfb2d-f8a4-4f0b-b12e-15f24fdaeb24&qr_code=true'
              }
            ],
          },
          {
            title: 'More',
            items: [
              {
                label: 'GitHub',
                href: 'https://github.com/bytedance/vArmor',
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} vArmor Project.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
      },
    }),
    plugins: [
      [
        'vercel-analytics',
        {
          debug: true,
          mode: 'auto',
        },
      ],
    ],
};

export default config;
