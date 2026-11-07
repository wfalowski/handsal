import { defineConfig } from "astro/config";

const site = process.env.SITE_URL;

export default defineConfig({
  output: "static",
  ...(site ? { site } : {}),
  i18n: {
    defaultLocale: "en",
    locales: ["en", "pl"],
    routing: {
      prefixDefaultLocale: false,
    },
  },
  markdown: {
    // Shiki paints tokens with style attributes, which the page CSP rejects.
    syntaxHighlight: false,
  },
  build: {
    inlineStylesheets: "never",
  },
  vite: {
    build: {
      assetsInlineLimit: 0,
    },
  },
});
