/// <reference types="astro/client" />

interface ImportMetaEnv {
  readonly SITE_GITHUB_URL?: string;
  readonly SITE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
