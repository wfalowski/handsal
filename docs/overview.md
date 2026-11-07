---
title: Documentation
description: How Handsal issues tokens, and how an API checks them.
---

# Documentation

Handsal is an authorization server. A service asks it for a token. Your API checks that token before it does the work.

- [Protect an API](/docs/sdk). `@handsal/sdk` does the check in Hono, Express, and Next.js. The article in the repository is `docs/sdk.md`.
- [Integration guide](https://github.com/wfalowski/handsal/blob/main/docs/integration.md). Requesting a token, the verification rules, private keys, agents, and delegation.
- [Deployment](https://github.com/wfalowski/handsal/blob/main/docs/deployment.md). The container, PostgreSQL, and the public URL.
- [Management API](https://github.com/wfalowski/handsal/blob/main/docs/api.md).
- [AI agents](https://github.com/wfalowski/handsal/blob/main/docs/agents.md).

These pages are the markdown files in `docs/`. The longer guides stay markdown too, and the links above open them.
