# Handsal MCP agent (example)

A reference MCP server (stdio) for the agent runtime side of Handsal. It holds an agent application's private key and gives the model one tool, `handsal_fetch`. The tool gets a short-lived access token from Handsal with `private_key_jwt`, waits for a human when a scope needs approval, calls the HTTP API with the token and returns only the HTTP response. Handsal never sees the private half of the key, and the model never sees the token: the access token, the client assertion and the private key never appear in a tool result, a log line or an error message.

## Prerequisites

- A Handsal tenant with a resource (for example `https://api.acme.io/invoices`) and its scopes.
- An application of kind `agent`, granted those scopes, with authentication method `private_key_jwt` and a registered public key (see [integration guide, section 5](../../docs/integration.md#5-authenticating-with-private_key_jwt)). Generate the key pair with:

  ```bash
  openssl ecparam -name prime256v1 -genkey -noout -out key.pem && openssl ec -in key.pem -pubout
  ```

  Register the printed public key and note its `kid`. `key.pem` stays with the runtime. SEC1 (`EC PRIVATE KEY`) and PKCS8 (`PRIVATE KEY`) PEM both work; only P-256 keys are accepted.
- Node 24 and a build of this package: `pnpm install && pnpm --filter @handsal/example-mcp-agent build`.

## Configuration

| Variable | Required | Description |
|---|---|---|
| `HANDSAL_TOKEN_ENDPOINT` | yes | The tenant's token endpoint, e.g. `http://localhost:3001/t/acme-payments/oauth/token`. Also the assertion's `aud`, so it must match Handsal's `PUBLIC_URL` exactly. |
| `HANDSAL_CLIENT_ID` | yes | The agent application's `client_id`. |
| `HANDSAL_KID` | yes | The `kid` of the registered public key. |
| `HANDSAL_PRIVATE_KEY_FILE` | yes | Path to the private key PEM. |
| `HANDSAL_APPROVAL_WAIT_SECONDS` | no (90) | How long one tool call waits for a human approval before answering "still waiting". |
| `HANDSAL_APPROVALS_URL` | no | Link to the tenant's Approvals page, included in the "waiting" message. |
| `HANDSAL_HTTP_TIMEOUT_SECONDS` | no (60) | Timeout of the API call, including reading the response. Token endpoint requests always time out after 15 s. |

A missing or invalid variable, an unreadable key file or a non-P-256 key stops the server at startup with exit code 1 and a message naming the variable.

### Claude Code

```bash
claude mcp add handsal-agent \
  -e HANDSAL_TOKEN_ENDPOINT=http://localhost:3001/t/acme-payments/oauth/token \
  -e HANDSAL_CLIENT_ID=app_x7k2... \
  -e HANDSAL_KID=key-2026-11 \
  -e HANDSAL_PRIVATE_KEY_FILE=/home/agent/.handsal/key.pem \
  -- node examples/mcp-agent/dist/index.js
```

### Claude Desktop

```json
{
  "mcpServers": {
    "handsal-agent": {
      "command": "node",
      "args": ["/path/to/handsal/examples/mcp-agent/dist/index.js"],
      "env": {
        "HANDSAL_TOKEN_ENDPOINT": "http://localhost:3001/t/acme-payments/oauth/token",
        "HANDSAL_CLIENT_ID": "app_x7k2...",
        "HANDSAL_KID": "key-2026-11",
        "HANDSAL_PRIVATE_KEY_FILE": "/home/agent/.handsal/key.pem",
        "HANDSAL_APPROVALS_URL": "https://auth.example.com/t/<tenantId>/approvals"
      }
    }
  }
}
```

## The tool

`handsal_fetch` takes `url`, `method` (`GET` by default), optional `body` and `content_type` (`application/json` by default when a body is sent), `resource` (the Handsal audience), `scope` (space-separated), `task_id` (1 to 128 characters of `A-Za-z0-9._:-`; passed to Handsal unchanged, so the admin UI groups the calls under one task), and optional `justification` and `actor_hint`, both shown to the human approver.

The `url` must be under `resource`: same scheme, host and port, and the same path or a path below it. Paths with encoded separators (`%2F`, `%5C`) or `..` segments are refused. A refused call never requests a token. Redirects are not followed, so the token is never sent anywhere else.

Ordinary tokens are cached in memory per resource, scope and `task_id` until 10 seconds before they expire; a different `task_id` or scope always gets its own token. A token obtained through a human approval is never cached: it is used for the one HTTP call that asked for it, and the next call needs a new approval. Identical calls running at the same time share one token request, so parallel calls cannot use up one approval.

### A normal call

The model calls:

```json
{"url":"https://api.acme.io/invoices/4411","resource":"https://api.acme.io/invoices","scope":"invoices:read","task_id":"refund-4411"}
```

The server signs an assertion, gets a token and calls the API. The model sees only:

```
HTTP 200 OK
content-type: application/json

{"id":4411,"amount":120.5,"status":"paid"}
```

The server stops reading bodies after 64 KiB and ends them with `[truncated]`. A Handsal refusal (`invalid_scope`, `unauthorized_client`, a `429` budget limit with "retry after N s", ...) comes back as an error result with the error code and description.

### An approval-gated call

The model calls with a scope whose agent policy is `approval`:

```json
{"url":"https://api.acme.io/invoices/4411/refund","method":"POST","body":"{\"amount\":120.5}","resource":"https://api.acme.io/invoices","scope":"invoices:refund","task_id":"refund-4411","justification":"Customer asked for a refund of order 4411","actor_hint":"jane@acme.example"}
```

Handsal answers `authorization_pending` and an approval card appears in the admin UI. The server polls for up to `HANDSAL_APPROVAL_WAIT_SECONDS`. A network error, `5xx` or `429` during polling is retried up to 3 times; after that, or if nobody decides in time, the model sees:

```
Waiting for human approval (approval_id 6f1c2c1e-...). Waited 90 s. A human must approve this request in the Handsal admin UI at https://auth.example.com/t/<tenantId>/approvals. Call handsal_fetch again with the same arguments to keep waiting; the request will not be duplicated.
```

Calling again with the same arguments resumes the same approval (Handsal returns the same `approval_id` for a repeated request). Once a human approves, the next poll returns the token and the model sees the response of the refund call, marked as approved:

```
HTTP 200 OK (sent with a human-approved token, valid for this call only)
content-type: application/json

{"id":4411,"status":"refunded"}
```

The approval covers this one call. Another refund, even with the same `task_id`, needs a new approval. If the human denies it, or nobody decides within 30 minutes, the model gets an error result (`access_denied` or `expired_token`) and has to start a new request.

## Security notes

- The key file must be readable only by the user that runs the server (`chmod 600 key.pem`). Anyone who can read it can act as the agent.
- If the agent application has `allowed_cidrs`, they must include the egress address of the machine running this server, or every token request fails with `unauthorized_client`.
- Tokens are cached in memory only and disappear when the process exits; expired entries are dropped. Nothing is written to disk and nothing is logged.
- Error text from the token endpoint is shortened to 300 characters and cleaned of tokens and client assertions before the model sees it.
