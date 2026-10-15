# Fly.io MCP gateway

A remote, OAuth-protected [Model Context Protocol](https://modelcontextprotocol.io/) gateway for Fly.io. Each user connects their own Fly account through OAuth; the gateway holds no shared Fly credential.

The gateway implements MCP and Fly API calls in one Go process. There is no `flyctl` subprocess, loopback proxy, CLI configuration, or shared Fly management credential. It reuses Fly's MCP metadata and fly-go API types, not CLI builders or SDK HTTP clients. See [source provenance and regeneration](third_party/README.md).

```text
MCP client ──OAuth + PKCE──▶ gateway with in-process MCP ──▶ Fly APIs
                              │
                              └── no database or persisted user credentials
```

## Native management tools

All 60 names from the [upstream catalog](https://github.com/superfly/flyctl/tree/95b7f3e777a4c685599b6b75cfcfc0d8cbbd9fd9/internal/command/mcp/server) are registered with native handlers:

| Group | Count | Operations |
| --- | ---: | --- |
| Apps | 6 | Create, destroy, list, move, releases, restart |
| Machines | 20 | Create/run, clone, update, list/status, exec, lifecycle, cordon/upcordon, leases, egress IPs |
| Volumes | 9 | Create, destroy, extend, fork, list/show, update, snapshots |
| Certificates | 5 | Add, check, list, remove, show |
| IPs | 5 | Allocate IPv4/IPv6, list, private addresses, release |
| Organizations | 6 | Create, delete, invite, list, remove member, show |
| Secrets | 4 | Stage set/unset, list metadata, deploy |
| Platform | 3 | Regions, status, VM sizes |
| Logs/status | 2 | Bounded log retrieval, app status |

MCP is stateless. Every call uses the authenticated caller's request context; arguments cannot supply credentials or endpoints. There is no environment or local-login fallback. Calls use the public Machines API (`https://api.machines.dev`), Fly GraphQL (`https://api.fly.io/graphql`), Fly's log API, and public platform status. Redirects and automatic mutation retries are disabled. Failed writes can have partial or unknown outcomes: inspect resource state before retrying. Multi-resource operations return completed work where available. Machine updates preserve omitted configuration fields and use leases and current-version checks. Machine listings omit configuration; explicit status `display-config` and exec may return sensitive workload data to the caller. Secret tools return metadata, not stored values.

Hosted differences from the CLI:

- App-scoped tools require an explicit app; there is no local `fly.toml`, shell, interactive picker, or image build. Machine create/run accepts a published image. Custom create IDs and `use-zstd=true` fail before writes.
- `fly-machine-upcordon` retains the upstream spelling and invokes the uncordon API.
- Secrets set/unset stage changes; `fly-secrets-deploy` updates managed Machines using their existing configuration, retaining stopped state. App restarts are rolling and health-checked unless explicitly skipped.
- Logs return at most five pages / 500 entries and indicate truncation; releases return the latest 25 with a conservative truncation flag. Long operations are bounded to five minutes, Machine leases to four minutes of work.
- Moving apps with statics is rejected before mutation: copying their Tigris bucket needs separate S3 authority. This service does not acquire or simulate that authority.

Local protocol tests do not establish live access to every resource or write operation. Test real OAuth and tools against a dedicated, disposable Fly account; account billing/quota can prevent creation of app/Machine fixtures. Do not use production resources for destructive acceptance tests.

## Credential model

**The tools can mutate resources and account state using the caller's Fly permissions, not an organization boundary chosen by the operator.** These operations can incur charges, interrupt services, permanently delete data, and execute commands on Machines. The gateway discovers the user's organizations instead of selecting a fixed organization. The Fly organization hosting the gateway does not restrict those permissions.

OAuth authorization starts a Fly login immediately, without a separate gateway confirmation. Each user opens Fly's approval, then returns its one-time completion code in the original gateway tab. Any additional approval required by Fly remains mandatory. The gateway:

1. redeems the completion code with its own S256 PKCE verifier, independently of the MCP client's PKCE exchange;
2. selects exactly one `fo1` credential from the returned bundle, rejecting missing or ambiguous OAuth credentials and discarding all permission/discharge macaroons;
3. verifies the selected credential with Fly's read-only `viewer { id }` query, requiring a valid identity and no GraphQL errors;
4. uses `fo1` to discover all organization pages and create a `deploy_organization` API token for each membership with a requested `10m` expiry, following Fly CLI's token-minting API;
5. acquires missing authentication discharges, keeping the browser on the gateway for any additional Fly approval; and
6. retains the completed management grant and unchanged `fo1` encrypted in memory, returning a short, random, one-time authorization code. The client's code exchange retrieves and rechecks that grant rather than minting another one.

Before issuing OAuth tokens, the gateway checks the complete management bundle with `apps(first: 1)`. This can return an empty list and is not proof of access to a known app. Access tokens contain that bundle plus `fo1`. Organization listing uses `fo1`; app listing uses the complete GraphQL bundle; Machines receives only the management macaroons. These headers are selected directly in the gateway, without CLI pruning, implicit token acquisition or refresh during tool calls. Refresh tokens retain only `fo1`, not the expiring management bundle. All wrappers use authenticated AES-256-GCM encryption and are stored by the MCP client.

Discharge acquisition supports only Fly's exact HTTPS authentication issuers, `https://auth.fly.io` and `https://api.fly.io/aaa/v1`, with same-issuer polling. Unsupported issuers fail closed. A returned discharge must match the requested ticket and issuer and cannot replace the minted permissions or `fo1`. All counted tickets must have matching discharges before GraphQL verification. Structural matching is not cryptographic authorization: Fly still verifies the credential on API requests. No third-party policy opt-outs are requested. The gateway's Fly HTTP client does not follow redirects. Each request is bounded to 12 seconds and each management acquisition/approval submission to 45 seconds. Discovery, partial minting, malformed/oversized bundles, or verification failures issue no OAuth tokens; already-created Fly tokens expire naturally, rather than being silently reused or automatically revoked. Live acceptance for actual MCP operations still requires testing with a consenting user; even management GraphQL verification does not prove every Machines operation succeeds.

The service has no credential database. Its only secret is a random 32-byte `TOKEN_ENCRYPTION_KEY` stored with Fly Secrets. The `fo1` exists in request memory and inside the client's encrypted tokens, not on the service's disk. Pending authorization state is sealed, served with `Cache-Control: no-store`, and bound to an HttpOnly browser cookie, same-origin POSTs, and one-time login IDs. Clients use exact registered callbacks; there is no legacy CLI-session polling fallback.

Access tokens expire at most **9 minutes from the start of management minting**, including time spent approving. Parsed permission/discharge expiries can shorten that deadline further, leaving one minute for in-flight work. Every refresh rediscovers current memberships, mints a fresh set, completes non-interactive discharges, and verifies it; tool calls themselves do not mint tokens. A failed renewal, including a requirement for another browser approval, revokes the local connection and requires reconnecting, rather than retaining old authority. A single organization refusing a token fails the exchange instead of silently giving partial access.

Access and refresh tokens share a **30-day local connection deadline**; this is not a claim about the opaque `fo1` credential's expiry. Fly may expire or revoke it earlier. Refresh never renews `fo1` itself or extends the original deadline. Reconnect when the connection expires or Fly rejects the credential. Rotating the encryption key signs every user out immediately. Disconnecting does not revoke the login or already-issued management tokens at Fly; the latter expire after their short lifetime. Tokens created by earlier versions are not deleted automatically.

Refresh tokens rotate on every use. Reusing one revokes that connection's access tokens and subsequent refresh tokens. Grant IDs, token hashes, expiry times, and encrypted pending authorization-code payloads are retained in memory. **Restarting or deploying the gateway signs users out**, so they must reconnect their MCP client; replay protection never silently resets to accepting old tokens. This is a single-Machine design, not a persistent OAuth service.

OAuth authorization code flow uses S256 PKCE, exact redirect URI matching, short-lived single-use codes, RFC 8414 authorization-server metadata, RFC 9728 protected-resource metadata, and RFC 7591 dynamic client registration. Dynamic client records are sealed and stateless.

Authorization codes contain 144 random bits encoded as 24 URL-safe characters, independent of the credential bundle size. Their encrypted payloads are indexed by the code's hash, expire after at most five minutes (or the management deadline, if earlier), and are deleted on redemption or expiry cleanup. Invalid client or PKCE attempts do not consume a valid code. This avoids large callback URLs.

Raw upstream errors, result bodies, and credentials are not forwarded to shared logs. Administrators who can inspect the gateway Machine remain trusted; do not treat this service as isolating credentials from its infrastructure administrators.

Gateway authorization diagnostics log fixed stage names, HTTP statuses, decode outcomes, OAuth credential counts, GraphQL error counts/categories, and acceptance booleans. They never log raw upstream bodies or errors, headers, URLs, completion codes, tokens, organization IDs, or user identifiers. Error categories are heuristic summaries, not a definitive Fly diagnosis. Inspect `login_start`, `login_redeem`, `credential_parse`, `login_verification`, `login_complete`, `management_organizations`, `management_mint`, `management_verification`, and `oauth_tokens_issued` events with `fly logs --app <app>`. GraphQL stage acceptance means valid response data without GraphQL errors; the enclosing exchange also validates required fields before issuing tokens.

`authorization_redirect` records only code length and whether state is present when constructing the callback redirect. It does not prove that the client received or accepted the redirect.

After minting and successful discharge completion, `management_structure` records whether Fly's macaroon parser decoded the bundle and, if so, counts permission tokens, discharge tokens (including unrelated ones), and third-party tickets without a matching discharge. It logs no ticket data or issuer locations. This diagnostic is an unverified structural check, not signature, expiry, binding, or resource-authorization verification; zero missing tickets does not prove usable access. Parse failures report no counts rather than suggesting that nothing is missing. `management_discharge` records request method/status or a fixed unsupported-issuer reason, never ticket contents, approval URLs, or response bodies.

Direct tool requests have fixed stages `mcp_organizations`, `mcp_app_organization`, `mcp_apps`, and `mcp_machines`. An upstream failure is returned as an MCP tool error with a safe description, rather than a truncated CLI query or a successful empty result.

## Deploy

Edit [`fly.toml`](fly.toml): choose a unique app name and region, set `PUBLIC_BASE_URL` to the app's public HTTPS origin, and set `OAUTH_REDIRECT_URIS` to the exact callback URLs of the MCP clients you allow. Create the app once, set its encryption key without printing it, then deploy:

```bash
fly apps create my-fly-mcp --org <your-org>

key="$(openssl rand -base64 32)"
printf 'TOKEN_ENCRYPTION_KEY=%s\n' "$key" | fly secrets import --app my-fly-mcp
unset key

fly deploy --remote-only --yes --ha=false
curl --fail https://my-fly-mcp.fly.dev/healthz
```

Keep this deployment at one Machine. OAuth grant state is process-local; requests cannot be distributed across multiple gateway processes. MCP itself is stateless. The Fly configuration keeps the Machine running and uses rolling deploys.

Registration and authorization require an exact match with one of `OAUTH_REDIRECT_URIS`; other hosts, loopback ports and paths are not implicitly allowed. List only the callbacks of clients you trust to receive users' Fly-backed tokens.

For continuous deployment, create an app-scoped deploy token, store it as `FLY_API_TOKEN` in your CI system's secret store, and run `mise run check` followed by `mise run deploy`:

```bash
fly tokens create deploy --app my-fly-mcp --name "fly-mcp deploy" --expiry 8760h
```

Do not set `FLY_API_TOKEN` as a Fly app secret. It belongs only in the deployment environment; the running gateway does not use ambient Fly credentials.

## Connect an MCP client

Add `https://my-fly-mcp.fly.dev/mcp` as a remote MCP server with OAuth authentication. Clients discover the authorization server from the protected-resource metadata and register themselves dynamically; no OAuth client secret is shared. The client's callback URL must be listed in `OAUTH_REDIRECT_URIS`.

The browser page asks for permission to use management tools and create and renew short-lived management tokens across all of your organizations. Open Fly approval in a new tab and paste the completion code back into the gateway page—not into a chat. If the gateway then offers **Open required Fly approval**, complete it in the new tab, return, and choose **Check approval**. The client is not connected until management acquisition and verification succeed and the browser returns to the client's callback. Each user's OAuth session is separate and refreshes only within the original local connection deadline.

## Development

Install the pinned tools with [mise](https://mise.jdx.dev/), then run the checks:

```bash
mise install
mise run check
```

The tests exercise OAuth through an actual in-process MCP tool call, all 60 names over HTTP, API pagination, per-caller read/write isolation, header selection, native API protocols, configuration preservation, and safe upstream failures. They use local Fly API fixtures and no real credentials. With `agent-browser` and Chromium installed, run the optional authorization-page browser test:

```bash
BROWSER_TEST=1 go test -run TestOAuthBrowserRedirect ./internal/gateway
```

To run the complete service locally, provide a development encryption key:

```bash
export TOKEN_ENCRYPTION_KEY="$(openssl rand -base64 32)"
export OAUTH_REDIRECT_URIS=http://localhost:8976/oauth/callback
go run ./cmd/fly-mcp
```

Connect to `http://localhost:8080/mcp` from a client whose callback is listed in `OAUTH_REDIRECT_URIS`. The gateway requires an explicit user-approved Fly login and never falls back to a local `flyctl` login. Automated tests use synthetic `fo1` credentials and local verification responses; live login and an actual MCP call must also be tested with a consenting user and a disposable Fly account before relying on the integration.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `TOKEN_ENCRYPTION_KEY` | required | Base64-encoded random 32-byte AES key; set through Fly Secrets. Rotating it signs every user out |
| `OAUTH_REDIRECT_URIS` | required | Space-separated exact approved OAuth client callback URLs; no wildcards or implicit loopback exceptions |
| `PUBLIC_BASE_URL` | `http://localhost:$PORT` | Canonical HTTPS issuer and MCP resource origin |
| `PORT` | `8080` | Public gateway port |
| `FLY_GRAPHQL_URL` | `https://api.fly.io/graphql` | Fly GraphQL endpoint; override only for testing |

`PUBLIC_BASE_URL` must use HTTPS except on loopback. There is no separate backend listener. `flyctl` is needed only by deployment commands, not to build, test, or run the service.

## License

[MIT](LICENSE). `internal/gateway/tool_catalog.json` contains metadata derived from flyctl under Apache-2.0; see [third_party](third_party/README.md).
