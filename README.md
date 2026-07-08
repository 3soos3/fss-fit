# fit-issuer

A standalone Go service that issues and verifies **Forensic Investigation Tokens (FIT)** as defined in FSS-0006. FITs are signed JWTs that authorize a named analyst to call specific MCP tools for a specific investigation — carrying the legal authority, purpose, and tool-scope of the forensic engagement.

- **Image**: `ghcr.io/3soos3/fit-issuer`
- **Port**: `:8090`
- **Tag format**: `F0006-vX.Y.Z` (X.Y = FSS-0006 standard version; Z = service patch)

---

## How it works

A FIT is a `FIT+JWT` signed with Ed25519. It binds together:

| Claim | Example |
|---|---|
| `investigation_id` | `550e8400-e29b-41d4-a716-446655440000` |
| `authorized_analyst` | `analyst@example.org` |
| `authorized_tools` | `["search_technique", "get_.*"]` (Go regexps) |
| `legal_authority` | `CASE-2026-0042` |
| `purpose` | `Identify malware persistence techniques` |
| `aud` | MCP server URL(s) |

When an MCP server receives a tool call, its middleware calls `POST /fit/verify` with the FIT, the tool name, the caller identity, and the server ID. The verifier runs 11 checks (FSS-0006 §8.2) in order and returns `{"valid": true}` plus extracted claims, or the failed step and reason.

---

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/fit/login` | Bearer OIDC JWT | Auto-issue `public` profile FIT after OAuth login |
| `POST` | `/fit/issue` | Bearer `FIT_AUTHORITY_TOKEN` | Forensic authority manual issuance |
| `POST` | `/fit/revoke` | Bearer `FIT_AUTHORITY_TOKEN` | Revoke a FIT by `jti` |
| `POST` | `/fit/verify` | None | Verify a FIT (called by MCP server middleware) |
| `GET`  | `/.well-known/fss-jwks.json` | None | Public key discovery |
| `GET`  | `/health` | None | 503 if signing key unreadable |

### POST /fit/login

Present a valid OIDC Bearer token (from your configured provider — Dex, Keycloak, etc.). Returns a FIT scoped to the `public` profile.

```sh
curl -X POST https://iat.3soos3.online/fit/login \
  -H "Authorization: Bearer <oidc-token>"
```

### POST /fit/issue

Forensic authority issues a FIT with explicit scope. All fields except `data_scope`, `invocation_types_permitted`, `supervisor`, and `classification` are required.

```sh
curl -X POST https://iat.3soos3.online/fit/issue \
  -H "Authorization: Bearer <FIT_AUTHORITY_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "investigation_id": "550e8400-e29b-41d4-a716-446655440000",
    "authorized_analyst": "analyst@example.org",
    "authorized_tools": ["search_technique", "get_technique"],
    "legal_authority": "CASE-2026-0042",
    "purpose": "Identify malware persistence techniques"
  }'
```

A `profile` field can be included to load defaults from `profiles.yaml`; explicit fields override profile defaults.

### POST /fit/verify

Called by MCP server middleware — not by end users.

```json
{
  "fit": "<compact FIT+JWT>",
  "server_id": "https://mcp.example.org/solve-it",
  "tool_name": "search_technique",
  "client_identity": "analyst@example.org",
  "investigation_id": "550e8400-e29b-41d4-a716-446655440000",
  "invocation_type": "human_direct"
}
```

Success: `{"valid": true, "investigation_id": "...", "authorized_analyst": "...", ...}`

Failure: `{"valid": false, "failed_step": 5, "reason": "aud mismatch"}`

### POST /fit/revoke

```sh
curl -X POST https://iat.3soos3.online/fit/revoke \
  -H "Authorization: Bearer <FIT_AUTHORITY_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"jti": "770a0600-e29b-41d4-a716-446655440002"}'
```

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `FIT_ISSUER_URL` | *(required)* | `iss` claim in all FITs |
| `FIT_JWKS_URL` | *(required)* | Written into deployment record |
| `OAUTH_JWKS_URL` | *(required)* | OIDC provider JWKS for `/fit/login` |
| `OAUTH_ISSUER_URL` | derived from JWKS URL | OIDC `iss` for token validation |
| `FIT_AUDIENCE` | *(required)* | Comma-separated MCP server URLs |
| `FIT_AUTHORITY_TOKEN` | *(required)* | Bearer secret for issue/revoke |
| `FIT_DATA_DIR` | `/data` | Dir for `signing_key.pem` and `revoked_jtis.json` |
| `FIT_DEFAULT_VALIDITY_DAYS` | `30` | Token lifetime |
| `FIT_PROFILES_CONFIG` | `$FIT_DATA_DIR/profiles.yaml` | Optional profiles config |

`OAUTH_ISSUER_URL` should be set explicitly when using Keycloak or any provider whose JWKS path doesn't end in `/keys` or `/jwks` (e.g. `https://keycloak.example.org/realms/myrealm`).

---

## Profiles

`profiles.yaml` lets you define named sets of defaults for `POST /fit/issue`. The special `public` profile drives `POST /fit/login`.

```yaml
public:
  validity_days: 7
  authorized_tools:
    - "list_techniques"
    - "search_technique"
  purpose: "Public read-only access"
  invocation_types_permitted:
    - "human_direct"

investigation:
  validity_days: 30
  authorized_tools:
    - "search_technique"
    - "get_technique"
    - "get_case_.*"
```

Startup fails if the file exists but cannot be parsed.

---

## Running

### With Podman

```sh
podman run -d \
  --name fit-issuer \
  --network mcp-net \
  -p 8090:8090 \
  -v fit-data:/data \
  -e FIT_ISSUER_URL=https://iat.3soos3.online \
  -e FIT_JWKS_URL=https://iat.3soos3.online/.well-known/fss-jwks.json \
  -e OAUTH_JWKS_URL=https://auth.3soos3.online/keys \
  -e FIT_AUDIENCE=https://mcp.3soos3.online/solve-it \
  -e FIT_AUTHORITY_TOKEN=<secret> \
  ghcr.io/3soos3/fit-issuer:latest
```

### Build locally

```sh
make image          # podman build -t fit-issuer:local .
make build          # go build -o bin/fit-issuer ./cmd/fit-issuer
```

---

## Development

**Requirements**: Go 1.22, Podman (for image builds)

```sh
make test           # unit + integration tests
make test-unit      # go test ./internal/... -race -count=1 -v
make test-integration
make lint           # golangci-lint
make vet            # go vet
make vuln           # govulncheck
make ci             # vet + test
```

Run a single test:

```sh
go test ./internal/... -run TestKeyGeneration -v
go test ./tests/integration/... -run TestPostFitLogin -v
```

---

## Key management

On first start, an Ed25519 keypair is generated and written to `$FIT_DATA_DIR/signing_key.pem`. The `kid` (RFC 7638 JWK thumbprint) and public key are logged at INFO level — copy these into your deployment record. Key rotation requires a restart with a new key file; the old `kid` will no longer resolve in JWKS.

---

## Security notes

- **`authorized_tools` are Go regexp patterns**, anchored `^(?:pattern)$` at verify time. Catch-all patterns (`.*`, `.+`) are rejected at issuance.
- **Revocation** uses atomic file writes (write to `.tmp`, rename). The in-memory set is the hot path; the JSON file is reloaded on a ≤5-minute TTL per FSS-0006 §10.2.
- `POST /fit/verify` failures log `event=FSS_AUTH_DENIED` with `failed_step` and `reason` — FIT content is never logged.
- The container runs as `nonroot:nonroot` (uid 65532) on a distroless base; `/data` is the only writable volume.

---

## CI/CD

| Workflow | Trigger | What it does |
|---|---|---|
| `gate.yml` | Every PR | golangci-lint, go vet, unit tests (`-race`), integration tests, build check |
| `release.yml` | `F0006-v*` tag | Multi-arch build (amd64/arm64), push GHCR + Docker Hub, Trivy scan (fail on CRITICAL), cosign sign, Syft SBOM, Zenodo deposit |
| `security.yml` | Weekly | govulncheck, CodeQL, Trivy on `:latest`, OpenSSF Scorecard |

All GitHub Actions use pinned commit SHA hashes.
