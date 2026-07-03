# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**fit-issuer** is a standalone Go service that issues and verifies Forensic Investigation Tokens (FIT) as defined in FSS-0008. It runs as a container on the same VPS as the MCP servers, reachable only within the `mcp-net` Podman network except for the Traefik-fronted public endpoint.

- **Repository**: `github.com/3soos3/fit-issuer`
- **Image**: `ghcr.io/3soos3/fit-issuer`
- **Port**: `:8090`
- **Tag format**: `F0008-vX.Y.Z` (X.Y = FSS-0008 standard version; Z = service patch)

## Commands

```sh
make build           # go build -o bin/fit-issuer ./cmd/fit-issuer
make test            # runs test-unit + test-integration
make test-unit       # go test ./tests/unit/... -race -count=1 -v
make test-integration # go test ./tests/integration/... -count=1 -v
make lint            # golangci-lint run ./...
make vet             # go vet ./...
make vuln            # govulncheck ./...
make image           # podman build -t fit-issuer:local .
make ci              # lint + vet + test
```

Run a single test:
```sh
go test ./tests/unit/... -run TestKeyGeneration -v
go test ./tests/integration/... -run TestPostFitLogin -v
```

## Architecture

### Package Dependency Order

Build packages in this order — each depends only on what's above it:

1. `internal/config` — env var loading, no external deps
2. `internal/toolmatch` — regexp matching + catch-all detection, no deps
3. `internal/profiles` — load `profiles.yaml`, merge logic; depends on `toolmatch`
4. `internal/keys` — Ed25519 keypair gen, persist/load, JWKS output, `kid` derivation; depends on `config`
5. `internal/revocation` — file-backed revoked JTI list, in-memory cache (5-min TTL); depends on `config`
6. `internal/tokens` — FIT JWT construction and signing; depends on `keys`, `toolmatch`
7. `internal/handlers` — HTTP handlers; depend on all of the above
8. `cmd/fit-issuer/main.go` — wires everything, starts server

### Key Design Decisions

**authorized_tools are Go regexp patterns** (not exact strings). Every pattern is anchored `^(?:pattern)$` at verify time. Catch-all patterns (`.*`, `.+`, `^.*$`) are rejected at issuance for all FIT types. Detection: reject if the compiled pattern matches both `""` and `"a"`.

**Two distinct invocation-type fields** — easy to confuse:
- `invocation_type`: the MCP server's own deployment setting (`MCP_INVOCATION_TYPE` env var on the MCP server, not on fit-issuer)
- `invocation_types_permitted`: the FIT claim set by the forensic authority, checked in Step 11 of `/fit/verify`

**FIT profiles** are defined in `/data/profiles.yaml`. The `public` profile is used exclusively by `POST /fit/login`. Other profiles are selectable via `POST /fit/issue` with `"profile": "<name>"`. Profile defaults are merged under request-body fields (explicit fields override defaults). Startup fails if `profiles.yaml` exists but is unparseable.

**Revocation** uses atomic writes (write to `.tmp`, then `rename`) to prevent corruption. The in-memory set is the hot path; the JSON file is reloaded on TTL expiry (≤5 min per FSS-0008 §10.2).

**Key identity** (`kid`) = RFC 7638 JWK thumbprint: `base64url(sha256(utf8(json_sorted({"crv":"Ed25519","kty":"OKP","x":"<x>"}))))`. Log the public key and `kid` at INFO level on startup — operators copy this into the deployment record.

### Endpoints Summary

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/fit/login` | Bearer Dex JWT | Auto-issue public FIT after OAuth login |
| `POST` | `/fit/issue` | Bearer `FIT_AUTHORITY_TOKEN` | Forensic authority manual issuance |
| `POST` | `/fit/revoke` | Bearer `FIT_AUTHORITY_TOKEN` | Revoke a FIT by `jti` |
| `POST` | `/fit/verify` | None | Verify a FIT (called by MCP server middleware) |
| `GET`  | `/.well-known/fss-jwks.json` | None | Public key discovery |
| `GET`  | `/health` | None | 503 if signing key unreadable |

### FSS-0008 §8.2 Verification Steps

`POST /fit/verify` runs 11 steps in order; first failure returns immediately with `failed_step`:

1. JOSE header `typ == "FIT+JWT"`
2. `iss` in trusted issuers
3. `kid` resolves in JWKS; key not retired
4. Ed25519 signature valid
5. `aud` includes `server_id`
6. `jti` not revoked (cache TTL ≤5 min)
7. `nbf ≤ now < exp` (30s clock skew allowed)
8. `investigation_id` matches FIT claim
9. At least one anchored pattern in `authorized_tools` matches `tool_name`
10. `client_identity` matches `authorized_analyst`
11. If `invocation_types_permitted` present: `invocation_type` must be in list

On success, return `{ "valid": true }` plus extracted claims for provenance stamping. On failure, log `event=FSS_AUTH_DENIED, failed_step, reason` — never log FIT content.

## Environment Variables

| Variable | Default / Example | Purpose |
|----------|-------------------|---------|
| `FIT_ISSUER_URL` | `https://iat.3soos3.online` | `iss` claim in all FITs |
| `FIT_JWKS_URL` | `https://iat.3soos3.online/.well-known/fss-jwks.json` | Written into deployment record |
| `OAUTH_JWKS_URL` | `https://auth.3soos3.online/keys` | Dex JWKS for `/fit/login` validation |
| `FIT_AUDIENCE` | comma-separated MCP server URLs | Valid `aud` values in issued FITs |
| `FIT_DEFAULT_VALIDITY_DAYS` | `30` | Token lifetime |
| `FIT_AUTHORITY_TOKEN` | `<secret>` | Bearer token for `/fit/issue` and `/fit/revoke` |
| `FIT_DATA_DIR` | `/data` | Volume-mounted dir for `signing_key.pem` and `revoked_jtis.json` |
| `FIT_PROFILES_CONFIG` | `/data/profiles.yaml` | Optional profiles config |

## Docker / Container

- Multi-stage: `golang:1.22-alpine` builder → `gcr.io/distroless/static` runtime
- Static binary only — no shell, no package manager; `/data` is the only writable volume
- `USER nonroot:nonroot` (uid 65532)
- `EXPOSE 8090`
- OCI build args: `VERSION`, `VCS_REF`, `BUILD_DATE`
- Expected image size: ~10–15 MB; startup: <100 ms

## CI/CD

- **`gate.yml`** — required on every PR: golangci-lint, go vet, unit tests (`-race`), integration tests, build check
- **`release.yml`** — triggered on `F0008-v*` tags: multi-arch build (amd64/arm64), push GHCR + Docker Hub, Trivy scan (fail on CRITICAL), cosign sign, Syft SBOM, Zenodo deposit
- **`security.yml`** — weekly: govulncheck, CodeQL, Trivy on `:latest`, OpenSSF Scorecard

All GitHub Actions must use pinned commit SHA hashes (no floating tags). Structured JSON logging via `log/slog` (stdlib).
