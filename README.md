# vault-secrets-broker

> **A proof of concept demonstrating genuine credential rotation through HashiCorp Vault** — not just credential storage.

[![CI](https://github.com/jralmaraz/vault-secrets-broker/actions/workflows/ci.yml/badge.svg)](https://github.com/jralmaraz/vault-secrets-broker/actions/workflows/ci.yml)
[![Security](https://github.com/jralmaraz/vault-secrets-broker/actions/workflows/security.yml/badge.svg)](https://github.com/jralmaraz/vault-secrets-broker/actions/workflows/security.yml)
[![Supply Chain](https://github.com/jralmaraz/vault-secrets-broker/actions/workflows/supply-chain.yml/badge.svg)](https://github.com/jralmaraz/vault-secrets-broker/actions/workflows/supply-chain.yml)

---

## The Problem: The KV Misconception

In enterprise Vault deployments, a common and costly mistake is treating the **KV secrets engine as a credential rotation solution**. It is not.

| Behaviour | KV Engine | Dynamic Secrets Engine (this PoC) |
|---|---|---|
| Stores the credential securely | ✅ | ✅ |
| Audits every access | ✅ | ✅ |
| Enforces a TTL on Vault's copy | ✅ | ✅ |
| Calls the target system's API to create a new credential | ❌ | ✅ |
| Revokes the old credential on the target system when the lease expires | ❌ | ✅ |
| Prevents a leaked credential from remaining valid beyond its TTL | ❌ | ✅ |

When a KV-stored credential expires in Vault, **the credential is still valid on Auth0 / Splunk / SonarQube indefinitely**. Only a secrets engine that knows how to call those systems' APIs can perform real rotation.

This PoC proves that pattern using three components connected by a layered security model.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Applications / Consumers                    │
│              vault read generic/creds/my-role               │
└──────────────────────┬──────────────────────────────────────┘
                       │ TLS 1.3
┌──────────────────────▼──────────────────────────────────────┐
│              HashiCorp Vault 2.1+  (:8200 TLS)              │
│                                                             │
│   ┌─────────────────────┐   ┌──────────────────────────┐   │
│   │  vault-rest-engine  │   │  vault-auth0-engine       │   │
│   │  (Generic Plugin)   │   │  (Auth0 Native Plugin)   │   │
│   └──────────┬──────────┘   └──────────────────────────┘   │
│              │                                              │
│   ┌──────────▼──────────┐   ┌──────────────────────────┐   │
│   │   Transit Engine    │   │  PKI Engine               │   │
│   │  cred-rotation-key  │   │  Internal CA              │   │
│   │  (aes256-gcm96)     │   │  mTLS cert issuance       │   │
│   └─────────────────────┘   └──────────────────────────┘   │
│                                                             │
│   ┌─────────────────────┐   ┌──────────────────────────┐   │
│   │     KV v2           │   │  AppRole Auth             │   │
│   │ Transit-encrypted   │   │  cred-rotation-api role   │   │
│   │  adapter config     │   └──────────────────────────┘   │
│   └─────────────────────┘                                   │
└──────────────────────┬──────────────────────────────────────┘
                       │ mTLS (mutual TLS)
┌──────────────────────▼──────────────────────────────────────┐
│         Credential Rotation API  (:8443 mTLS)               │
│                                                             │
│   POST /v1/credentials/rotate                               │
│   POST /v1/credentials/revoke                               │
│   GET  /v1/credentials/status/:lease_id                     │
│                                                             │
│   ┌──────────────┐  ┌───────────────┐  ┌────────────────┐  │
│   │ Auth0 Adapter│  │ Splunk Adapter│  │ SonarQube Adpt │  │
│   └──────┬───────┘  └───────┬───────┘  └───────┬────────┘  │
└──────────┼──────────────────┼───────────────────┼───────────┘
           │ TLS              │ TLS               │ TLS
    Auth0 Mgmt API      Splunk REST API    SonarQube Web API
```

### The AuthZEN Parallel

This API design mirrors the [AuthZEN](https://openid.net/wg/authzen/) standardisation pattern:

| AuthZEN (authorization decisions) | CredentialBroker (credential lifecycle) |
|---|---|
| `POST /access/v1/evaluation` | `POST /v1/credentials/rotate` |
| `{ subject, resource, action }` | `{ provider, resource_id, lease_id }` |
| `→ { decision: bool }` | `→ { encrypted_value, expires_at }` |
| Any PDP implements the contract | Any SaaS adapter implements the contract |
| Callers don't know if it's OPA or OpenFGA | Vault doesn't know if it's Auth0 or Splunk |

Adding a new SaaS provider = adding one adapter to the API. Zero Vault plugin changes.

---

## Security Model

### Encryption layers (defence in depth)

```
Layer 5 — Vault storage encryption (Raft/Consul)
  └─ Layer 4 — Transit envelope encryption (KV adapter config at rest)
       └─ Layer 3 — Transit envelope encryption (credential values in motion)
            └─ Layer 2 — mTLS (plugin ↔ Credential Rotation API)
                 └─ Layer 1 — TLS 1.3 (consumer ↔ Vault)
```

### Vault 2.0+ Envelope Encryption

The `cred-rotation-key` (type `aes256-gcm96`) supports envelope encryption: for every `transit/encrypt` call, Vault generates a **unique Data Encryption Key (DEK)** using AES-256-GCM, encrypts the plaintext with it, and wraps the DEK with the Transit master key. The returned ciphertext (`vault:v1:...`) includes the wrapped DEK as a header.

This means:
- The same credential rotated twice produces **two unrelated ciphertexts** — correlation is impossible
- A compromised ciphertext reveals nothing without the Transit master key (held in Vault's seal)
- The Transit key itself is **non-exportable** and has no plaintext backup

### Credential never plaintext at rest

```
SaaS API → new_secret (plaintext, over TLS)
  │
  └─ cred-rotation-api encrypts immediately:
       POST /v1/transit/encrypt/cred-rotation-key
       → vault:v1:AbC123...  (ciphertext)
         │
         └─ sent over mTLS to vault-rest-engine
              │
              └─ vault-rest-engine decrypts in memory:
                   POST /v1/transit/decrypt/cred-rotation-key
                   → plaintext (in plugin process memory only)
                     │
                     └─ returned to consumer over TLS 1.3
```

The plaintext credential exists in two places:
1. In the SaaS provider's API response (over TLS)
2. In the plugin process memory immediately before returning to the consumer

It is never written to disk, never stored in Vault KV, never logged.

### Auth model

| Hop | Auth method | Secret type |
|---|---|---|
| Consumer → Vault | OIDC / Kubernetes / AppRole | Vault token (scoped, short-lived) |
| Plugin → Credential Rotation API | mTLS client certificate | cert issued by internal PKI CA |
| Credential Rotation API → Vault (Transit) | AppRole | role_id (non-secret) + secret_id (injected at boot) |
| Credential Rotation API → SaaS providers | TLS + API credentials | loaded from Transit-decrypted KV at startup |

### AppRole bootstrap options (no Kubernetes)

| Environment | Method | Notes |
|---|---|---|
| Local dev / PoC | `VAULT_APPROLE_SECRET_ID` env var | Simple. Never use in shared environments. |
| Any host (recommended) | **Vault TLS Cert Auth** | Cert = identity, no secret to inject. Cert issued by internal PKI engine. |
| Bare metal / VM | SPIFFE/SPIRE + Vault JWT auth | Vault 2.0+ native SVID support. No cert management needed. |
| Cloud (AWS/GCP/Azure) | Cloud metadata auth | IAM role / managed identity is the trust root. No secret at all. |
| Any (Vault-native) | AppRole + Response Wrapping | 5-min single-use wrapping token, detectable if intercepted. |

---

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| Go | 1.26+ | `brew install go` |
| Vault | 2.1+ | `brew install hashicorp/tap/vault` |
| git | any | — |
| curl | any | — |

For CI development:
| Tool | Version | Install |
|---|---|---|
| golangci-lint | latest | `brew install golangci-lint` |
| govulncheck | v1.6.0 | `go install golang.org/x/vuln/cmd/govulncheck@v1.6.0` |
| gosec | latest | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/jralmaraz/vault-secrets-broker.git
cd vault-secrets-broker

# Fill in your Auth0 dev tenant credentials
cp .env.example .env
vim .env
```

`.env` fields:

```bash
AUTH0_DOMAIN=dev-XXXXXXXX.us.auth0.com          # your Auth0 tenant domain
AUTH0_MGMT_CLIENT_ID=<vault-secrets-broker-mgmt app client_id>
AUTH0_MGMT_CLIENT_SECRET=<vault-secrets-broker-mgmt app client_secret>
AUTH0_MGMT_AUDIENCE=https://<your-tenant>/api/v2/
AUTH0_TEST_APP_CLIENT_ID=<test-app-alpha client_id>
```

> **Auth0 setup**: create a Machine-to-Machine application in your Auth0 dashboard named `vault-secrets-broker-mgmt`, authorize it against the **Auth0 Management API** with scopes `read:clients` and `update:clients`. Create a second application (`test-app-alpha`) — its `client_id` is what Vault will rotate.

### 2. Run Phase 1 setup

```bash
make setup
```

This starts a Vault dev server and configures:
- **PKI engine**: internal CA at `pki/` + `internal-mtls-client` role for issuing plugin mTLS certs
- **Transit engine**: `cred-rotation-key` (aes256-gcm96, non-exportable) at `transit/`
- **KV v2**: at `secret/` with Auth0 adapter config stored — `client_secret` Transit-encrypted at rest
- **AppRole**: `cred-rotation-api` role at `auth/approle/` with scoped policy
- **Policies**: `cred-rotation-api-policy` (Transit + KV read), `vault-plugin-policy` (Transit decrypt only)

Output ends with a summary and writes `.vault-env` for environment reuse.

### 3. Load the Vault environment

```bash
source .vault-env
vault status       # should show sealed=false
vault kv get secret/cred-rotation-api/adapters/auth0
# mgmt_client_secret_encrypted = vault:v1:...  ← Transit ciphertext, not plaintext
```

### 4. Verify Transit round-trip manually

```bash
source .env  # load AUTH0_MGMT_CLIENT_SECRET
source .vault-env

CIPHER=$(vault kv get -field=mgmt_client_secret_encrypted \
  secret/cred-rotation-api/adapters/auth0)

RECOVERED=$(vault write -field=plaintext \
  transit/decrypt/cred-rotation-key \
  ciphertext="$CIPHER" | base64 -d)

[ "$RECOVERED" = "$AUTH0_MGMT_CLIENT_SECRET" ] && echo "✓ Match" || echo "✗ Mismatch"
```

### 5. Stop Vault

```bash
make stop
```

---

## Repository Structure

```
vault-secrets-broker/
│
├── plugins/
│   ├── vault-rest-engine/          # Component 1: Generic REST secrets engine
│   │   ├── go.mod                  # Independent module (Vault SDK dep isolated here)
│   │   ├── go.sum
│   │   └── main.go                 # Plugin entry point (Phase 3)
│   │
│   └── vault-auth0-engine/         # Component 3: Auth0-native secrets engine
│       ├── go.mod
│       ├── go.sum
│       └── main.go                 # Plugin entry point (Phase 4)
│
├── cred-rotation-api/              # Component 2: Credential Rotation abstraction API
│   ├── go.mod                      # No Vault SDK — calls Vault via REST
│   ├── go.sum
│   ├── main.go                     # mTLS server entry point (Phase 2)
│   ├── adapter/                    # Adapter interface + implementations (Phase 2)
│   │   ├── adapter.go              # Adapter interface
│   │   ├── auth0/                  # Auth0 Management API adapter (Phase 2)
│   │   ├── splunk/                 # Splunk REST API adapter (Phase 5)
│   │   └── sonarqube/              # SonarQube Web API adapter (Phase 5)
│   └── vault/                      # Vault client for Transit + AppRole (Phase 2)
│
├── vault/
│   ├── policies/
│   │   ├── cred-rotation-api.hcl   # Transit encrypt/decrypt + KV read
│   │   └── vault-plugin.hcl        # Transit decrypt only (for Vault plugins)
│   ├── certs/                      # Generated locally — gitignored
│   │   └── internal-ca.crt         # PKI root CA certificate
│   └── vault-dev.log               # Runtime log — gitignored
│
├── scripts/
│   ├── phase1-setup.sh             # Vault infrastructure bootstrap
│   └── stop-vault.sh               # Stop the Vault dev server
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                  # Build, test, vet, fmt, lint per module
│   │   ├── security.yml            # govulncheck, gosec, CodeQL, policy lint
│   │   └── supply-chain.yml        # go mod verify, SBOM, dependency review
│   └── dependabot.yml              # Weekly dep updates per module + actions
│
├── .golangci.yml                   # golangci-lint config (gosec, errcheck, etc.)
├── .env.example                    # Template — copy to .env with real values
├── Makefile                        # setup, stop, build, test, fmt, vet
└── README.md
```

### Why three independent `go.mod` files?

| Concern | Shared root `go.mod` | Per-directory `go.mod` (chosen) |
|---|---|---|
| Vault SDK isolation | SDK pulled into API's dep graph unnecessarily | API has no SDK dep — calls Vault via REST |
| Version conflicts | Single `go.sum`: SDK vs API dep conflicts possible | Each component pins independently |
| Plugin release | Monorepo version tag covers all three components | Each plugin can be tagged independently |
| Security audit | One `govulncheck` run covers everything | Per-component audit, scoped findings |

---

## Development

### Running tests

```bash
# All modules
make test

# Single module
cd cred-rotation-api && go test -race ./...
cd plugins/vault-rest-engine && go test -race ./...
cd plugins/vault-auth0-engine && go test -race ./...
```

Tests are run with the `-race` flag (data race detector) on all CI runs.

#### Test structure

Each component follows this layout:

```
cred-rotation-api/
├── adapter/
│   ├── adapter.go
│   ├── adapter_test.go        # interface contract tests
│   ├── auth0/
│   │   ├── auth0.go
│   │   └── auth0_test.go      # unit tests with httptest.Server mock
│   └── mock/
│       └── adapter.go         # MockAdapter for integration tests
├── server/
│   ├── server.go
│   └── server_test.go         # mTLS handshake tests
└── vault/
    ├── client.go
    └── client_test.go         # Transit encrypt/decrypt contract tests
```

**Testing philosophy for this project:**

- **Unit tests** use `net/http/httptest` to mock SaaS APIs — no real Auth0 calls in unit tests
- **Integration tests** (tagged `//go:build integration`) require a live Vault dev server and real Auth0 tenant; run with `go test -tags=integration ./...`
- The Transit encrypt/decrypt round-trip is always tested against a real (dev) Vault instance in integration tests — this is intentional. Mocking Transit would validate nothing about the actual security model.
- No mocks for Vault — integration tests proved more reliable than mock-based tests for catching real encryption bugs

### Linting

```bash
# All modules
make fmt   # gofmt check
make vet   # go vet

# golangci-lint (per module)
cd cred-rotation-api && golangci-lint run --config ../.golangci.yml
```

Key linters enabled (see `.golangci.yml`):

| Linter | Why |
|---|---|
| `gosec` | Catches hardcoded credentials (G101), TLS `InsecureSkipVerify` (G402), weak crypto (G401-G505) |
| `errcheck` | Every crypto/TLS/HTTP error must be handled — silent failures are security bugs |
| `bodyclose` | HTTP response body leaks cause connection pool exhaustion |
| `noctx` | HTTP requests without context can hang indefinitely — DoS risk |
| `staticcheck` | Finds deprecated API usage, unreachable code, type assertion issues |
| `exhaustive` | Forces exhaustive switch on adapter dispatch enums — no unhandled providers |

### Local security scan

```bash
# Vulnerability check against Go's vuln database
cd cred-rotation-api && govulncheck ./...

# Static security analysis
cd cred-rotation-api && gosec ./...
```

---

## CI / CD and Supply Chain Security

### Workflows

| Workflow | Triggers | What it checks |
|---|---|---|
| `ci.yml` | Push to any branch, PR to main | Build, test, vet, fmt, golangci-lint per module |
| `security.yml` | Push to main, PR to main, weekly cron | govulncheck, gosec + SARIF upload, CodeQL, Vault policy lint |
| `supply-chain.yml` | Push to main, PR to main | go mod verify, go mod tidy, SBOM generation, action pin check |

### Supply chain controls

#### `go mod verify`
Every CI run calls `go mod verify` before building. This cryptographically verifies that every module in the build list matches the hash recorded in `go.sum`. A compromised module in the Go module proxy will fail this check.

```bash
# Run locally
cd cred-rotation-api && go mod verify
# Expected: all modules verified
```

#### `go mod tidy` drift check
CI fails if `go.mod`/`go.sum` differ after running `go mod tidy`. This ensures no dependency was added to source code without being properly declared.

#### Dependabot
Configured for all three Go modules and GitHub Actions (`.github/dependabot.yml`). Weekly on Mondays. Automatic PRs for dependency updates; each PR triggers full CI + security scan.

#### SBOM (Software Bill of Materials)
On every push to `main`, a CycloneDX JSON SBOM is generated per module using `anchore/sbom-action` (backed by Syft). SBOMs are uploaded as workflow artifacts (90-day retention) and can be used for:
- License compliance auditing
- Vulnerability impact assessment when new CVEs are disclosed
- Regulatory reporting

#### Dependency review
Every PR to `main` runs `actions/dependency-review-action`, which:
- Blocks PRs introducing dependencies with known CVEs (CVSS ≥ 4.0)
- Blocks dependencies with non-OSI-approved licenses

#### govulncheck (pinned at v1.6.0)
Scans Go binaries and source against the [Go vulnerability database](https://vuln.go.dev). Unlike `go mod verify` (which checks tampering), `govulncheck` checks for **known security vulnerabilities** in your actual call graph — it only reports vulnerabilities in code paths that are reachable.

#### gosec
Static security analyser that understands Go semantics. Key rules enforced:
- `G101`: hardcoded credentials (string containing "secret", "password", etc.)
- `G402`: `tls.Config` with `InsecureSkipVerify: true`
- `G403`: RSA keys shorter than 2048 bits
- `G404`: `math/rand` used instead of `crypto/rand`
- `G501`–`G505`: import of weak hash functions (MD5, SHA1)

SARIF output is uploaded to GitHub Security → Code Scanning for review in the PR.

#### CodeQL
GitHub's semantic code analysis. Runs the `security-extended` query suite against the full call graph of all three modules (built together so CodeQL can trace cross-component calls). Results appear in GitHub Security → Code Scanning.

#### Action pin check
A script in `supply-chain.yml` warns if any GitHub Actions workflow step uses a mutable tag (`@main`, `@master`, `@latest`, `@v1`) instead of a pinned commit SHA. Unpinned actions can be hijacked by a compromised action publisher. Not yet failing CI (warning only) — convert to hard failure before production use.

**Pinning example:**
```yaml
# Mutable — vulnerable to tag mutation attacks:
- uses: actions/checkout@v4

# Pinned — safe even if the tag is moved:
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

---

## Vault Infrastructure Detail

### PKI Engine

The PKI engine acts as the internal Certificate Authority for all mTLS communication inside the system.

```bash
# View the internal CA certificate
vault read pki/cert/ca

# Issue a client certificate for the vault-rest-engine plugin
vault write pki/issue/internal-mtls-client \
  common_name="vault-rest-engine" \
  ttl=720h
```

The `internal-mtls-client` role issues certificates with:
- `client_flag=true, server_flag=false` — usable only as TLS client certificates
- RSA 2048-bit key
- Max TTL 720h (30 days)
- Any CN/SAN allowed (internal trust boundary)

### Transit Engine

```bash
# Inspect the key
vault read transit/keys/cred-rotation-key
# type: aes256-gcm96
# exportable: false
# allow_plaintext_backup: false

# Encrypt a value (returns vault:v1:<ciphertext>)
vault write transit/encrypt/cred-rotation-key \
  plaintext=$(printf 'my-secret' | base64)

# Decrypt (returns base64 of original plaintext)
vault write transit/decrypt/cred-rotation-key \
  ciphertext="vault:v1:..."
```

The `vault:v1:` prefix encodes the key version. When the key is rotated (`vault write -f transit/keys/cred-rotation-key/rotate`), old ciphertexts can still be decrypted (backward-compatible) but new encryptions use the new key version (`vault:v2:`). Callers can be rewrapped via `transit/rewrap`.

### AppRole

```bash
# View the cred-rotation-api role
vault read auth/approle/role/cred-rotation-api

# Generate a new secret_id (for response wrapping, add -wrap-ttl=5m)
vault write -f auth/approle/role/cred-rotation-api/secret-id

# Authenticate as the API (test)
vault write auth/approle/login \
  role_id=$VAULT_APPROLE_ROLE_ID \
  secret_id=$VAULT_APPROLE_SECRET_ID
```

The `cred-rotation-api` AppRole:
- Token TTL: 1h (renewable)
- Token max TTL: 4h
- Token bound CIDR: `127.0.0.1/32` (local only in dev)
- Policies: `cred-rotation-api-policy` only

### KV v2 — stored adapter config

```bash
# View the Auth0 adapter config
vault kv get secret/cred-rotation-api/adapters/auth0

# Fields:
# domain                         — Auth0 tenant domain (plaintext)
# mgmt_client_id                 — Management app client_id (plaintext)
# mgmt_client_secret_encrypted   — Transit ciphertext (vault:v1:...)
# mgmt_audience                  — API audience URL (plaintext)
# test_app_client_id             — Target application client_id (plaintext)
```

Only the `client_secret` is Transit-encrypted. The other fields are not sensitive (client_ids and domain are not credentials — they are identifiers). This follows the principle of minimal encryption overhead: encrypt what is actually secret.

---

## Phase Roadmap

| Phase | Status | What gets built |
|---|---|---|
| **1. Foundation** | ✅ Complete | Vault dev server, PKI, Transit, AppRole, KV, policies, setup script |
| **2. cred-rotation-api** | 🔜 Next | mTLS Go server, Adapter interface, Auth0 adapter, Transit config loading |
| **3. vault-rest-engine** | ⏳ Planned | Custom Vault plugin, config/roles/creds paths, mTLS call to API, lease management |
| **4. vault-auth0-engine** | ⏳ Planned | Auth0-native Vault plugin (direct API calls), comparison with Phase 2+3 approach |
| **5. Additional adapters** | ⏳ Planned | Splunk + SonarQube adapters in cred-rotation-api, zero plugin changes |
| **6. Hardening** | ⏳ Planned | Circuit breaker, rotation failure handling, demo script, audit log review |

---

## Adding a New SaaS Provider

To add a new SaaS provider (e.g. Datadog), you need to:

1. Implement the `Adapter` interface in `cred-rotation-api/adapter/datadog/`
2. Register it in the adapter registry
3. Add a Vault role pointing at provider `"datadog"` with the resource_id

**Zero changes to Vault plugins.** The `vault-rest-engine` plugin is completely unaware of which provider it's rotating for.

```go
// cred-rotation-api/adapter/adapter.go
type Adapter interface {
    Rotate(ctx context.Context, req RotateRequest) (RotateResult, error)
    Revoke(ctx context.Context, req RevokeRequest) error
    Status(ctx context.Context, credentialID string) (CredentialStatus, error)
    Name() string
}
```

---

## Security Considerations and Known Limitations (PoC)

| Item | Status | Notes |
|---|---|---|
| `vault server -dev` is in-memory | PoC only | Dev mode uses an in-memory storage backend. Restart = all data lost. Switch to Raft file backend for persistence testing. |
| AppRole secret_id via env var | Phase 1 only | Replace with Vault TLS Cert Auth in Phase 2. Env var approach is acceptable for local dev. |
| `token_bound_cidrs=127.0.0.1/32` | PoC | Restricts AppRole token use to localhost. Remove or adjust for multi-host deployment. |
| Internal CA is self-signed | PoC | For production, root the internal CA under your enterprise PKI. |
| Plugin binary not SHA-pinned | Phase 1 | Plugin registration with SHA256 hash is implemented in the setup script. See Phase 3 for CI-automated binary signing. |
| TLS cert on `cred-rotation-api` | Phase 2 | Server cert for the API's mTLS listener will be issued by the internal PKI in Phase 2. Phase 1 only establishes the CA. |
