# Security Suppression Register

Every `// #nosec` annotation and `//nolint:gosec` comment in this repository is listed
here with the rationale, the risk assessed, and the alternative that was considered and
rejected. If you add a new suppression without a corresponding entry here, the PR will
not be approved.

---

## Format

Each entry follows this structure:

```
### <Rule> — <file:line> (short label)
**Status**: suppressed / accepted risk
**What the rule detects**: …
**Why this instance is safe**: …
**Alternative considered**: …
**Risk if wrong**: …
```

---

## Suppressions

### G118 — adapter/sonarqube/sonarqube.go · adapter/datadog/datadog.go · adapter/pagerduty/pagerduty.go · adapter/splunk/splunk.go

**Rule**: CWE-400 — Goroutine uses `context.Background()` or `context.TODO()` while a
request-scoped context is available.

**What the rule detects**: A goroutine spawned inside a request handler that ignores the
caller's context, which could mask context cancellation and leave goroutines running
indefinitely after the request has already been abandoned or timed out.

**Why this instance is safe — and intentional**:

The cleanup goroutine's job is to delete the *old* credential from the SaaS provider
after a new one has been successfully created. If the caller's request context is used
and the consumer's HTTP call times out or is cancelled mid-flight, the cleanup would
silently no-op — leaving the old, revoked-but-still-valid credential alive in the SaaS
provider with no audit trail and no retry.

Using an independent `context.WithTimeout(context.Background(), 10s)` guarantees that:
1. The cleanup runs to completion regardless of what the caller does.
2. It cannot run forever — the 10-second budget is enforced.
3. The goroutine is tracked by `cleanupWg`; `Drain()` waits for it on graceful shutdown.

**Alternative considered**: Use the request context with a deadline extension.  
**Why rejected**: Extending a cancelled context is not supported in Go's standard library;
a new independent context is the correct pattern. Using the original context would risk
leaving dangling active credentials on every timeout/cancellation event — which is a
security regression.

**Risk if wrong**: A goroutine that never terminates on a hung provider call. Mitigated
by the hard 10-second timeout on `deleteCtx` and the `Drain()` method which waits for
all goroutines during graceful shutdown. The chaos/scenarios_test.go
`TestGracefulShutdownDrainsCleanup` test verifies this behaviour.

---

### G402 — adapter/splunk/splunk.go · adapter/splunk/splunk_integration_test.go · chaos/helpers_test.go

**Rule**: CWE-295 — TLS `InsecureSkipVerify` set to `true`.

**What the rule detects**: Disabling TLS certificate verification, which allows
man-in-the-middle attacks.

**Why this instance is safe**:

- **splunk.go**: `InsecureSkipVerify` is set from `cfg.Insecure`, a `bool` that defaults
  to `false`. It is never `true` in production deployments; it is only set to `true`
  explicitly for local Docker integration tests via an environment-sourced config. The
  field name and package comment both document this constraint.

- **splunk_integration_test.go** and **chaos/helpers_test.go**: These are test files.
  The transport is used only to connect to `httptest.TLSServer`, which always uses a
  self-signed certificate generated in-process. There is no network path to a real
  server; the connection stays on the loopback interface.

**Alternative considered**: Provide a custom CA bundle for the test server's certificate.  
**Why rejected**: `httptest.NewTLSServer` generates a fresh self-signed cert for every
test run; extracting and injecting that CA bundle adds significant boilerplate with no
security benefit in a loopback-only test context.

**Risk if wrong**: Only in tests — there is no production code path where
`InsecureSkipVerify` is `true`. The `Insecure bool` field in `splunk.Config` is
explicitly documented as "for CI only — never production."

---

### G404 — chaos/mock_provider.go

**Rule**: CWE-338 — Use of `math/rand` (weak random number generator) instead of
`crypto/rand`.

**What the rule detects**: Use of a deterministic, non-cryptographically-secure PRNG
in a context where unpredictable random values are security-critical (e.g., generating
secrets, nonces, tokens).

**Why this instance is safe**:

`math/rand.Float64()` is used in the `MockProvider.wrap()` method to decide whether a
simulated fault injection event should fire — i.e., whether to return a 429 or 500
response in a test. This is probabilistic test behaviour, not a security primitive:

- No secrets, tokens, nonces, or IDs are generated.
- The "randomness" controls only whether a chaos test returns an HTTP error code.
- Test reproducibility and speed matter here; `crypto/rand` would be slower and its
  unpredictability provides zero benefit for fault injection percentages.

**Alternative considered**: `crypto/rand` for uniform distribution.  
**Why rejected**: Cryptographic randomness is overkill for "return a 500 30% of the
time in a unit test." The only consumer of this randomness is the test harness itself.

**Risk if wrong**: None — this code is in `package chaos` which is never imported by
production code. The file is excluded from any binary build that is not a test binary.

---

## Adding a new suppression

1. Make the change and add both annotations to the code line:
   ```go
   someCall() // #nosec G<N> //nolint:gosec -- <short reason>
   ```
   (`// #nosec` must come FIRST — the standalone gosec binary stops scanning a comment
   that starts with something other than `#nosec`.)

2. Add an entry to this file before opening a PR.

3. The PR description must reference the entry here.
