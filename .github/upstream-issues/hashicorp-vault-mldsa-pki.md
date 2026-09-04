# Upstream engagement: ML-DSA PKI support in HashiCorp Vault

## References

| Resource | Link |
|---|---|
| Upstream tracking issue | hashicorp/vault#27239 |
| Community PR (ML-DSA-65 + ML-DSA-87) | hashicorp/vault#32007 |
| Go stdlib ML-DSA issue | golang/go#78888 |
| Local tracking issue | jralmaraz/vault-secrets-broker#12 |

## Background

NIST finalized ML-DSA (FIPS 204) in August 2024. `crypto/mldsa` landed in Go 1.27 (stable).
`crypto/x509` + `crypto/tls` ML-DSA support (golang/go#78888) is the remaining stdlib blocker.
HashiCorp shipped ML-DSA sign/verify in Vault Enterprise Transit (experimental, 1.19+).
PKI issuance is downstream of Transit and of Go `crypto/x509` support — currently targeted 2027+.

## Current status of community PR #32007

- Opened: June 2026
- Implements: ML-DSA-65 and ML-DSA-87 for Vault PKI engine using `circl` (already vendored)
- 44 unit tests, backward-compatible, correct OIDs (FIPS 204: 2.16.840.1.101.3.4.3.18 / .19)
- Custom ASN.1 X.509 construction because `crypto/x509` doesn't support ML-DSA yet
- CLA: status ambiguous (bot fired both signed/unsigned messages) — recheck at https://cla.hashicorp.com/hashicorp/vault?pullRequest=32007
- Vercel failure: `vercel.json` schema issue, unrelated to the code change
- No HashiCorp reviewer assigned as of filing date

## Comment to post on issue #27239

> **Use case and timeline pressure**
>
> We're building a Vault-native secrets broker ([vault-secrets-broker](https://github.com/jralmaraz/vault-secrets-broker))
> and are blocked on ML-DSA certificate issuance for our mTLS auth surface. Our current mTLS
> certificates (ECDSA) are quantum-vulnerable; the key exchange layer is already covered
> (X25519MLKEM768 in Go 1.24+), but authentication is not.
>
> Concrete timeline pressure: France's ANSSI has set a 2027 deadline for PQC migration in critical
> systems. EJBCA, Microsoft AD CS, and AWS Private CA have all shipped ML-DSA certificate support.
> Vault is the gap for teams running a self-hosted PKI.
>
> **Current state of the Go ecosystem:**
> - `crypto/mldsa` landed in **Go 1.27** (stable, production-ready)
> - `crypto/x509` + `crypto/tls` ML-DSA support is tracked at golang/go#78888 — not yet complete,
>   but this is the only remaining stdlib blocker for Vault to use it natively
>
> **PR #32007** already implements ML-DSA-65 and ML-DSA-87 for the PKI engine using `circl`
> (already vendored). It includes 44 unit tests and is backward-compatible. It would unblock our
> use case today. It's been open since June 2026 without a HashiCorp reviewer. Could someone from
> the team take a look and provide direction on whether this approach is aligned with HashiCorp's
> roadmap?

## Comment to post on PR #32007

> Thanks for doing this — the work here (custom ASN.1 construction, correct OIDs, post-signing
> verification, PEM label convention) is exactly what's needed and the `circl`-first approach is
> the right call while `crypto/x509` is still catching up.
>
> A few observations that might help get this moving:
>
> 1. **stdlib migration path**: You noted "can be swapped to `crypto/mldsa` when Go 1.27 ships"
>    — it has shipped. Vault modules already on Go 1.27.1 could reference `crypto/mldsa` directly
>    for key generation, while keeping the custom ASN.1 path until golang/go#78888 lands in
>    `crypto/x509`. Not a blocker, but worth noting for the review discussion.
>
> 2. **Vercel failure** is a `vercel.json` schema issue unrelated to this PR — shouldn't affect
>    merge consideration.
>
> 3. **CLA**: the bot shows mixed signals — worth rechecking at
>    https://cla.hashicorp.com/hashicorp/vault?pullRequest=32007 if that's flagged as a blocker.
>
> We're building on top of Vault's PKI engine for mTLS workload identity and are directly blocked
> on ML-DSA cert issuance. Happy to assist with testing or review if that's helpful.
