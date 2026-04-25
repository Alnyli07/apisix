# DPoP Plugin — Integration Test Expansion

**Date:** 2026-04-24
**Branch:** `feat/plugin-dpop-test-infra`
**Status:** Design approved

## Purpose

Expand `t/plugin/dpop.t` with negative integration tests that exercise the DPoP claim validation boundary end-to-end via actual HTTP requests against a route backed by the plugin. The existing suite only covers schema checks and happy-path crypto for four algorithms; it does not prove the plugin rejects malformed or tampered proofs.

## Context

The repo already ships an external k6 suite (`k6/dpop-e2e.js`) with ~48 assertions covering the same ground in a real APISIX deployment (plus WASM parity and Redis replay scenarios). That suite requires a live APISIX, an IDP, and external orchestration, so it does not run in the upstream APISIX CI pipeline.

`t/plugin/dpop.t` runs in-process via `test-nginx` / `prove`, with every PR, zero external dependencies. Negative tests added here pin the security invariants that matter most at unit-level and are cheap to run. The k6 suite remains the real-world gate for post-PR validation — in particular for newly added algorithms (ES384, ES512, PS256/384/512).

## Scope

**In:**
- New helper module `t/lib/dpop.lua` encapsulating key generation, JWK construction, JWT building, DPoP proof construction and signing.
- Refactor TEST 15–18 (existing happy-path tests for ES256/ES384/RS256/PS256) to use the helper.
- Add TEST 19–30 (12 negative integration tests) covering DPoP claim validation, replay, freshness, binding, and header hygiene.
- Plugin guard: reject DPoP proof JWKs that contain private key parameters.

**Out:**
- `enforce_introspection` integration (needs a real IDP; already covered by k6 S2).
- `strict_htu` + `public_base_url` scheme/host tests (covered by k6 S3).
- Lua ↔ WASM parity comparisons (k6 exclusive).
- Redis-backed replay cache (k6 exclusive; our replay test uses the default memory cache).

## Architecture

Two files change, one file is created. No APISIX core changes.

### New: `t/lib/dpop.lua`

A thin helper module exposing reusable crypto and JWT building blocks. Lives under `t/lib/` per APISIX convention (see `t/lib/keycloak.lua`, `t/lib/test_admin.lua`) — the harness adds `t/?.lua` to `lua_package_path`, so tests load it with `require("lib.dpop")`.

**API:**

```lua
local _M = {}

-- Base64url encoding without padding.
function _M.b64url_encode(bytes)

-- DER ECDSA-Sig (SEQUENCE of two INTEGERs) → raw R||S, fixed width per component.
-- comp_size: 32 (ES256), 48 (ES384).
function _M.der_to_raw_ecdsa(der, comp_size)

-- EC keypair generator. curve ∈ {"prime256v1" = P-256, "secp384r1" = P-384}.
-- Returns pkey, jwk (table), thumbprint (base64url RFC 7638).
function _M.new_ec_keypair(curve)

-- RSA keypair generator. bits default 2048.
-- Returns pkey, jwk (table), thumbprint (base64url RFC 7638).
function _M.new_rsa_keypair(bits)

-- "{alg:none,typ:JWT}.{sub,cnf.jkt,exp}." — alg=none access token used as
-- a carrier of cnf.jkt when verify_access_token=false.
-- overrides: { cnf_jkt, exp, sub, extra = {...} }.
function _M.make_alg_none_access_token(thumbprint, overrides)

-- Build and sign a DPoP proof (JWS Compact).
-- opts: {
--   pkey, jwk, alg,               -- required (alg in ES256/ES384/RS256/PS256/none)
--   htm, htu, iat, jti,           -- claims; nil-able to simulate absence
--   ath,                          -- optional
--   typ,                          -- default "dpop+jwt"; override for negative test
--   extra_header, extra_payload,  -- merged into respective JSON objects
--   omit = { "jti", "iat", ... }, -- remove these claims entirely
--   raw_signature,                -- if set, skip signing; use these bytes as signature
--                                    (used for alg=none proof test)
-- }
-- Returns the compact JWS string.
function _M.make_dpop_proof(opts)

-- Convenience: one call returns the parts needed for a valid happy flow.
-- alg ∈ {"ES256","ES384","RS256","PS256"}.
-- proof_overrides (optional) are merged into the proof opts; any claim can be
-- overridden to drive negative tests without re-assembling the flow.
-- Returns: { access_token, proof, jwk, thumbprint, pkey }.
function _M.valid_flow(alg, proof_overrides)

return _M
```

Design rationale:
- `make_dpop_proof` exposes enough override hooks to build *any* malformed proof we need — wrong claims, missing claims, wrong typ, wrong alg, precomputed signature. Negative tests stay one-liners.
- `valid_flow` is the common case; negative tests start from it and mutate one field.
- `der_to_raw_ecdsa` is deliberately parameterized by `comp_size` — the previous inline bug (`pos=3`) was caused by per-test duplication; a single helper eliminates that class of bug.
- JKT-mismatch scenarios (TEST 23) need two independent keypairs. Rather than adding a dedicated helper, that test calls `new_ec_keypair` twice and composes `make_alg_none_access_token` + `make_dpop_proof` manually. One test, no reusable abstraction needed.

### Changed: `t/plugin/dpop.t`

- TEST 15–18 rewritten to use the helper. Each block collapses from ~90 lines of inline crypto to ~15 lines (require, call `valid_flow`, make request, assert).
- TEST 19–30 added after TEST 18.
- No new route setup blocks — TEST 12's route (with `verify_access_token=false`, `allowed_algs=["ES256","ES384","RS256","PS256"]`) is reused for the negative tests.

### Changed: `apisix/plugins/dpop.lua`

Single targeted security fix in `get_or_create_pkey(jwk)`: before calling `openssl_pkey.new(..., {format="JWK"})`, reject JWKs that contain any private-key-shaped parameter. For EC that's `d`; for RSA that's any of `d`, `p`, `q`, `dp`, `dq`, `qi`. Returns `nil, "proof JWK must not contain private key parameters"`. This closes TEST 29.

## Test scenarios (TEST 19–30)

All use the TEST 12 route (`/hello` with DPoP plugin, `verify_access_token=false`). Requests go to `http://127.0.0.1:1984/hello` via `resty.http`. Regex patterns are provisional — they will be tightened against actual plugin error strings during implementation.

| #   | Scenario                         | Override                                           | Expect | Body contains            |
|-----|----------------------------------|----------------------------------------------------|--------|--------------------------|
| 19  | wrong htm                        | proof.htm = "POST", request is GET                 | 401    | `invalid_dpop_proof` + `htm` |
| 20  | wrong htu                        | proof.htu = "http://other.example/x"               | 401    | `invalid_dpop_proof` + `htu` |
| 21  | missing ath with AT present      | proof.ath omitted                                  | 401    | `invalid_dpop_proof` + `ath` |
| 22  | wrong ath                        | proof.ath = sha256("garbage") (b64url)             | 401    | `invalid_dpop_proof` + `ath` |
| 23  | JKT binding mismatch             | AT.cnf.jkt = thumbprint of a *different* key       | 401    | `invalid_dpop_proof` + `jkt` |
| 24  | expired proof                    | proof.iat = now − 600 (default proof_max_age = 60) | 401    | `invalid_dpop_proof` + `expired\|too old` |
| 25  | future iat                       | proof.iat = now + 600                              | 401    | `invalid_dpop_proof` + `future\|skew` |
| 26  | replay                           | same proof twice (stable jti)                      | 200, 401 | second: `invalid_dpop_proof` + `replay` |
| 27  | empty jti                        | proof.jti = ""                                     | 401    | `invalid_dpop_proof` + `jti` |
| 28  | alg=none proof                   | proof.header.alg = "none", raw_signature = ""      | 401    | `invalid_dpop_proof` + (`alg\|unsupported`) |
| 29  | private key in proof jwk         | inject `d` parameter into jwk (EC case)            | 401    | `invalid_dpop_proof` + `private\|jwk` |
| 30  | multiple DPoP headers            | send two DPoP headers on same request              | 401    | `invalid_dpop_proof` + `multiple\|duplicate` |

Implementation notes:
- TEST 26's replay relies on the default in-memory replay cache. No extra config.
- TEST 28 is expected to be caught by `allowed_algs` filtering before signature verification is attempted. The regex accepts either error wording.
- TEST 30 is emitted via test-nginx `--- more_headers` writing two `DPoP:` lines.

## Commit strategy (on `feat/plugin-dpop-test-infra`)

Four sequential commits, each independently sensible:

1. `test(infra): add lib/dpop helper module for test-nginx`
2. `test(plugin): refactor happy-path DPoP tests to use shared helper`
3. `fix(plugin): reject DPoP proof JWK containing private key parameters`
4. `test(plugin): add negative DPoP claim validation tests (19-30)`

When the PR is ready to be cleaned up, **all four** commits are cherry-picked back to `feat/plugin-dpop`. The `ci-test.Dockerfile` commit (`e0354e1`) stays on the test-infra branch.

## Verification

- `docker run --rm apisix-dpop-test` (via `t/ci-test.Dockerfile` on amd64) must report `All tests successful.` with expected count `54 + 12*3 = ~90` (exact count depends on per-test assertions; the harness line `Files=1, Tests=N` is the source of truth).
- No existing test regresses. TEST 15–18 still pass after refactor.
- Plugin guard (commit 3) does not break any existing test; only TEST 29 exercises it.

## Non-goals and explicit deferrals

- Not testing JWKS signature verification of access tokens (`verify_access_token=true`) — route config stays with verification off, matching the simplicity of the existing happy-path tests.
- Not adding ES512 / PS384 / PS512 to the test suite — they are accepted by the schema but not exercised end-to-end here. k6 can cover them in real-world runs against an IDP that emits them.
- Not extracting a full PASETO-like DSL; the helper stays small and transparent.
