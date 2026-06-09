# DPoP Integration Test Expansion — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand `t/plugin/dpop.t` with 12 negative DPoP claim validation tests using a new shared helper module at `t/lib/dpop.lua`, and add one plugin security guard rejecting proof JWKs that contain private-key parameters.

**Architecture:** New `t/lib/dpop.lua` provides reusable JWT/proof construction primitives (loaded as `require("lib.dpop")` via APISIX's existing `lua_package_path`). Existing happy-path TEST 15–18 are refactored to use the helper. New TEST 19–30 reuse the same TEST 12 route with proof_overrides driving each negative scenario. One plugin change: a guard in `get_or_create_pkey` that rejects JWKs containing `d` (EC) or `d/p/q/dp/dq/qi` (RSA).

**Tech Stack:** Lua 5.1 (LuaJIT), test-nginx + prove (Perl), `resty.openssl.pkey`, `resty.sha256`, `cjson.safe`, `resty.http`. Tests run in `t/ci-test.Dockerfile` on linux/amd64.

**Branch:** `feat/plugin-dpop-test-infra` (already pushed to `origin`).

**Spec:** `docs/superpowers/specs/2026-04-24-dpop-integration-tests-design.md`

---

## File Structure

| Action  | Path                                  | Responsibility                                                    |
|---------|---------------------------------------|-------------------------------------------------------------------|
| Create  | `t/lib/dpop.lua`                      | Crypto + JWT + DPoP proof construction helpers for tests          |
| Modify  | `t/plugin/dpop.t`                     | Refactor TEST 15–18; add TEST 19–30                               |
| Modify  | `apisix/plugins/dpop.lua` (line 454)  | Reject JWKs with private-key parameters in `get_or_create_pkey`   |

---

## Verification Approach

We cannot run `prove` locally on this dev machine (darwin/arm64). Verification happens by building and running `t/ci-test.Dockerfile` on a linux/amd64 host. The runner command is the same after every change:

```bash
docker build -f t/ci-test.Dockerfile -t apisix-dpop-test .
docker run --rm apisix-dpop-test
```

Expected output: `All tests successful.` and `Files=1, Tests=N` where N grows from 54 to roughly 90 as tests are added (the exact number depends on per-test assertion count).

If you don't have an amd64 host with Docker locally, push the branch and ask the user to run the build there.

---

## Task 1: Create the helper module `t/lib/dpop.lua`

**Files:**
- Create: `t/lib/dpop.lua`

- [ ] **Step 1: Write the helper module**

Create `t/lib/dpop.lua` with the following content:

```lua
--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- DPoP test helper.
-- Loaded from test blocks as require("lib.dpop").
local cjson = require("cjson.safe")
local openssl_pkey = require("resty.openssl.pkey")
local resty_sha256 = require("resty.sha256")
local string_format = string.format
local ngx = ngx

local _M = {}

-- base64url without padding
function _M.b64url_encode(bytes)
    local b = ngx.encode_base64(bytes)
    return (b:gsub("+", "-"):gsub("/", "_"):gsub("=", ""))
end

-- DER ECDSA-Sig (SEQUENCE of two INTEGERs) → raw R||S of fixed width.
-- Layout: 0x30 <seq_len> 0x02 <r_len> <r> 0x02 <s_len> <s>.
-- pos starts at 4: skip 0x30 (1) + seq_len (1) + 0x02 r tag (1).
function _M.der_to_raw_ecdsa(der, comp_size)
    local pos = 4
    local r_len = der:byte(pos)
    pos = pos + 1
    local r = der:sub(pos, pos + r_len - 1)
    pos = pos + r_len + 1
    local s_len = der:byte(pos)
    pos = pos + 1
    local s = der:sub(pos, pos + s_len - 1)
    while #r > comp_size do r = r:sub(2) end
    while #s > comp_size do s = s:sub(2) end
    while #r < comp_size do r = "\0" .. r end
    while #s < comp_size do s = "\0" .. s end
    return r .. s
end

local function sha256_b64url(bytes)
    local sha = resty_sha256:new()
    sha:update(bytes)
    return _M.b64url_encode(sha:final())
end
_M.sha256_b64url = sha256_b64url

-- EC key pair. curve ∈ {"prime256v1" (P-256), "secp384r1" (P-384)}.
-- Returns pkey, jwk_table, thumbprint_b64url (RFC 7638).
function _M.new_ec_keypair(curve)
    local pkey = openssl_pkey.new({ type = "EC", curve = curve })
    local p = pkey:get_parameters()
    local crv
    if curve == "prime256v1" then
        crv = "P-256"
    elseif curve == "secp384r1" then
        crv = "P-384"
    else
        error("unsupported EC curve: " .. tostring(curve))
    end
    local jwk = {
        kty = "EC", crv = crv,
        x = _M.b64url_encode(p.x:to_binary()),
        y = _M.b64url_encode(p.y:to_binary()),
    }
    -- RFC 7638 EC thumbprint: lex-sorted {crv, kty, x, y}
    local input = string_format(
        '{"crv":"%s","kty":"EC","x":"%s","y":"%s"}',
        jwk.crv, jwk.x, jwk.y
    )
    return pkey, jwk, sha256_b64url(input)
end

-- RSA key pair. bits default 2048.
-- Returns pkey, jwk_table, thumbprint_b64url (RFC 7638).
function _M.new_rsa_keypair(bits)
    bits = bits or 2048
    local pkey = openssl_pkey.new({ type = "RSA", bits = bits })
    local p = pkey:get_parameters()
    local jwk = {
        kty = "RSA",
        n = _M.b64url_encode(p.n:to_binary()),
        e = _M.b64url_encode(p.e:to_binary()),
    }
    -- RFC 7638 RSA thumbprint: lex-sorted {e, kty, n}
    local input = string_format(
        '{"e":"%s","kty":"RSA","n":"%s"}',
        jwk.e, jwk.n
    )
    return pkey, jwk, sha256_b64url(input)
end

-- alg=none access token: "{alg:none,typ:JWT}.{sub,cnf.jkt,exp}."
-- overrides: { sub, cnf_jkt, exp, extra = {...} }
function _M.make_alg_none_access_token(thumbprint, overrides)
    overrides = overrides or {}
    local payload = {
        sub = overrides.sub or "testuser",
        cnf = { jkt = overrides.cnf_jkt or thumbprint },
        exp = overrides.exp or (ngx.time() + 3600),
    }
    if overrides.extra then
        for k, v in pairs(overrides.extra) do payload[k] = v end
    end
    local h = _M.b64url_encode(cjson.encode({ alg = "none", typ = "JWT" }))
    local p = _M.b64url_encode(cjson.encode(payload))
    return h .. "." .. p .. "."
end

local DIGEST = {
    ES256 = "sha256", ES384 = "sha384",
    RS256 = "sha256",
    PS256 = "sha256",
}
local EC_COMP = { ES256 = 32, ES384 = 48 }

-- Build and sign a DPoP proof.
-- opts:
--   pkey, jwk, alg                (required; alg ∈ ES256/ES384/RS256/PS256/none)
--   htm, htu, iat, jti, ath       (claims; nil means "do not include")
--   typ                           (defaults to "dpop+jwt")
--   extra_header, extra_payload   (merged into header/payload tables)
--   omit = { "claim", ... }       (final pass: removes these claim keys)
--   raw_signature                 (if set: skip signing, use these bytes)
function _M.make_dpop_proof(opts)
    local header = {
        typ = opts.typ or "dpop+jwt",
        alg = opts.alg,
        jwk = opts.jwk,
    }
    if opts.extra_header then
        for k, v in pairs(opts.extra_header) do header[k] = v end
    end

    local payload = {}
    if opts.htm ~= nil then payload.htm = opts.htm end
    if opts.htu ~= nil then payload.htu = opts.htu end
    if opts.iat ~= nil then payload.iat = opts.iat end
    if opts.jti ~= nil then payload.jti = opts.jti end
    if opts.ath ~= nil then payload.ath = opts.ath end
    if opts.extra_payload then
        for k, v in pairs(opts.extra_payload) do payload[k] = v end
    end
    if opts.omit then
        for _, key in ipairs(opts.omit) do payload[key] = nil end
    end

    local h_b64 = _M.b64url_encode(cjson.encode(header))
    local p_b64 = _M.b64url_encode(cjson.encode(payload))
    local signing_input = h_b64 .. "." .. p_b64

    local sig_b64
    if opts.raw_signature ~= nil then
        sig_b64 = _M.b64url_encode(opts.raw_signature)
    elseif opts.alg == "none" then
        sig_b64 = ""
    else
        local digest = DIGEST[opts.alg]
        if not digest then
            error("unsupported alg: " .. tostring(opts.alg))
        end
        local sig
        if opts.alg == "PS256" then
            sig = opts.pkey:sign(signing_input, digest, nil,
                {{"rsa_padding_mode", "pss"}})
        else
            sig = opts.pkey:sign(signing_input, digest)
        end
        if EC_COMP[opts.alg] then
            sig = _M.der_to_raw_ecdsa(sig, EC_COMP[opts.alg])
        end
        sig_b64 = _M.b64url_encode(sig)
    end

    return signing_input .. "." .. sig_b64
end

-- Convenience: full happy-flow components.
-- alg ∈ {"ES256","ES384","RS256","PS256"}.
-- proof_overrides may override any claim or pass extras to make_dpop_proof.
-- Returns: { access_token, proof, jwk, thumbprint, pkey }.
function _M.valid_flow(alg, proof_overrides)
    local pkey, jwk, thumbprint
    if alg == "ES256" then
        pkey, jwk, thumbprint = _M.new_ec_keypair("prime256v1")
    elseif alg == "ES384" then
        pkey, jwk, thumbprint = _M.new_ec_keypair("secp384r1")
    elseif alg == "RS256" or alg == "PS256" then
        pkey, jwk, thumbprint = _M.new_rsa_keypair(2048)
    else
        error("unsupported alg: " .. tostring(alg))
    end

    local access_token = _M.make_alg_none_access_token(thumbprint)
    local ath = sha256_b64url(access_token)

    proof_overrides = proof_overrides or {}
    local opts = {
        pkey = pkey,
        jwk = proof_overrides.jwk or jwk,
        alg = proof_overrides.alg or alg,
        htm = proof_overrides.htm or "GET",
        htu = proof_overrides.htu or "http://localhost/hello",
        iat = proof_overrides.iat or ngx.time(),
        jti = proof_overrides.jti
            or (alg:lower() .. "-" .. tostring(ngx.now())),
        ath = proof_overrides.ath ~= nil and proof_overrides.ath or ath,
        typ = proof_overrides.typ,
        extra_header = proof_overrides.extra_header,
        extra_payload = proof_overrides.extra_payload,
        omit = proof_overrides.omit,
        raw_signature = proof_overrides.raw_signature,
    }
    local proof = _M.make_dpop_proof(opts)
    return {
        access_token = access_token,
        proof = proof,
        jwk = jwk,
        thumbprint = thumbprint,
        pkey = pkey,
    }
end

return _M
```

- [ ] **Step 2: Commit the helper module**

```bash
git add t/lib/dpop.lua
git commit -m "test(infra): add lib/dpop helper module for test-nginx"
```

---

## Task 2: Refactor TEST 15–18 to use the helper

**Files:**
- Modify: `t/plugin/dpop.t` (lines 334–727 — TEST 15–18 blocks)

- [ ] **Step 1: Replace TEST 15 (ES256)**

Replace the existing TEST 15 block (currently lines 334–439) with:

```
=== TEST 15: generate valid DPoP proof (ES256) and verify full flow
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local cjson = require("cjson.safe")
            local f = h.valid_flow("ES256")
            local httpc = require("resty.http").new()
            local res, err = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP " .. f.access_token,
                        ["DPoP"] = f.proof,
                    },
                }
            )
            if not res then
                ngx.say("failed: " .. (err or ""))
                return
            end
            ngx.say("status: " .. res.status)
            if res.status ~= 200 then
                ngx.say("body: " .. (res.body or ""))
            end
        }
    }
--- response_body
status: 200
--- no_error_log
[error]
```

- [ ] **Step 2: Replace TEST 16 (ES384)**

Replace TEST 16 with the same body but `h.valid_flow("ES384")`.

- [ ] **Step 3: Replace TEST 17 (RS256)**

Replace TEST 17 with the same body but `h.valid_flow("RS256")`.

- [ ] **Step 4: Replace TEST 18 (PS256)**

Replace TEST 18 with the same body but `h.valid_flow("PS256")`.

- [ ] **Step 5: Verify in Docker**

```bash
docker build -f t/ci-test.Dockerfile -t apisix-dpop-test .
docker run --rm apisix-dpop-test
```

Expected: `All tests successful.` with `Files=1, Tests=54`.

If a test regresses, do not proceed — fix the helper.

- [ ] **Step 6: Commit**

```bash
git add t/plugin/dpop.t
git commit -m "test(plugin): refactor happy-path DPoP tests to use shared helper"
```

---

## Task 3: Plugin guard — reject JWK with private key parameters

**Files:**
- Modify: `apisix/plugins/dpop.lua` (function `get_or_create_pkey` near line 454)

- [ ] **Step 1: Add the guard**

Edit `apisix/plugins/dpop.lua`. Replace the function `get_or_create_pkey` (currently around line 453–458) with:

```lua
-- A DPoP proof's embedded JWK MUST be a public key only.
-- Reject any JWK that carries private-key-shaped parameters
-- (RFC 7517 §4.4 / RFC 7518 §6).
local function jwk_has_private_params(jwk)
    if not jwk then return false end
    if jwk.kty == "EC" then
        return jwk.d ~= nil
    elseif jwk.kty == "RSA" then
        return jwk.d ~= nil
            or jwk.p ~= nil or jwk.q ~= nil
            or jwk.dp ~= nil or jwk.dq ~= nil
            or jwk.qi ~= nil
    end
    return false
end

-- Get or create openssl pkey from JWK, cached by JSON representation
local function get_or_create_pkey(jwk)
    if jwk_has_private_params(jwk) then
        return nil, "proof JWK must not contain private key parameters"
    end
    local jwk_json = cjson.encode(jwk)
    local pkey = _pkey_cache:get(jwk_json)
    if pkey then
        return pkey
    end
    local new_pkey, err = openssl_pkey.new(jwk_json, { format = "JWK" })
    if not new_pkey then
        return nil, err
    end
    _pkey_cache:set(jwk_json, new_pkey, 3600)  -- 1 hour TTL
    return new_pkey
end
```

- [ ] **Step 2: Verify existing tests still pass**

```bash
docker build -f t/ci-test.Dockerfile -t apisix-dpop-test .
docker run --rm apisix-dpop-test
```

Expected: `All tests successful.` with `Files=1, Tests=54`. The guard should not affect any existing test (none of them embed private parameters).

- [ ] **Step 3: Commit**

```bash
git add apisix/plugins/dpop.lua
git commit -m "fix(plugin): reject DPoP proof JWK containing private key parameters"
```

---

## Task 4: Add negative tests TEST 19–30

**Files:**
- Modify: `t/plugin/dpop.t` (append after TEST 18)

All 12 tests share the same shape:
1. `require("lib.dpop")` and build the proof + access token.
2. Send via `resty.http` to `http://127.0.0.1:1984/hello` (TEST 12's existing route).
3. Echo the inner response status and the parsed `error` field.
4. Assert the resulting two-line body via `--- response_body`.

The TEST 12 route was created with `verify_access_token=false` and `allowed_algs=["ES256","ES384","RS256","PS256"]`. None of the tests in this task create new routes.

For every test below, append the block to the end of `t/plugin/dpop.t` (after TEST 18, before any trailing newline). Do not run docker between individual tests — verify them all together at the end.

- [ ] **Step 1: TEST 19 — wrong htm**

```
=== TEST 19: wrong htm in proof — 401
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local cjson = require("cjson.safe")
            local f = h.valid_flow("ES256", { htm = "POST" })
            local httpc = require("resty.http").new()
            local res = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP " .. f.access_token,
                        ["DPoP"] = f.proof,
                    },
                }
            )
            local body = cjson.decode(res.body or "{}") or {}
            ngx.say("status: " .. res.status)
            ngx.say("error: " .. (body.error or "?"))
        }
    }
--- response_body
status: 401
error: invalid_dpop_proof
```

- [ ] **Step 2: TEST 20 — wrong htu**

```
=== TEST 20: wrong htu in proof — 401
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local cjson = require("cjson.safe")
            local f = h.valid_flow("ES256",
                { htu = "http://other.example/x" })
            local httpc = require("resty.http").new()
            local res = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP " .. f.access_token,
                        ["DPoP"] = f.proof,
                    },
                }
            )
            local body = cjson.decode(res.body or "{}") or {}
            ngx.say("status: " .. res.status)
            ngx.say("error: " .. (body.error or "?"))
        }
    }
--- response_body
status: 401
error: invalid_dpop_proof
```

- [ ] **Step 3: TEST 21 — missing ath when AT is present**

```
=== TEST 21: missing ath claim when access token is present — 401
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local cjson = require("cjson.safe")
            local f = h.valid_flow("ES256", { omit = { "ath" } })
            local httpc = require("resty.http").new()
            local res = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP " .. f.access_token,
                        ["DPoP"] = f.proof,
                    },
                }
            )
            local body = cjson.decode(res.body or "{}") or {}
            ngx.say("status: " .. res.status)
            ngx.say("error: " .. (body.error or "?"))
        }
    }
--- response_body
status: 401
error: invalid_dpop_proof
```

- [ ] **Step 4: TEST 22 — wrong ath**

```
=== TEST 22: wrong ath value in proof — 401
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local cjson = require("cjson.safe")
            local bogus_ath = h.sha256_b64url("not the real access token")
            local f = h.valid_flow("ES256", { ath = bogus_ath })
            local httpc = require("resty.http").new()
            local res = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP " .. f.access_token,
                        ["DPoP"] = f.proof,
                    },
                }
            )
            local body = cjson.decode(res.body or "{}") or {}
            ngx.say("status: " .. res.status)
            ngx.say("error: " .. (body.error or "?"))
        }
    }
--- response_body
status: 401
error: invalid_dpop_proof
```

- [ ] **Step 5: TEST 23 — JKT binding mismatch (cnf.jkt ≠ thumbprint of proof JWK)**

```
=== TEST 23: cnf.jkt does not match proof JWK thumbprint — 401
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local cjson = require("cjson.safe")
            -- Two independent EC key pairs.
            local p1, jwk1, _t1 = h.new_ec_keypair("prime256v1")
            local _p2, _jwk2, t2 = h.new_ec_keypair("prime256v1")
            -- Access token binds to KEY 2, but proof is signed by KEY 1.
            local at = h.make_alg_none_access_token(t2)
            local proof = h.make_dpop_proof({
                pkey = p1, jwk = jwk1, alg = "ES256",
                htm = "GET",
                htu = "http://localhost/hello",
                iat = ngx.time(),
                jti = "jkt-mismatch-" .. tostring(ngx.now()),
                ath = h.sha256_b64url(at),
            })
            local httpc = require("resty.http").new()
            local res = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP " .. at,
                        ["DPoP"] = proof,
                    },
                }
            )
            local body = cjson.decode(res.body or "{}") or {}
            ngx.say("status: " .. res.status)
            ngx.say("error: " .. (body.error or "?"))
        }
    }
--- response_body
status: 401
error: invalid_dpop_proof
```

- [ ] **Step 6: TEST 24 — expired proof (iat too old)**

```
=== TEST 24: expired proof iat exceeds proof_max_age — 401
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local cjson = require("cjson.safe")
            local f = h.valid_flow("ES256", { iat = ngx.time() - 600 })
            local httpc = require("resty.http").new()
            local res = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP " .. f.access_token,
                        ["DPoP"] = f.proof,
                    },
                }
            )
            local body = cjson.decode(res.body or "{}") or {}
            ngx.say("status: " .. res.status)
            ngx.say("error: " .. (body.error or "?"))
        }
    }
--- response_body
status: 401
error: invalid_dpop_proof
```

- [ ] **Step 7: TEST 25 — future iat beyond clock skew**

```
=== TEST 25: future iat beyond clock_skew — 401
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local cjson = require("cjson.safe")
            local f = h.valid_flow("ES256", { iat = ngx.time() + 600 })
            local httpc = require("resty.http").new()
            local res = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP " .. f.access_token,
                        ["DPoP"] = f.proof,
                    },
                }
            )
            local body = cjson.decode(res.body or "{}") or {}
            ngx.say("status: " .. res.status)
            ngx.say("error: " .. (body.error or "?"))
        }
    }
--- response_body
status: 401
error: invalid_dpop_proof
```

- [ ] **Step 8: TEST 26 — replay (same proof twice)**

```
=== TEST 26: same proof replayed → first 200, second 401
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local cjson = require("cjson.safe")
            -- Pin jti so we know both requests use the same proof bytes.
            local f = h.valid_flow("ES256", { jti = "replay-fixed-jti" })
            local httpc = require("resty.http").new()
            local r1 = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP " .. f.access_token,
                        ["DPoP"] = f.proof,
                    },
                }
            )
            local r2 = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP " .. f.access_token,
                        ["DPoP"] = f.proof,
                    },
                }
            )
            ngx.say("first: " .. r1.status)
            ngx.say("second: " .. r2.status)
            local b2 = cjson.decode(r2.body or "{}") or {}
            ngx.say("second_error: " .. (b2.error or "?"))
        }
    }
--- response_body
first: 200
second: 401
second_error: invalid_dpop_proof
```

- [ ] **Step 9: TEST 27 — empty jti**

```
=== TEST 27: empty jti claim — 401
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local cjson = require("cjson.safe")
            local f = h.valid_flow("ES256", { jti = "" })
            local httpc = require("resty.http").new()
            local res = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP " .. f.access_token,
                        ["DPoP"] = f.proof,
                    },
                }
            )
            local body = cjson.decode(res.body or "{}") or {}
            ngx.say("status: " .. res.status)
            ngx.say("error: " .. (body.error or "?"))
        }
    }
--- response_body
status: 401
error: invalid_dpop_proof
```

- [ ] **Step 10: TEST 28 — alg=none proof attack**

```
=== TEST 28: proof with alg=none and empty signature — 401
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local cjson = require("cjson.safe")
            local pkey, jwk, tp = h.new_ec_keypair("prime256v1")
            local at = h.make_alg_none_access_token(tp)
            local proof = h.make_dpop_proof({
                pkey = pkey, jwk = jwk, alg = "none",
                htm = "GET",
                htu = "http://localhost/hello",
                iat = ngx.time(),
                jti = "alg-none-" .. tostring(ngx.now()),
                ath = h.sha256_b64url(at),
                raw_signature = "",
            })
            local httpc = require("resty.http").new()
            local res = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP " .. at,
                        ["DPoP"] = proof,
                    },
                }
            )
            local body = cjson.decode(res.body or "{}") or {}
            ngx.say("status: " .. res.status)
            ngx.say("error: " .. (body.error or "?"))
        }
    }
--- response_body
status: 401
error: invalid_dpop_proof
```

- [ ] **Step 11: TEST 29 — proof JWK contains private key parameter `d`**

```
=== TEST 29: proof JWK contains private key parameter — 401
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local cjson = require("cjson.safe")
            local pkey, jwk, tp = h.new_ec_keypair("prime256v1")
            -- Inject a private-key-shaped parameter; bytes content is irrelevant
            -- because the plugin must reject by shape before any crypto check.
            jwk.d = h.b64url_encode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            local at = h.make_alg_none_access_token(tp)
            local proof = h.make_dpop_proof({
                pkey = pkey, jwk = jwk, alg = "ES256",
                htm = "GET",
                htu = "http://localhost/hello",
                iat = ngx.time(),
                jti = "private-jwk-" .. tostring(ngx.now()),
                ath = h.sha256_b64url(at),
            })
            local httpc = require("resty.http").new()
            local res = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP " .. at,
                        ["DPoP"] = proof,
                    },
                }
            )
            local body = cjson.decode(res.body or "{}") or {}
            ngx.say("status: " .. res.status)
            ngx.say("error: " .. (body.error or "?"))
        }
    }
--- response_body
status: 401
error: invalid_dpop_proof
```

- [ ] **Step 12: TEST 30 — multiple DPoP headers**

```
=== TEST 30: request with two DPoP headers — 401
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local cjson = require("cjson.safe")
            -- Two valid proofs (different jti) signed by the same key.
            local pkey, jwk, tp = h.new_ec_keypair("prime256v1")
            local at = h.make_alg_none_access_token(tp)
            local ath = h.sha256_b64url(at)
            local make = function(jti)
                return h.make_dpop_proof({
                    pkey = pkey, jwk = jwk, alg = "ES256",
                    htm = "GET",
                    htu = "http://localhost/hello",
                    iat = ngx.time(), jti = jti, ath = ath,
                })
            end
            local p1 = make("multi-1")
            local p2 = make("multi-2")
            local httpc = require("resty.http").new()
            local res = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP " .. at,
                        -- Array value emits two DPoP headers.
                        ["DPoP"] = { p1, p2 },
                    },
                }
            )
            local body = cjson.decode(res.body or "{}") or {}
            ngx.say("status: " .. res.status)
            ngx.say("error: " .. (body.error or "?"))
        }
    }
--- response_body
status: 401
error: invalid_dpop_proof
```

- [ ] **Step 13: Run full suite in Docker**

```bash
docker build -f t/ci-test.Dockerfile -t apisix-dpop-test .
docker run --rm apisix-dpop-test
```

Expected: `All tests successful.` with `Files=1, Tests=N` where N ≈ 90 (54 prior + ~36 new from 12 negative tests at ~3 subtests each, give or take by directive count).

If any test fails, look at the failure carefully:

- **`got: status: 200, error: ?` instead of `status: 401`**: The plugin accepted a proof that the test expected to be rejected. Either the override didn't take effect, or the plugin is missing the corresponding check.
- **`got: status: 401, error: <something else>`** and the something else is `invalid_token` rather than `invalid_dpop_proof`: this means the plugin failed at the access-token stage instead of the proof stage. The cnf.jkt path for that test is wrong; verify the access token is using the matching thumbprint.
- **TEST 26 second 200 instead of 401**: replay cache is not active. Double-check the route config has not been modified and the plugin defaults to a working memory cache.
- **TEST 29 200 instead of 401**: Task 3 was skipped or the guard didn't land in `get_or_create_pkey`.

If a regex/wording mismatch causes a near-miss (status correct, error close), update the test's expected `error:` line to match what the plugin actually emits (the goal is asserting the OAuth error code, which is `invalid_dpop_proof`). Do not weaken the status check.

- [ ] **Step 14: Commit**

```bash
git add t/plugin/dpop.t
git commit -m "test(plugin): add negative DPoP claim validation tests (19-30)"
```

---

## Task 5: Push the branch

- [ ] **Step 1: Push**

```bash
git push
```

Expected: branch updates `feat/plugin-dpop-test-infra` on origin with the four new commits.

- [ ] **Step 2: Final state check**

```bash
git log --oneline -10
```

Expected (top to bottom, newest first):

```
<sha> test(plugin): add negative DPoP claim validation tests (19-30)
<sha> fix(plugin): reject DPoP proof JWK containing private key parameters
<sha> test(plugin): refactor happy-path DPoP tests to use shared helper
<sha> test(infra): add lib/dpop helper module for test-nginx
<sha> docs(spec): correct TEST 30 multi-header implementation note
<sha> docs(spec): design for DPoP integration test expansion
<sha> fix(test): correct DER offset in ES256/ES384 der_to_raw helper
<sha> fix(plugin): preserve empty trailing segments when splitting JWT
<sha> test(infra): add containerized test runner for DPoP plugin
<sha> test(plugin): expand DPoP test suite with full crypto flow coverage
```

The four newest commits are the cherry-pick candidates for `feat/plugin-dpop` when the PR is being cleaned up. The Dockerfile commit and the spec/plan docs stay on this branch only.

---

## Notes on cherry-picking back to `feat/plugin-dpop` (later)

When the test-infra branch has been validated end-to-end on amd64 and you are ready to tighten up the PR, cherry-pick the four implementation commits in this order:

1. `test(infra): add lib/dpop helper module for test-nginx`
2. `test(plugin): refactor happy-path DPoP tests to use shared helper`
3. `fix(plugin): reject DPoP proof JWK containing private key parameters`
4. `test(plugin): add negative DPoP claim validation tests (19-30)`

Do not cherry-pick the Dockerfile commit (`e0354e1`) or the docs/superpowers commits. They live on this branch.
