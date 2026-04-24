#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
use t::APISIX 'no_plan';

repeat_each(1);
no_long_string();
no_root_location();
no_shuffle();

add_block_preprocessor(sub {
    my ($block) = @_;

    if (!defined $block->yaml_config) {
        my $yaml_config = <<_EOC_;
apisix:
  node_listen: 1984
plugins:
  - dpop
  - example-plugin
  - key-auth
_EOC_
        $block->set_value("yaml_config", $yaml_config);
    }

    if ((!defined $block->error_log) && (!defined $block->no_error_log)) {
        $block->set_value("no_error_log", "[error]");
    }

    if (!defined $block->request) {
        $block->set_value("request", "GET /t");
    }
});

run_tests();

__DATA__

=== TEST 1: schema — valid minimal config (defaults)
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.dpop")
            local ok, err = plugin.check_schema({})
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say("done")
        }
    }
--- response_body
done



=== TEST 2: schema — valid config with discovery
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.dpop")
            local ok, err = plugin.check_schema({
                discovery = "http://127.0.0.1:8080/.well-known/openid-configuration",
                allowed_algs = {"ES256", "RS256"},
                proof_max_age = 60,
                clock_skew_seconds = 10,
            })
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say("done")
        }
    }
--- response_body
done



=== TEST 3: schema — enforce_introspection requires introspection_endpoint
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.dpop")
            local ok, err = plugin.check_schema({
                enforce_introspection = true,
            })
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say("done")
        }
    }
--- response_body
enforce_introspection=true requires introspection_endpoint



=== TEST 4: schema — strict_htu requires public_base_url
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.dpop")
            local ok, err = plugin.check_schema({
                strict_htu = true,
            })
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say("done")
        }
    }
--- response_body
strict_htu=true requires public_base_url



=== TEST 5: schema — replay_cache.ttl too small triggers security error
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.dpop")
            local ok, err = plugin.check_schema({
                proof_max_age = 120,
                clock_skew_seconds = 5,
                replay_cache = {
                    type = "memory",
                    ttl = 60,
                },
            })
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say("done")
        }
    }
--- response_body_like
SECURITY ERROR: replay_cache\.ttl.*must be >= proof_max_age.*



=== TEST 6: schema — replay_cache.type=redis requires redis.host
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.dpop")
            local ok, err = plugin.check_schema({
                replay_cache = {
                    type = "redis",
                },
            })
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say("done")
        }
    }
--- response_body
replay_cache.type=redis requires replay_cache.redis.host



=== TEST 7: schema — valid enforce_introspection with endpoint
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.dpop")
            local ok, err = plugin.check_schema({
                enforce_introspection = true,
                introspection_endpoint = "http://127.0.0.1:8080/introspect",
                introspection_client_id = "client1",
                introspection_client_secret = "secret1",
            })
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say("done")
        }
    }
--- response_body
done



=== TEST 8: set up route with dpop plugin
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1',
                ngx.HTTP_PUT,
                [[{
                    "plugins": {
                        "dpop": {
                            "verify_access_token": false,
                            "allowed_algs": ["ES256","ES384","RS256","PS256"]
                        }
                    },
                    "upstream": {
                        "nodes": {
                            "127.0.0.1:1980": 1
                        },
                        "type": "roundrobin"
                    },
                    "uri": "/hello"
                }]]
                )
            if code >= 300 then
                ngx.status = code
            end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 9: request without Authorization header — 401
--- request
GET /hello
--- error_code: 401
--- response_body_like
invalid_dpop_proof.*



=== TEST 10: request with unsupported scheme — 401
--- request
GET /hello
--- more_headers
Authorization: Basic dXNlcjpwYXNz
--- error_code: 401
--- response_body_like
invalid_dpop_proof.*



=== TEST 11: request with DPoP scheme but missing DPoP proof header — 401
--- request
GET /hello
--- more_headers
Authorization: DPoP eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fake
--- error_code: 401
--- response_body_like
missing DPoP proof header.*



=== TEST 12: set up route with uri_allow for selective enforcement
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/2',
                ngx.HTTP_PUT,
                [[{
                    "plugins": {
                        "dpop": {
                            "verify_access_token": false,
                            "uri_allow": ["/protected"]
                        }
                    },
                    "upstream": {
                        "nodes": {
                            "127.0.0.1:1980": 1
                        },
                        "type": "roundrobin"
                    },
                    "uri": "/public"
                }]]
                )
            if code >= 300 then
                ngx.status = code
            end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 13: uri_allow bypass — schema accepts config
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.dpop")
            local ok, err = plugin.check_schema({
                uri_allow = {"/protected", "/admin/*"},
            })
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say("done")
        }
    }
--- response_body
done



=== TEST 14: DPoP proof with invalid JWT format — 401
--- request
GET /hello
--- more_headers
Authorization: DPoP eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fake
DPoP: not-a-valid-jwt
--- error_code: 401
--- response_body_like
invalid_dpop_proof.*



=== TEST 15: generate valid DPoP proof (ES256) and verify full flow
--- config
    location /t {
        content_by_lua_block {
            local cjson = require("cjson.safe")
            local openssl_pkey = require("resty.openssl.pkey")
            local resty_sha256 = require("resty.sha256")

            local function b64url_encode(input)
                local b64 = ngx.encode_base64(input)
                return b64:gsub("+", "-"):gsub("/", "_"):gsub("=", "")
            end

            -- DER ECDSA sig → raw R||S for JWS
            local function der_to_raw(der, size)
                -- DER layout: 0x30 <seq_len> 0x02 <r_len> <r...> 0x02 <s_len> <s...>
                -- pos starts at 4 (skipping 0x30, seq_len, and the 0x02 r INTEGER tag)
                local pos = 4
                local r_len = der:byte(pos)
                pos = pos + 1
                local r = der:sub(pos, pos + r_len - 1)
                pos = pos + r_len + 1
                local s_len = der:byte(pos)
                pos = pos + 1
                local s = der:sub(pos, pos + s_len - 1)
                while #r > size do r = r:sub(2) end
                while #s > size do s = s:sub(2) end
                while #r < size do r = "\0" .. r end
                while #s < size do s = "\0" .. s end
                return r .. s
            end

            local pkey = openssl_pkey.new({
                type = "EC", curve = "prime256v1"
            })
            local params = pkey:get_parameters()
            local jwk = {
                kty = "EC", crv = "P-256",
                x = b64url_encode(params.x:to_binary()),
                y = b64url_encode(params.y:to_binary()),
            }

            local tp_input = '{"crv":"P-256"'
                .. ',"kty":"EC"'
                .. ',"x":"' .. jwk.x .. '"'
                .. ',"y":"' .. jwk.y .. '"}'
            local sha = resty_sha256:new()
            sha:update(tp_input)
            local thumbprint = b64url_encode(sha:final())

            local at_h = b64url_encode(
                cjson.encode({alg = "none", typ = "JWT"})
            )
            local at_p = b64url_encode(cjson.encode({
                sub = "testuser",
                cnf = { jkt = thumbprint },
                exp = ngx.time() + 3600,
            }))
            local access_token = at_h .. "." .. at_p .. "."

            local dpop_h = cjson.encode({
                typ = "dpop+jwt", alg = "ES256", jwk = jwk,
            })
            local dpop_p = cjson.encode({
                htm = "GET",
                htu = "http://localhost/hello",
                iat = ngx.time(),
                jti = "es256-" .. tostring(ngx.now()),
                ath = b64url_encode((function()
                    local s2 = resty_sha256:new()
                    s2:update(access_token)
                    return s2:final()
                end)()),
            })
            local si = b64url_encode(dpop_h)
                .. "." .. b64url_encode(dpop_p)
            local der_sig = pkey:sign(si, "sha256")
            local raw_sig = der_to_raw(der_sig, 32)
            local proof = si .. "." .. b64url_encode(raw_sig)

            local http = require("resty.http")
            local httpc = http.new()
            local res, err = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP "
                            .. access_token,
                        ["DPoP"] = proof,
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



=== TEST 16: ES384 algorithm — full DPoP flow
--- config
    location /t {
        content_by_lua_block {
            local cjson = require("cjson.safe")
            local openssl_pkey = require("resty.openssl.pkey")
            local resty_sha256 = require("resty.sha256")

            local function b64url_encode(input)
                local b64 = ngx.encode_base64(input)
                return b64:gsub("+", "-"):gsub("/", "_"):gsub("=", "")
            end

            local function der_to_raw(der, size)
                -- DER layout: 0x30 <seq_len> 0x02 <r_len> <r...> 0x02 <s_len> <s...>
                -- pos starts at 4 (skipping 0x30, seq_len, and the 0x02 r INTEGER tag)
                local pos = 4
                local r_len = der:byte(pos)
                pos = pos + 1
                local r = der:sub(pos, pos + r_len - 1)
                pos = pos + r_len + 1
                local s_len = der:byte(pos)
                pos = pos + 1
                local s = der:sub(pos, pos + s_len - 1)
                while #r > size do r = r:sub(2) end
                while #s > size do s = s:sub(2) end
                while #r < size do r = "\0" .. r end
                while #s < size do s = "\0" .. s end
                return r .. s
            end

            local pkey = openssl_pkey.new({
                type = "EC", curve = "secp384r1"
            })
            local params = pkey:get_parameters()
            local jwk = {
                kty = "EC", crv = "P-384",
                x = b64url_encode(params.x:to_binary()),
                y = b64url_encode(params.y:to_binary()),
            }

            local tp = '{"crv":"P-384"'
                .. ',"kty":"EC"'
                .. ',"x":"' .. jwk.x .. '"'
                .. ',"y":"' .. jwk.y .. '"}'
            local sha = resty_sha256:new()
            sha:update(tp)
            local thumbprint = b64url_encode(sha:final())

            local at_h = b64url_encode(
                cjson.encode({alg = "none", typ = "JWT"})
            )
            local at_p = b64url_encode(cjson.encode({
                sub = "testuser",
                cnf = { jkt = thumbprint },
                exp = ngx.time() + 3600,
            }))
            local access_token = at_h .. "." .. at_p .. "."

            local dpop_h = cjson.encode({
                typ = "dpop+jwt", alg = "ES384", jwk = jwk,
            })
            local dpop_p = cjson.encode({
                htm = "GET",
                htu = "http://localhost/hello",
                iat = ngx.time(),
                jti = "es384-" .. tostring(ngx.now()),
                ath = b64url_encode((function()
                    local s2 = resty_sha256:new()
                    s2:update(access_token)
                    return s2:final()
                end)()),
            })
            local si = b64url_encode(dpop_h)
                .. "." .. b64url_encode(dpop_p)
            local der_sig = pkey:sign(si, "sha384")
            local raw_sig = der_to_raw(der_sig, 48)
            local proof = si .. "." .. b64url_encode(raw_sig)

            local http = require("resty.http")
            local httpc = http.new()
            local res, err = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP "
                            .. access_token,
                        ["DPoP"] = proof,
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



=== TEST 17: RS256 algorithm — full DPoP flow
--- config
    location /t {
        content_by_lua_block {
            local cjson = require("cjson.safe")
            local openssl_pkey = require("resty.openssl.pkey")
            local resty_sha256 = require("resty.sha256")

            local function b64url_encode(input)
                local b64 = ngx.encode_base64(input)
                return b64:gsub("+", "-"):gsub("/", "_"):gsub("=", "")
            end

            local pkey = openssl_pkey.new({
                type = "RSA", bits = 2048
            })
            local rp = pkey:get_parameters()
            local jwk = {
                kty = "RSA",
                n = b64url_encode(rp.n:to_binary()),
                e = b64url_encode(rp.e:to_binary()),
            }

            local tp = '{"e":"' .. jwk.e .. '"'
                .. ',"kty":"RSA"'
                .. ',"n":"' .. jwk.n .. '"}'
            local sha = resty_sha256:new()
            sha:update(tp)
            local thumbprint = b64url_encode(sha:final())

            local at_h = b64url_encode(
                cjson.encode({alg = "none", typ = "JWT"})
            )
            local at_p = b64url_encode(cjson.encode({
                sub = "testuser",
                cnf = { jkt = thumbprint },
                exp = ngx.time() + 3600,
            }))
            local access_token = at_h .. "." .. at_p .. "."

            local dpop_h = cjson.encode({
                typ = "dpop+jwt", alg = "RS256", jwk = jwk,
            })
            local dpop_p = cjson.encode({
                htm = "GET",
                htu = "http://localhost/hello",
                iat = ngx.time(),
                jti = "rs256-" .. tostring(ngx.now()),
                ath = b64url_encode((function()
                    local s2 = resty_sha256:new()
                    s2:update(access_token)
                    return s2:final()
                end)()),
            })
            local si = b64url_encode(dpop_h)
                .. "." .. b64url_encode(dpop_p)
            -- RSA sig is already in correct format
            local sig = pkey:sign(si, "sha256")
            local proof = si .. "." .. b64url_encode(sig)

            local http = require("resty.http")
            local httpc = http.new()
            local res, err = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP "
                            .. access_token,
                        ["DPoP"] = proof,
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



=== TEST 18: PS256 algorithm (RSA-PSS) — full DPoP flow
--- config
    location /t {
        content_by_lua_block {
            local cjson = require("cjson.safe")
            local openssl_pkey = require("resty.openssl.pkey")
            local resty_sha256 = require("resty.sha256")

            local function b64url_encode(input)
                local b64 = ngx.encode_base64(input)
                return b64:gsub("+", "-"):gsub("/", "_"):gsub("=", "")
            end

            local pkey = openssl_pkey.new({
                type = "RSA", bits = 2048
            })
            local rp = pkey:get_parameters()
            local jwk = {
                kty = "RSA",
                n = b64url_encode(rp.n:to_binary()),
                e = b64url_encode(rp.e:to_binary()),
            }

            local tp = '{"e":"' .. jwk.e .. '"'
                .. ',"kty":"RSA"'
                .. ',"n":"' .. jwk.n .. '"}'
            local sha = resty_sha256:new()
            sha:update(tp)
            local thumbprint = b64url_encode(sha:final())

            local at_h = b64url_encode(
                cjson.encode({alg = "none", typ = "JWT"})
            )
            local at_p = b64url_encode(cjson.encode({
                sub = "testuser",
                cnf = { jkt = thumbprint },
                exp = ngx.time() + 3600,
            }))
            local access_token = at_h .. "." .. at_p .. "."

            local dpop_h = cjson.encode({
                typ = "dpop+jwt", alg = "PS256", jwk = jwk,
            })
            local dpop_p = cjson.encode({
                htm = "GET",
                htu = "http://localhost/hello",
                iat = ngx.time(),
                jti = "ps256-" .. tostring(ngx.now()),
                ath = b64url_encode((function()
                    local s2 = resty_sha256:new()
                    s2:update(access_token)
                    return s2:final()
                end)()),
            })
            local si = b64url_encode(dpop_h)
                .. "." .. b64url_encode(dpop_p)
            -- PSS padding via pkey_ctrl_str
            local sig = pkey:sign(si, "sha256", nil,
                {{"rsa_padding_mode", "pss"}})
            local proof = si .. "." .. b64url_encode(sig)

            local http = require("resty.http")
            local httpc = http.new()
            local res, err = httpc:request_uri(
                "http://127.0.0.1:1984/hello",
                {
                    method = "GET",
                    headers = {
                        ["Authorization"] = "DPoP "
                            .. access_token,
                        ["DPoP"] = proof,
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
