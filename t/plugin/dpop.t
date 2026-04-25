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
            local h = require("lib.dpop")
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



=== TEST 16: ES384 algorithm — full DPoP flow
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local f = h.valid_flow("ES384")
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



=== TEST 17: RS256 algorithm — full DPoP flow
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local f = h.valid_flow("RS256")
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



=== TEST 18: PS256 algorithm (RSA-PSS) — full DPoP flow
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.dpop")
            local f = h.valid_flow("PS256")
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
