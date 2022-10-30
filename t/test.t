# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

repeat_each(1);
run_tests();

__DATA__

=== TEST 1: /name/*name
--- config
    location /t {
        content_by_lua_block {
            local json = require("cjson.safe")
            local radix = require("resty.rax")
            local rx = radix.new({
                {
                    paths = {"/name/:name"},
                    metadata = "metadata /name",
                },
            })

            local opts = {}
            local meta = rx:match("/name/json", nil, opts)
            ngx.say("match meta: ", meta)
            ngx.say("matched: ", json.encode(opts))

            meta = rx:match("/name/", opts)
            ngx.say("match meta: ", meta)
            ngx.say("matched: ", json.encode(opts))
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- response_body
match meta: metadata /name
matched: {"name":"json"}
match meta: metadata /name
matched: {"name":""}