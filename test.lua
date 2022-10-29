local radix = require("resty.rax")
local inspect = require("resty.inspect")
local json = require("cjson.safe")
local rx = radix.new({
    {
        paths = {"/user/:user/age/#age"},
        metadata = "/user/:user/age/#age",
    },
    {
        paths = {"/user/:user"},
        metadata = "/user/:user",
    }
})
ngx.say(inspect(rx))
local meta_a = rx:match("/user/foo")
ngx.say("match meta: ", meta_a)

local meta_b, m = rx:match("/user/foo/age/29e",nil, {})
ngx.say("match meta: ", meta_b)
ngx.say(inspect(m))