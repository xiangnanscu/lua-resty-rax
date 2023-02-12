local radix = require("resty.rax")
local rx = radix.new({
        { path = { "/user/:name/age/#age" }, handler = "/user/:name/age/:age", method = { 'GET', 'POST' } },
        { path = { "/user/:name" },          handler = "/user/:name" }
    })
rx:insert("/hello", { handler = "/hello", method = 'GET' })
-- test matching
ngx.say(rx:match("/hello"))
ngx.say(rx:match("/user/xiangnan"))
local data, matched = rx:match("/user/xiangnan/age/22", "GET")
ngx.say(data, ':', matched.name, ':', matched.age)
ngx.say(rx:match("/user/xiangnan/age/22", "PUT"))
ngx.say(rx:match("/user/xiangnan/age/not_matched", "GET"))
