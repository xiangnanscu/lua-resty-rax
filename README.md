# lua-resty-rax
High performance router for openresty web (trim [lua-resty-radixtree](https://github.com/api7/lua-resty-radixtree) for web framework)
# Synopsis
```lua
local radix = require("resty.rax")
local rx = radix.new({
  {paths = {"/user/:name/age/:age(\\d+)"}, metadata = "/user/:name/age/:age", methods = {'GET', 'POST'}},
  {paths = {"/user/:name"}, metadata = "/user/:name"}
})
rx:insert("/hello", {metadata = "/hello", methods = 'GET'})
ngx.say(rx:match("/hello"))
ngx.say(rx:match("/user/xiangnan"))
ngx.say(rx:match("/user/xiangnan/age/22", "GET"))
ngx.say(rx:match("/user/xiangnan/age/22", "PUT"))
ngx.say(rx:match("/user/xiangnan/age/not_matched", "GET"))
local data, matched = rx:match("/user/xiangnan/age/22", "GET", {})
ngx.say(data, ':',matched.name, ':',matched.age)
```
# install
If you install openresty in `/usr/local/openresty`, then:
```
make && INST_PREFIX=/usr/local/openresty/luajit make install
```
