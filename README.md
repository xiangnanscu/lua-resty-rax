# lua-resty-rax
High performance router for openresty web, focus on mapping string to hanlder.
# Synopsis
```lua
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
```
output:
```
nilfailed to match
/user/:name
/user/:name/age/:age:xiangnan:22
nilfailed to match
nilfailed to match
```
# install
```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/xiangnanscu/lua-resty-rax/main/install.sh)"
```
command above assumes you install openresty in `/usr/local/openresty`, in fact its content is:
```
git clone https://github.com/xiangnanscu/lua-resty-rax.git --depth=1
cd lua-resty-rax
make && make install && make clean
```
