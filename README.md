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
output:
```
/hello
/user/:name
/user/:name/age/:age
nil
nil
/user/:name/age/:age:xiangnan:22
```
# install
```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/xiangnanscu/lua-resty-rax/main/install.sh)"
```
command above assumes you install openresty in `/usr/local/openresty`, in fact its content is:
```
git clone https://github.com/xiangnanscu/lua-resty-rax.git --depth=1
cd lua-resty-rax
make && INST_PREFIX=/usr/local/openresty/luajit make install && make clean
```
