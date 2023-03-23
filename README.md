# lua-resty-rax
High performance router for openresty web, focus on mapping string to hanlder.
# Synopsis
```lua
local Radix = require("resty.rax")
-- make a rx instance with initial routes
local rx = Radix.new({
  { path = { "/user/:name/age/#age" }, handler = "/user/:name/age/#age", method = { 'GET', 'POST' } },
  { path = { "/user/:name" },          handler = "/user/:name" }
})
-- insert a route
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
/user/:name/age/#age:xiangnan:22
nilfailed to match
nilfailed to match
```
# api
## Radix.new
make a router
```lua
---@param routes? {path: string|string[], handler: any,  method?: string|string[]}[]
---@return Radix
function Radix.new(routes)
end
```
example:
```lua
local rx = Radix.new({
  { path = { "/user/:name/age/#age" }, handler = "/user/:name/age/#age", method = { 'GET', 'POST' } },
  { path = { "/user/:name" },          handler = "/user/:name" }
})
```
## Radix.insert
insert a route. `path` can be a static string, or params string like `/:foo`(match any string ) or `/#id`(match number string) or `/*all` (match any string including `/`). when `method` not provided, means this route matchs any method.
```lua
---@param self Radix
---@param path string
---@param route {handler: any,  method?: string|string[]}
---@return boolean
function Radix.insert(self, path, route)
end
```
example:
```lua
rx:insert("/foo", { handler = "foo" })
rx:insert("/bar", { handler = function(request) return "bar" end, method = 'GET' })
rx:insert("/baz", { handler = "baz", method = { "get", "post" } })
rx:insert("/number/#id", { handler = "number" })
```
## Radix.match
match router from a string. if `method` not provided and the route is created with method, matching will fail even if `path` matches.
if a static route is matched, the handler defined in route will be returned. if a dynamic route is matched, the handler and the matching table will be returned.
```lua
---@param self Radix
---@param path string
---@param method? string
---@return any, (string|table)?, number?
function Radix.match(self, path, method)
end
```
example:
```lua
rx:match("/fooo")         --fail
rx:match("/foo")          --ok
rx:match("/foo", "GET")   --ok
rx:match("/foo", "post")  --ok
rx:match("/bar", "GET")   --ok
rx:match("/bar", "post")  --fail
rx:match("/baz", "GET")   --ok
rx:match("/baz", "post")  --ok
rx:match("/bar", "patch") --fail
local handler, matched = rx:match("/number/5") -- ok, handler = "number", matched = {id = 5}
```
# install
```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/xiangnanscu/lua-resty-rax/main/install.sh)"
```
command above assumes you install openresty in `/usr/local/openresty`, in fact its content is:
```
cd /tmp
rm -rf lua-resty-rax
git clone https://github.com/xiangnanscu/lua-resty-rax.git --depth=1
cd lua-resty-rax
make && INST_PREFIX=/usr/local/openresty make install && make clean
```
