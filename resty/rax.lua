-- https://github.com/xiangnanscu/lua-resty-rax
-- derived from:
-- https://github.com/api7/lua-resty-radixtree
--
-- Copyright 2019-2020 Shenzhen ZhiLiu Technology Co., Ltd.
-- https://www.apiseven.com
--
-- See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The owner licenses this file to You under the Apache License, Version 2.0;
-- you may not use this file except in compliance with
-- the License. You may obtain a copy of the License at
--
--    http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local bit           = require("bit")
local ngx_re        = require("ngx.re")
local base          = require("resty.core.base")
local ffi           = require("ffi")
local ngx           = ngx
local table         = table
local new_tab       = base.new_tab
local tonumber      = tonumber
local ipairs        = ipairs
local table_insert  = table.insert
local table_concat  = table.concat
local string        = string
local getmetatable  = getmetatable
local setmetatable  = setmetatable
local type          = type
local error         = error
local newproxy      = newproxy
local re_match      = ngx.re.match
local str_find      = string.find
local re_split      = ngx_re.split

local COLON_BYTE    = string.byte(":")
local ASTERISK_BYTE = string.byte("*")
local INTEGER_BYTE  = string.byte("#")

local function load_shared_lib(so_name)
  local cpath = package.cpath
  local tried_paths = new_tab(32, 0)
  local i = 1
  for k, _ in string.gmatch(cpath, "[^;]+") do
    local fpath = string.match(k, "(.*/)")
    fpath = fpath .. so_name
    -- Don't get me wrong, the only way to know if a file exist is trying
    -- to open it.
    local f = io.open(fpath)
    if f ~= nil then
      io.close(f)
      return ffi.load(fpath)
    end
    tried_paths[i] = fpath
    i = i + 1
  end
  error(string.format("can't find %s, tried path:", so_name, table_concat(tried_paths, ',')))
end

local so_name
if ffi.os == 'OSX' then
  so_name = 'librax.dylib'
else
  so_name = 'librax.so'
end
---@class radix_c
---@field radix_tree_new function
---@field radix_tree_new_it function
---@field radix_tree_destroy function
---@field radix_tree_find function
---@field radix_tree_insert function
---@field radix_tree_prev function
---@field radix_tree_search function
---@field radix_tree_stop function
local radix_c = load_shared_lib(so_name)

ffi.cdef [[
    int memcmp(const void *s1, const void *s2, size_t n);

    void *radix_tree_new();
    int radix_tree_destroy(void *t);
    int radix_tree_insert(void *t, const unsigned char *buf, size_t len,
        int idx);
    void *radix_tree_find(void *t, const unsigned char *buf, size_t len);
    void *radix_tree_search(void *t, void *it, const unsigned char *buf,
        size_t len);
    int radix_tree_prev(void *it, const unsigned char *buf, size_t len);
    int radix_tree_stop(void *it);

    void *radix_tree_new_it(void *t);
]]


---@type {string:number}
local METHODS_BITS = {}
for i, name in ipairs({ "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE", "PURGE" }) do
  METHODS_BITS[name] = bit.lshift(1, i - 1)
end

---@class Radix
---@field hash_path {string:any}
---@field match_data {number:any}
---@field tree any
---@field tree_it any
local Radix = {}

-- only work under lua51 or luajit
local function setmt__gc(t, mt)
  local prox = newproxy(true)
  getmetatable(prox).__gc = function()
    mt.__gc(t)
  end
  t[prox] = true
  return setmetatable(t, mt)
end

local function gc_free(self)
  -- if ngx.worker.exiting() then
  --     return
  -- end

  self:free()
end

local RadixMeta = { __index = Radix, __gc = gc_free }

---@param path string
---@return string, string[]
local function fetch_pattern(path)
  local res = re_split(path, "/", "jo")
  if not res then
    error("failed to split path")
  end
  local names = {}
  for i, item in ipairs(res) do
    local first_byte = item:byte(1, 1)
    if first_byte == COLON_BYTE then
      local name = res[i]:sub(2)
      if name == "" then
        error("empty name for parameter is not allowed")
      end
      table_insert(names, name)
      -- See https://www.rfc-editor.org/rfc/rfc1738.txt BNF for specific URL schemes
      res[i] = [=[([\w\-_;:@&=!',\%\$\.\+\*\(\)]+)]=]
    elseif first_byte == INTEGER_BYTE then
      local name = res[i]:sub(2)
      if name == "" then
        error("empty name for parameter is not allowed")
      end
      table_insert(names, name)
      res[i] = [[(\d+)]]
    elseif first_byte == ASTERISK_BYTE then
      local name = res[i]:sub(2)
      if name == "" then
        name = ":ext"
      end
      table_insert(names, name)
      -- '.' matches any character except newline
      res[i] = [=[((.|\n)*)]=]
    end
  end
  if #names == 0 then
    error("parameter character (:#*) must be preceded with /")
  end
  return table_concat(res, [[/]]), names
end

local function match_route_method(route, method)
  if route.method == 0 then
    return true
  end
  if not method or not METHODS_BITS[method] or bit.band(route.method, METHODS_BITS[method]) == 0 then
    return false
  end
  return true
end

---@param routes? {path: string|string[], handler: any,  method?: string|string[]}[]
---@return Radix
function Radix.new(routes)
  local tree = radix_c.radix_tree_new()
  local tree_it = radix_c.radix_tree_new_it(tree)
  if tree_it == nil then
    error("failed to new radixtree iterator")
  end
  if routes == nil then
    routes = {}
  end
  local self = setmt__gc({
    tree = tree,
    tree_it = tree_it,
    match_data_index = 0,
    match_data = new_tab(#routes, 0),
    hash_path = new_tab(0, #routes)
  }, RadixMeta)
  local route_n = #routes
  -- register routes
  for i = 1, route_n do
    local route = routes[i]
    local path = route.path
    if type(path) == "string" then
      self:insert(path, route)
    else
      for _, p in ipairs(path) do
        self:insert(p, route)
      end
    end
  end

  return self
end

---@class route_opts
---@field handler any
---@field method integer
---@field param boolean
---@field path string
---@field origin_path string
---@field match_names? string[]
---@field match_pattern? string


---@param self Radix
---@param path string
---@param route {handler: any,  method?: string|string[]}
---@return boolean
function Radix.insert(self, path, route)
  ---@type route_opts
  local route_opts = {
    origin_path = path,
    param = false,
    handler = route.handler
  }
  local method = route.method
  local bit_methods
  if not method then
    bit_methods = 0
  elseif type(method) == "string" then
    bit_methods = METHODS_BITS[method:upper()]
  elseif type(method) == "table" then
    bit_methods = 0
    for _, m in ipairs(method) do
      bit_methods = bit.bor(bit_methods, METHODS_BITS[m:upper()])
    end
  else
    error("invalid method type:" .. type(method))
  end
  route_opts.method = bit_methods

  local pos = str_find(path, '[:#]', 1)
  local static_prefix
  if pos then
    static_prefix = path:sub(1, pos - 1)
    route_opts.path = static_prefix
    route_opts.param = true
  else
    pos = str_find(path, '*', 1, true)
    if pos then
      if pos ~= #path then
        route_opts.param = true
      end
      static_prefix = path:sub(1, pos - 1)
    else
      static_prefix = path
    end
    route_opts.path = static_prefix
  end
  if static_prefix == path then
    self.hash_path[static_prefix] = route_opts
    return true
  end
  -- move fetch_pattern to insert, why not? it's fast
  if route_opts.param then
    route_opts.match_pattern, route_opts.match_names = fetch_pattern(route_opts.origin_path)
  else
    -- /foo/* or /foo*
  end

  local data_idx = radix_c.radix_tree_find(self.tree, static_prefix, #static_prefix)
  if data_idx ~= nil then
    local idx = assert(tonumber(ffi.cast('intptr_t', data_idx)))
    local routes = self.match_data[idx]
    if routes and routes[1].path == static_prefix then
      table_insert(routes, route_opts)
      return true
    end
  end

  self.match_data_index = self.match_data_index + 1
  self.match_data[self.match_data_index] = { route_opts }

  radix_c.radix_tree_insert(self.tree, static_prefix, #static_prefix, self.match_data_index)
  return true
end

---@param self Radix
---@param path string
---@param method? string
---@return any, (string|table)?, number?
function Radix.match(self, path, method)
  local hash_route = self.hash_path[path]
  if hash_route then
    if match_route_method(hash_route, method) then
      return hash_route.handler
    else
      return nil, "method not allowed", 405
    end
  end

  local it = radix_c.radix_tree_search(self.tree, self.tree_it, path, #path)
  if not it then
    return nil, "tree iterator error"
  end

  while true do
    local idx = radix_c.radix_tree_prev(it, path, #path)
    if idx <= 0 then
      break
    end
    local routes = self.match_data[idx]
    if routes then
      for _, route in ipairs(routes) do
        local handler = route.handler
        if match_route_method(route, method) then
          if not route.param then
            -- /foo/*, /foo*
            return handler
          end
          local pattern = route.match_pattern
          local names = route.match_names
          local captured = re_match(path, pattern, "jo")
          if not captured then
            goto continue
          end
          if captured[0] ~= path then
            goto continue
          end
          local matched = {}
          for i, v in ipairs(captured) do
            local name = names[i]
            if name and v then
              matched[name] = v
            end
          end
          return handler, matched
        end
        ::continue::
      end
    end
  end
  return nil, "page not found", 404
end

function Radix.free(self)
  local it = self.tree_it
  if it then
    radix_c.radix_tree_stop(it)
    ffi.C.free(it)
    self.tree_it = nil
  end

  if self.tree then
    radix_c.radix_tree_destroy(self.tree)
    self.tree = nil
  end
  return nil
end

return Radix
