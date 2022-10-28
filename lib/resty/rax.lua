-- https://github.com/xiangnan/lua-resty-rax
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
local base         = require("resty.core.base")
local clone_tab    = require("table.clone")
local bit          = require("bit")
local ngx          = ngx
local table        = table
local new_tab      = base.new_tab
local move_tab     = table.move
local tonumber     = tonumber
local ipairs       = ipairs
local ffi          = require("ffi")
local C            = ffi.C
local ffi_cast     = ffi.cast
local ffi_cdef     = ffi.cdef
local insert_tab   = table.insert
local string       = string
local getmetatable = getmetatable
local setmetatable = setmetatable
local type         = type
local error        = error
local newproxy     = newproxy
local re_match     = ngx.re.match
local ngx_re       = require("ngx.re")
local empty_table  = {}
local str_find     = string.find
local format       = string.format

setmetatable(empty_table, {
  __newindex = function()
    error("empty_table can not be changed")
  end
})

local function load_shared_lib(so_name)
  local string_gmatch = string.gmatch
  local string_match = string.match
  local io_open = io.open
  local io_close = io.close

  local cpath = package.cpath
  local tried_paths = new_tab(32, 0)
  local i = 1

  for k, _ in string_gmatch(cpath, "[^;]+") do
      local fpath = string_match(k, "(.*/)")
      fpath = fpath .. so_name
      -- Don't get me wrong, the only way to know if a file exist is trying
      -- to open it.
      local f = io_open(fpath)
      if f ~= nil then
          io_close(f)
          return ffi.load(fpath)
      end
      tried_paths[i] = fpath
      i = i + 1
    end

  error(table.concat(tried_paths, '\r\n', 1, #tried_paths))
end

local radix = load_shared_lib('librax.so')

ffi_cdef [[
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

local METHODS = {}
for i, name in ipairs({ "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE" }) do
  METHODS[name] = bit.lshift(1, i - 1)
  -- ngx.log(ngx.WARN, "name: ", name, " val: ", METHODS[name])
end

local _M = { _VERSION = 1.0 }

-- expose radix tree api for test
_M._symbols = radix

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

local mt = { __index = _M, __gc = gc_free }

local function sort_route(route_a, route_b)
  return (route_a.priority or 0) > (route_b.priority or 0)
end

local function insert_tab_in_order(tab, val, func)
  for i, elem in ipairs(tab) do
    if func(val, elem) then
      move_tab(tab, i, #tab, i + 1)
      tab[i] = val
      return
    end
  end
  insert_tab(tab, val)
end

local function insert_route(self, opts)
  local path = opts.path
  opts = clone_tab(opts)
  if opts.path_op == '=' then
    self.hash_path[path] = opts
    return true
  end

  local data_idx = radix.radix_tree_find(self.tree, path, #path)
  if data_idx ~= nil then
    local idx = tonumber(ffi_cast('intptr_t', data_idx))
    local routes = self.match_data[idx]
    if routes and routes[1].path == path then
      insert_tab_in_order(routes, opts, sort_route)
      return true
    end
  end

  self.match_data_index = self.match_data_index + 1
  self.match_data[self.match_data_index] = { opts }

  radix.radix_tree_insert(self.tree, path, #path, self.match_data_index)
  return true
end
local tmp = {}
local lru_pat, err = lrucache.new(1000)
if not lru_pat then
    error("failed to generate new lru object: " .. err)
end

local function fetch_pat(path)
  local pat = lru_pat:get(path)
  if pat then
      return pat[1], pat[2]   -- pat, names
  end

  clear_tab(tmp)
  local res = ngx_re.split(path, "/", "jo", nil, nil, tmp)
  if not res then
      return false
  end

  local names = {}
  for i, item in ipairs(res) do
      local first_byte = item:byte(1, 1)
      if first_byte == string.byte(":") then
          table.insert(names, res[i]:sub(2))
          -- See https://www.rfc-editor.org/rfc/rfc1738.txt BNF for specific URL schemes
          res[i] = [=[([\w\-_;:@&=!',\%\$\.\+\*\(\)]+)]=]

      elseif first_byte == string.byte("*") then
          local name = res[i]:sub(2)
          if name == "" then
              name = ":ext"
          end
          table.insert(names, name)
          -- '.' matches any character except newline
          res[i] = [=[((.|\n)*)]=]
      end
  end

  pat = table.concat(res, [[\/]])
  lru_pat:set(path, {pat, names}, 60 * 60)
  return pat, names
end

local function pre_insert_route(path, route)
  local route_opts = {}
  local method = route.methods
  local bit_methods
  if type(method) ~= "table" then
    bit_methods = method and METHODS[method] or 0
  else
    bit_methods = 0
    for _, m in ipairs(method) do
      bit_methods = bit.bor(bit_methods, METHODS[m])
    end
  end

  route_opts.path_org = path
  route_opts.param = false

  local pos = str_find(path, ':', 1, true)
  if pos then
    path = path:sub(1, pos - 1)
    route_opts.path_op = "<="
    route_opts.path = path
    route_opts.param = true
  else
    pos = str_find(path, '*', 1, true)
    if pos then
      if pos ~= #path then
        route_opts.param = true
      end
      path = path:sub(1, pos - 1)
      route_opts.path_op = "<="
    else
      route_opts.path_op = "="
    end
    route_opts.path = path
  end
  route_opts.metadata = route.metadata
  route_opts.method = bit_methods
  route_opts.priority = route.priority or 0
  if route_opts.param then
    route_opts.re_pat, route_opts.re_names = fetch_pat(route_opts.path_org)
  end
  return route_opts
end

local function compare_param(req_path, route, matched)
  if not matched and not route.param then
    return true
  end

  local pat = route.re_pat
  local names = route.re_names
  if #names == 0 then
    return true
  end

  local m = re_match(req_path, pat, "jo")
  if not m then
    return false
  end

  if m[0] ~= req_path then
    return false
  end

  if not matched then
    return true
  end

  for i, v in ipairs(m) do
    local name = names[i]
    if name and v then
      matched[name] = v
    end
  end
  return true
end

local function match_route_method(route, method)
  if route.method ~= 0 then
    if not method or type(METHODS[method]) ~= "number" or bit.band(route.method, METHODS[method]) == 0 then
      return false
    end
  end
  return true
end

local function _match_from_routes(routes, path, method, matched)
  -- if method == nil and matched == nil then
  --   local route = routes[1]
  --   if not route or route.method == 0 then
  --     return route
  --   end
  -- end
  for _, route in ipairs(routes) do
    if match_route_method(route, method) and compare_param(path, route, matched) then
      return route
    end
  end
  return nil
end

local function match_route(self, path, method, matched)
  local routes = self.hash_path[path]
  if routes then
    return routes
  end

  local it = radix.radix_tree_search(self.tree, self.tree_it, path, #path)
  if not it then
    return nil, "failed to match"
  end

  while true do
    local idx = radix.radix_tree_prev(it, path, #path)
    if idx <= 0 then
      break
    end

    routes = self.match_data[idx]
    if routes then
      local route = _match_from_routes(routes, path, method, matched)
      if route then
        return route
      end
    end
  end

  return nil
end

function _M.new(routes)
  if not routes then
    return nil, "missing argument route"
  end

  local route_n = #routes

  local tree = radix.radix_tree_new()
  local tree_it = radix.radix_tree_new_it(tree)
  if tree_it == nil then
    error("failed to new radixtree iterator")
  end

  local self = setmt__gc({
    tree = tree,
    tree_it = tree_it,
    match_data_index = 0,
    match_data = new_tab(#routes, 0),
    hash_path = new_tab(0, #routes)
  }, mt)

  -- register routes
  for i = 1, route_n do
    local route = routes[i]
    local paths = route.paths
    if type(paths) == "string" then
      self:insert(paths, route)
    else
      for _, path in ipairs(paths) do
        self:insert(path, route)
      end
    end
  end

  return self
end

function _M.insert(self, path, route)
  local route_opts = pre_insert_route(path, route)
  return insert_route(self, route_opts)
end

function _M.match(self, path, method, matched)
  local route, err = match_route(self, path, method, matched)
  if not route then
    if err then
      return nil, err
    end
    return nil
  end
  if matched then
    return route.metadata, matched
  else
    return route.metadata
  end
end

function _M.free(self)
  local it = self.tree_it
  if it then
    radix.radix_tree_stop(it)
    C.free(it)
    self.tree_it = nil
  end

  if self.tree then
    radix.radix_tree_destroy(self.tree)
    self.tree = nil
  end
  return nil
end

return _M
