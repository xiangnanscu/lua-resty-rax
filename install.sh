git clone https://github.com/xiangnanscu/lua-resty-rax.git --depth=1
cd lua-resty-rax
make && INST_PREFIX=/usr/local/openresty/luajit make install && make clean