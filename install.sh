rm -rf lua-resty-rax
git clone https://github.com/xiangnanscu/lua-resty-rax.git --depth=1
cd lua-resty-rax
make && INST_PREFIX=../lualib/xodel make install && make clean
