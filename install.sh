rm -rf lua-resty-rax
git clone https://github.com/xiangnanscu/lua-resty-rax.git --depth=1
cd lua-resty-rax
make && make install && make clean
cd ..
rm -rf lua-resty-rax