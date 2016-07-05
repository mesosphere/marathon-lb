#!/bin/bash
set -e

mkdir -p /usr/src

# Build Lua
cd /usr/src
wget http://www.lua.org/ftp/lua-5.3.3.tar.gz
tar zxf lua-*.tar.gz
cd lua-*
make -j4 linux LUA_LIB_NAME=lua53
make -j4 install LUA_LIB_NAME=lua53

# Build HAProxy
cd /usr/src
wget http://www.haproxy.org/download/1.6/src/haproxy-1.6.6.tar.gz
tar xf haproxy-*.tar.gz
cd haproxy-*
make -j4 \
  TARGET=custom \
  CPU=x86_64 \
  USE_PCRE=1 \
  USE_PCRE_JIT=1 \
  USE_LIBCRYPT=1 \
  USE_LINUX_SPLICE=1 \
  USE_LINUX_TPROXY=1 \
  USE_OPENSSL=1 \
  USE_DL=1 \
  USE_LUA=1 \
  LUA_LIB=/usr/local/lib/ \
  LUA_INC=/usr/local/include/ \
  USE_ZLIB=1 \
  LDFLAGS="-lcrypt  -lssl -lcrypto -L/usr/local/lib/ -llua -lm -L/usr/lib -lpcreposix -lpcre"
make -j4 install LDFLAGS="-lcrypt  -lssl -lcrypto -L/usr/local/lib/ -llua -lm -L/usr/lib -lpcreposix -lpcre -ldl"

# Clean up
cd /
rm -rf /usr/src/*
