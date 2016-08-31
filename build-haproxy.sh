#!/bin/bash
set -e

mkdir -p /usr/src

# Build Lua
LUA_VERSION="5.3.3"
LUA_SHA1="a0341bc3d1415b814cc738b2ec01ae56045d64ef"

cd /usr/src
LUA_FILENAME="lua-$LUA_VERSION"
wget "http://www.lua.org/ftp/$LUA_FILENAME.tar.gz"
echo "$LUA_SHA1  $LUA_FILENAME.tar.gz" | sha1sum -c
tar zxf "$LUA_FILENAME.tar.gz"
cd "$LUA_FILENAME"
make -j4 linux LUA_LIB_NAME=lua53
make -j4 install LUA_LIB_NAME=lua53

# Build HAProxy
HAPROXY_MAJOR_VERSION="1.6"
HAPROXY_VERSION="1.6.9"
HAPROXY_MD5="c52eee40eb66f290d6f089c339b9d2b3"

cd /usr/src
HAPROXY_FILENAME="haproxy-$HAPROXY_VERSION"
wget "http://www.haproxy.org/download/$HAPROXY_MAJOR_VERSION/src/$HAPROXY_FILENAME.tar.gz"
echo "$HAPROXY_MD5  $HAPROXY_FILENAME.tar.gz" | md5sum -c
tar zxf "$HAPROXY_FILENAME.tar.gz"
cd "$HAPROXY_FILENAME"
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
make -j4 install-bin LDFLAGS="-lcrypt  -lssl -lcrypto -L/usr/local/lib/ -llua -lm -L/usr/lib -lpcreposix -lpcre -ldl"

# Clean up
cd /
rm -rf /usr/src/*
