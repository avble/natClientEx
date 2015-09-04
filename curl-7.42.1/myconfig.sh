#!/bin/sh

./configure --enable-shared \
        --enable-static \
        --disable-thread \
        --enable-cookies \
        --enable-crypto-auth \
        --enable-nonblocking \
        --enable-file \
        --enable-ftp \
        --enable-http \
        --disable-ares \
        --disable-debug \
        --disable-dict \
        --disable-gopher \
        --disable-ldap \
        --disable-manual \
        --disable-sspi \
        --disable-telnet \
        --enable-tftp \
        --disable-verbose \
        --without-zlib   \
        --without-winssl     \
        --without-darwinssl   \
        --without-ssl     \
        --without-gnutls  \
        --without-polarssl \
        --without-cyassl  \
        --without-nss   \
        --without-axtls \
        --without-ca-bundle \
        --without-ca-path   \
        --without-libmetalink \
        --without-libssh2     \
        --without-librtmp     \
        --without-winidn  \
        --without-libidn   \
        --without-nghttp2      

