#!/bin/sh

export ROOTDIR="${PWD}"
#cd curl-7.37.1/
export CROSS_COMPILE="arm-openwrt-linux"
#export CPPFLAGS="-I${ROOTDIR}/openssl/include -I${ROOTDIR}/zlib/include"
#export LDFLAGS="-L${ROOTDIR}/openssl/libs -L${ROOTDIR}/zlib/libs"
export AR=${CROSS_COMPILE}-ar
export AS=${CROSS_COMPILE}-as
export LD=${CROSS_COMPILE}-ld
export RANLIB=${CROSS_COMPILE}-ranlib
export CC=${CROSS_COMPILE}-gcc
export NM=${CROSS_COMPILE}-nm
#export LIBS="-lssl -lcrypto"

./configure --enable-shared \
        --enable-static \
        --disable-thread \
        --enable-nonblocking \
        --enable-file \
        --enable-http \
        --disable-ares \
        --disable-debug \
        --disable-dict \
        --disable-gopher \
        --disable-ldap \
        --disable-manual \
        --disable-sspi \
        --disable-telnet \
        --disable-verbose \
        --without-ca-bundle \
        --without-gnutls \
        --without-krb4 \
        --without-libidn \
        --without-nss \
        --without-libssh2  \
	--prefix=${ROOTDIR}/build --target=${CROSS_COMPILE} --host=${CROSS_COMPILE} --build=i686-pc-linux-gnu 

#--with-ssl --with-zlib
