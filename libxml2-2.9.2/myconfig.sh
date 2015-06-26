#!/bin/sh

export ROOTDIR="${PWD}"
export CROSS_COMPILE="arm-openwrt-linux"
export AR=${CROSS_COMPILE}-ar
export AS=${CROSS_COMPILE}-as
export LD=${CROSS_COMPILE}-ld
export RANLIB=${CROSS_COMPILE}-ranlib
export CC=${CROSS_COMPILE}-gcc
export NM=${CROSS_COMPILE}-nm
export STAGING_DIR="../../../../openwrt/staging_dir"

./configure  --target=${CROSS_COMPILE} --host=${CROSS_COMPILE} --build=i686-pc-linux-gnu --without-zlib \
	--without-python



