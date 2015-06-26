#!/bin/sh

export ROOTDIR="${PWD}"
#export CROSS_COMPILE="arm-openwrt-linux"

export CROSS_COMPILE="arm-openwrt-linux-uclibcgnueabi"
export AR=${CROSS_COMPILE}-ar
export AS=${CROSS_COMPILE}-as
export LD=${CROSS_COMPILE}-ld
export RANLIB=${CROSS_COMPILE}-ranlib
export CC=${CROSS_COMPILE}-gcc
export NM=${CROSS_COMPILE}-nm
export STAGING_DIR="../../../../openwrt/staging_dir"

./configure --host=arm-linux-gnu --target=arm-linux --disable-sound  --disable-ssl
#./configure --host=arm-linux-gnu --target=arm-linux --disable-sound LDFLAGS=/home/huyle/works/00_VEriK_prj/05_dev/00_prj_ceres/ceres_core_system/ceres_app/openwrt/staging_dir/target-arm-openwrt-linux-uclibcgnueabi/usr/lib

