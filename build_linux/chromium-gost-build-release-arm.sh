#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh

cd $CHROMIUM_PATH
#bash build/install-build-deps.sh
#build/linux/sysroot_scripts/install-sysroot.py --arch=arm64
gn gen out/RELEASEARM --args="is_debug=false symbol_level=0 strip_debug_info=true is_official_build=true enable_linux_installer=true target_cpu=\"arm64\" $CHROMIUM_FLAGS $CHROMIUM_PRIVATE_ARGS"
ninja -C out/RELEASEARM "chrome/installer/linux:stable_deb" -k 0
ninja -C out/RELEASEARM "chrome/installer/linux:stable_rpm" -k 0

cd $CHROMIUM_GOST_REPO/build_linux/
mv -f $CHROMIUM_PATH/out/RELEASEARM/chromium-gost-stable_${CHROMIUM_TAG}-1_arm64.deb chromium-gost-${CHROMIUM_TAG}-linux-arm64.deb
mv -f $CHROMIUM_PATH/out/RELEASEARM/chromium-gost-stable-${CHROMIUM_TAG}-1.aarch64.rpm chromium-gost-${CHROMIUM_TAG}-linux-arm64.rpm
