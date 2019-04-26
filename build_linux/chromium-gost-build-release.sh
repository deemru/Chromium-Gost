#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh
export PATH=$DEPOT_TOOLS_PATH:$PATH

cd $CHROMIUM_GOST_REPO/build_linux/
if [ -f gostssl.so ]; then unlink gostssl.so; fi
. ./chromium-gost-build-gostssl.sh
mv -f gostssl.so $CHROMIUM_PATH/out/RELEASE/gostssl.so

cd $CHROMIUM_PATH
gn gen out/RELEASE --args="is_debug=false is_official_build=true enable_linux_installer=true ffmpeg_branding=\"Chrome\" proprietary_codecs=true $CHROMIUM_PRIVATE_ARGS"
ninja -C out/RELEASE "chrome/installer/linux:stable_deb"
ninja -C out/RELEASE "chrome/installer/linux:stable_rpm"

cd $CHROMIUM_GOST_REPO/build_linux/
mv -f $CHROMIUM_PATH/out/RELEASE/chromium-gost-stable_${CHROMIUM_TAG}-1_amd64.deb chromium-gost-${CHROMIUM_TAG}-linux-amd64.deb
mv -f $CHROMIUM_PATH/out/RELEASE/chromium-gost-stable-${CHROMIUM_TAG}-1.x86_64.rpm chromium-gost-${CHROMIUM_TAG}-linux-amd64.rpm

