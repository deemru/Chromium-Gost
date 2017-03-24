#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh
export PATH=$DEPOT_TOOLS_PATH:$PATH

cd $CHROMIUM_PATH
gn gen out/RELEASE --args="is_debug=false is_official_build=true symbol_level=0 enable_linux_installer=true $CHROMIUM_PRIVATE_ARGS"

cd $(dirname $0)
if [ ! -f gostssl.so ]; then ./chromium-gost-build-gostssl.sh; fi
mv gostssl.so $CHROMIUM_PATH/out/RELEASE/gostssl.so

cd $CHROMIUM_PATH
ninja -C out/RELEASE "chrome/installer/linux:beta_deb"
ninja -C out/RELEASE "chrome/installer/linux:beta_rpm"

cd $(dirname $0)
mv -f $CHROMIUM_PATH/out/RELEASE/chromium-gost-beta_${CHROMIUM_TAG}-1_amd64.deb chromium-gost-${CHROMIUM_TAG}-x64-beta.deb
mv -f $CHROMIUM_PATH/out/RELEASE/chromium-gost-beta-${CHROMIUM_TAG}-1.x86_64.rpm chromium-gost-${CHROMIUM_TAG}-x64-beta.rpm
