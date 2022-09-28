#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh

cd $CHROMIUM_PATH/out/RELEASE
unlink *.tar.bz2
if [ -d Chromium.app ]; then rm -rf Chromium.app; fi
if [ -d Chromium-Gost.app ]; then rm -rf Chromium-Gost.app; fi

cd $CHROMIUM_PATH
gn gen out/RELEASE --args="is_debug=false symbol_level=0 strip_debug_info=true is_official_build=true $CHROMIUM_FLAGS $CHROMIUM_PRIVATE_ARGS"
ninja -C out/RELEASE chrome
