#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh

cd $CHROMIUM_PATH
gn gen out/RELEASE --args="target_os=\"android\" target_cpu=\"arm64\" is_debug=false symbol_level=0 is_official_build=true treat_warnings_as_errors=false $CHROMIUM_FLAGS $CHROMIUM_PRIVATE_ARGS"
ninja -C out/RELEASE chrome_public_apk
