#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh
export PATH=$DEPOT_TOOLS_PATH:$PATH

cd $CHROMIUM_GOST_REPO/build_linux/
if [ -f gostssl.so ]; then unlink gostssl.so; fi
. ./chromium-gost-build-gostssl.sh
mv -f gostssl.so $CHROMIUM_PATH/out/DEBUG/gostssl.so

cd $CHROMIUM_PATH
gn gen out/DEBUG --args="is_debug=true is_component_build=false symbol_level=1 fatal_linker_warnings=false treat_warnings_as_errors=false $CHROMIUM_PRIVATE_ARGS"
ninja -C out/DEBUG chrome

