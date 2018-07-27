#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh
export PATH=$DEPOT_TOOLS_PATH:$PATH

cd $CHROMIUM_PATH
gn gen out/DEBUG --args="is_debug=true is_component_build=true remove_webcore_debug_symbols=true fatal_linker_warnings=false treat_warnings_as_errors=false $CHROMIUM_PRIVATE_ARGS"

cd $(dirname $0)
if [ ! -f gostssl.so ]; then ./chromium-gost-build-gostssl.sh; fi
mv gostssl.so $CHROMIUM_PATH/out/DEBUG/gostssl.so

cd $CHROMIUM_PATH
ninja -C out/DEBUG chrome
