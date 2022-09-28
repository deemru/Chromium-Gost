#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh

cd $CHROMIUM_PATH
gn gen out/DEBUG --args="is_debug=true is_component_build=true symbol_level=1 fatal_linker_warnings=false treat_warnings_as_errors=false $CHROMIUM_FLAGS $CHROMIUM_PRIVATE_ARGS"
ninja -C out/DEBUG chrome
