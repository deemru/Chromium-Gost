#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh
export PATH=$DEPOT_TOOLS_PATH:$PATH

cd $CHROMIUM_PATH
gn gen out/DEBUG --args="is_debug=true is_component_build=false symbol_level=1 fatal_linker_warnings=false treat_warnings_as_errors=false $CHROMIUM_PRIVATE_ARGS clang_use_chrome_plugins=false closure_compile=false enable_hangout_services_extension=false enable_mdns=false enable_mse_mpeg2ts_stream_parser=true enable_nacl=false enable_nacl_nonsfi=false enable_reporting=false enable_service_discovery=false enable_widevine=true"
ninja -C out/DEBUG chrome
