cd /d %~dp0
call chromium-gost-env.bat
set PATH=%DEPOT_TOOLS_PATH%;%PATH%
set DEPOT_TOOLS_WIN_TOOLCHAIN=0
set GYP_MSVS_VERSION=2017

cd %CHROMIUM_PATH%
call gn gen out\DEBUG --args="is_debug=true is_component_build=true symbol_level=1 target_cpu=\"x86\" fatal_linker_warnings=false treat_warnings_as_errors=false %CHROMIUM_PRIVATE_ARGS% clang_use_chrome_plugins=false closure_compile=false enable_hangout_services_extension=false enable_mdns=false enable_mse_mpeg2ts_stream_parser=true enable_nacl=false enable_nacl_nonsfi=false enable_reporting=false enable_service_discovery=false enable_widevine=true"
call ninja -C out\DEBUG chrome -k 0

if "%1"=="" cmd
