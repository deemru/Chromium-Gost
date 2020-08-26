cd /d %~dp0
call chromium-gost-env.bat
set PATH=%DEPOT_TOOLS_PATH%;%PATH%
set DEPOT_TOOLS_WIN_TOOLCHAIN=0

cd %CHROMIUM_PATH%
call gn gen out\DEBUG --args="is_debug=true is_component_build=true symbol_level=1 target_cpu=\"x86\" fatal_linker_warnings=false treat_warnings_as_errors=false %CHROMIUM_FLAGS% %CHROMIUM_PRIVATE_ARGS%"
call ninja -C out\DEBUG chrome -k 0

if "%1"=="" cmd
