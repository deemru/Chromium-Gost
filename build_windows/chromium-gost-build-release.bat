cd /d %~dp0
call chromium-gost-env.bat
set PATH=%DEPOT_TOOLS_PATH%;%PATH%
set DEPOT_TOOLS_WIN_TOOLCHAIN=0
set GYP_MSVS_VERSION=2015

cd %CHROMIUM_PATH%
call gn gen out\RELEASE --args="is_debug=false is_official_build=true target_cpu=\"x86\" symbol_level=0 %CHROMIUM_PRIVATE_ARGS%"
call ninja -C out\RELEASE mini_installer

set PATH=%SEVENZIP_PATH%;%PATH%
cd %CHROMIUM_GOST_REPO%\build_windows
rmdir /s /q RELEASE
mkdir RELEASE
cd RELEASE
7z x %CHROMIUM_PATH%\out\RELEASE\chrome.7z
copy ..\gostssl.dll Chrome-bin\%CHROMIUM_TAG%
move Chrome-bin chromium-gost-%CHROMIUM_TAG%-win32
7z a -mx=9 -md=256m chromium-gost-%CHROMIUM_TAG%-win32.7z chromium-gost-%CHROMIUM_TAG%-win32

if "%1"=="" timeout 86400
