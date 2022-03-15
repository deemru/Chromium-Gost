cd /d %~dp0
call chromium-gost-env.bat
set PATH=%DEPOT_TOOLS_PATH%;%PATH%
set DEPOT_TOOLS_WIN_TOOLCHAIN=0

cd %CHROMIUM_PATH%
call gn gen out\RELEASEARM --args="is_debug=false is_official_build=true enable_resource_allowlist_generation=false symbol_level=0 target_cpu=\"arm64\" %CHROMIUM_FLAGS% %CHROMIUM_PRIVATE_ARGS%"
del %CHROMIUM_PATH%\out\RELEASEARM\chrome.7z
del %CHROMIUM_PATH%\out\RELEASEARM\*.manifest
call ninja -C out\RELEASEARM mini_installer -k 0

set PATH=%SEVENZIP_PATH%;%PATH%
cd %CHROMIUM_GOST_REPO%\build_windows
rmdir /s /q RELEASEARM
mkdir RELEASEARM
cd RELEASEARM
copy %CHROMIUM_PATH%\out\RELEASEARM\mini_installer.exe chromium-gost-%CHROMIUM_TAG%-windows-arm-installer.exe
7z x %CHROMIUM_PATH%\out\RELEASEARM\chrome.7z
move Chrome-bin\chrome.exe Chrome-bin\%CHROMIUM_TAG%
move Chrome-bin\%CHROMIUM_TAG% chromium-gost-%CHROMIUM_TAG%
7z a -mm=Deflate -mfb=258 -mpass=15 -r chromium-gost-%CHROMIUM_TAG%-windows-arm.zip chromium-gost-%CHROMIUM_TAG%

if "%1"=="" cmd
