cd /d %~dp0
call chromium-gost-env.bat
set PATH=%DEPOT_TOOLS_PATH%;%PATH%
set DEPOT_TOOLS_WIN_TOOLCHAIN=0

cd %CHROMIUM_PATH%
call gn gen out\RELEASE32 --args="is_debug=false is_official_build=true target_cpu=\"x86\" %CHROMIUM_FLAGS% %CHROMIUM_PRIVATE_ARGS%"
del %CHROMIUM_PATH%\out\RELEASE32\chrome.7z
del %CHROMIUM_PATH%\out\RELEASE32\*.manifest
call ninja -C out\RELEASE32 mini_installer

set PATH=%SEVENZIP_PATH%;%PATH%
cd %CHROMIUM_GOST_REPO%\build_windows
rmdir /s /q RELEASE32
mkdir RELEASE32
cd RELEASE32
copy %CHROMIUM_PATH%\out\RELEASE32\mini_installer.exe chromium-gost-%CHROMIUM_TAG%-windows-386-installer.exe
7z x %CHROMIUM_PATH%\out\RELEASE32\chrome.7z
move Chrome-bin\chrome.exe Chrome-bin\%CHROMIUM_TAG%
move Chrome-bin\%CHROMIUM_TAG% chromium-gost-%CHROMIUM_TAG%
7z a -mm=Deflate -mfb=258 -mpass=15 -r chromium-gost-%CHROMIUM_TAG%-windows-386.zip chromium-gost-%CHROMIUM_TAG%

if "%1"=="" cmd
