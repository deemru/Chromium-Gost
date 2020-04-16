cd /d %~dp0
call chromium-gost-env.bat
set PATH=%DEPOT_TOOLS_PATH%;%PATH%
set DEPOT_TOOLS_WIN_TOOLCHAIN=0
set GYP_MSVS_VERSION=2017

cd %CHROMIUM_PATH%
call gn gen out\RELEASE --args="is_debug=false is_official_build=true ffmpeg_branding=\"Chrome\" proprietary_codecs=true %CHROMIUM_PRIVATE_ARGS% clang_use_chrome_plugins=false closure_compile=false enable_hangout_services_extension=false enable_mdns=false enable_mse_mpeg2ts_stream_parser=true enable_nacl=false enable_nacl_nonsfi=false enable_reporting=false enable_service_discovery=false enable_widevine=true"
del %CHROMIUM_PATH%\out\RELEASE\chrome.7z
del %CHROMIUM_PATH%\out\RELEASE\*.manifest
call ninja -C out\RELEASE mini_installer

set PATH=%SEVENZIP_PATH%;%PATH%
cd %CHROMIUM_GOST_REPO%\build_windows
rmdir /s /q RELEASE
mkdir RELEASE
cd RELEASE
copy %CHROMIUM_PATH%\out\RELEASE\mini_installer.exe chromium-gost-%CHROMIUM_TAG%-windows-amd64-installer.exe
7z x %CHROMIUM_PATH%\out\RELEASE\chrome.7z
move Chrome-bin\chrome.exe Chrome-bin\%CHROMIUM_TAG%
move Chrome-bin\%CHROMIUM_TAG% chromium-gost-%CHROMIUM_TAG%
7z a -mm=Deflate -mfb=258 -mpass=15 -r chromium-gost-%CHROMIUM_TAG%-windows-amd64.zip chromium-gost-%CHROMIUM_TAG%

if "%1"=="" cmd
