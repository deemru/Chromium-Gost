cd /d %~dp0
call chromium-gost-env.bat
set PATH=%DEPOT_TOOLS_PATH%;%PATH%
set DEPOT_TOOLS_WIN_TOOLCHAIN=0
set GYP_MSVS_VERSION=2015

cd %BORINGSSL_PATH%
call git checkout master
call git reset --hard

cd %CHROMIUM_PATH%
call git fetch --tags
call git checkout -b GOSTSSL-%CHROMIUM_TAG% tags/%CHROMIUM_TAG%
call git checkout GOSTSSL-%CHROMIUM_TAG%
call gclient sync
call git am --3way --ignore-space-change --keep-cr < %CHROMIUM_GOST_REPO%\patch\chromium.patch

cd %BORINGSSL_PATH%
call git checkout -b GOSTSSL-%CHROMIUM_TAG%
call git checkout GOSTSSL-%CHROMIUM_TAG%
call git am --3way --ignore-space-change --keep-cr < %CHROMIUM_GOST_REPO%\patch\boringssl.patch
timeout 60
