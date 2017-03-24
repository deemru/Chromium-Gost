cd /d %~dp0
call chromium-gost-env.bat
set PATH=%DEPOT_TOOLS_PATH%;%PATH%
set DEPOT_TOOLS_WIN_TOOLCHAIN=0
set GYP_MSVS_VERSION=2015

cd %BORINGSSL_PATH% || goto :finish
call git checkout -f master
call git reset --hard

cd %CHROMIUM_PATH% || goto :finish
call git fetch --tags
call git checkout -b GOSTSSL-%CHROMIUM_TAG% tags/%CHROMIUM_TAG%
call git checkout -f GOSTSSL-%CHROMIUM_TAG%
call gclient sync --with_branch_heads
call git am --3way --ignore-space-change < %CHROMIUM_GOST_REPO%\patch\chromium.patch || goto :finish
copy /y %CHROMIUM_GOST_REPO%\extra\chromium-gost.ico chrome\app\theme\chromium\win\chromium.ico

cd %BORINGSSL_PATH%
call git checkout -b GOSTSSL-%CHROMIUM_TAG%
call git checkout -f GOSTSSL-%CHROMIUM_TAG%
call git am --3way --ignore-space-change < %CHROMIUM_GOST_REPO%\patch\boringssl.patch || goto :finish

:finish
if "%1"=="" timeout 86400
