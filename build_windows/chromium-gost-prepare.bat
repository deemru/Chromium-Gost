cd /d %~dp0
call chromium-gost-env.bat
set PATH=%DEPOT_TOOLS_PATH%;%PATH%
set DEPOT_TOOLS_WIN_TOOLCHAIN=0
set GYP_MSVS_VERSION=2017
set GOST_BRANCH=GOSTSSL-%CHROMIUM_TAG%

cd %CHROMIUM_PATH%\.git || goto :finish
cd %BORINGSSL_PATH%\.git || goto :finish

cd %BORINGSSL_PATH%
call git reset HEAD~ --hard

cd %CHROMIUM_PATH%
call git reset HEAD~ --hard
call git fetch --tags
call git checkout -b %GOST_BRANCH% tags/%CHROMIUM_TAG%
call git checkout -f %GOST_BRANCH%
call gclient sync --with_branch_heads
call git am --3way --ignore-space-change < %CHROMIUM_GOST_REPO%\patch\chromium.patch || goto :finish
copy /y %CHROMIUM_GOST_REPO%\extra\chromium-gost.ico chrome\app\theme\chromium\win\chromium.ico

copy /y %CHROMIUM_GOST_REPO%\extra\product_logo\*.png chrome\app\theme\chromium\
copy /y %CHROMIUM_GOST_REPO%\extra\product_logo\product_logo_16.png chrome\app\theme\default_100_percent\chromium\product_logo_16.png
copy /y %CHROMIUM_GOST_REPO%\extra\product_logo\product_logo_32.png chrome\app\theme\default_100_percent\chromium\product_logo_32.png
copy /y %CHROMIUM_GOST_REPO%\extra\product_logo\product_logo_32.png chrome\app\theme\default_200_percent\chromium\product_logo_16.png
copy /y %CHROMIUM_GOST_REPO%\extra\product_logo\product_logo_64.png chrome\app\theme\default_200_percent\chromium\product_logo_32.png
copy /y %CHROMIUM_GOST_REPO%\extra\product_logo\product_logo_32.xpm chrome\app\theme\chromium\linux\product_logo_32.xpm

cd %BORINGSSL_PATH%
call git checkout -b %GOST_BRANCH%
call git checkout -f %GOST_BRANCH%
call git am --3way --ignore-space-change < %CHROMIUM_GOST_REPO%\patch\boringssl.patch || goto :finish

:finish
if "%1"=="" timeout 86400
