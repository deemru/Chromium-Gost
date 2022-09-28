cd /d %~dp0
call chromium-gost-env.bat

set DEPOT_TOOLS_WIN_TOOLCHAIN=0
set GOST_BRANCH=GOSTSSL-%CHROMIUM_TAG%

cd %CHROMIUM_PATH%\.git || goto :finish
cd %BORINGSSL_PATH%\.git || goto :finish

cd %CHROMIUM_PATH%
cmd /C "git format-patch HEAD~1 --stdout > %CHROMIUM_GOST_REPO%patch\chromium.patch"
cd %BORINGSSL_PATH%
cmd /C "git format-patch HEAD~1 --stdout > %CHROMIUM_GOST_REPO%patch\boringssl.patch"

cmd
