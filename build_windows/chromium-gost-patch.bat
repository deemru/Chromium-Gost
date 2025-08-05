cd /d %~dp0
call chromium-gost-env.bat

set DEPOT_TOOLS_WIN_TOOLCHAIN=0
set GOST_BRANCH=GOSTSSL-%CHROMIUM_TAG%

cd %CHROMIUM_PATH%\.git || goto :finish
cd %BORINGSSL_PATH%\.git || goto :finish

cd %CHROMIUM_PATH%
cmd /C "git format-patch HEAD~2..HEAD~1 --stdout > %CHROMIUM_GOST_REPO%patch\extra\extensions-manifestv2_ifdef.stage.patch"
cd %CHROMIUM_PATH%
cmd /C "git format-patch HEAD~1 --stdout > %CHROMIUM_GOST_REPO%patch\chromium.stage.patch"
cd %BORINGSSL_PATH%
cmd /C "git format-patch HEAD~1 --stdout > %CHROMIUM_GOST_REPO%patch\boringssl.stage.patch"
cd %CHROMIUM_PATH%\third_party\search_engines_data\resources
cmd /C "git format-patch HEAD~1 --stdout > %CHROMIUM_GOST_REPO%patch\search_engines_data.stage.patch"

curl -o %CHROMIUM_GOST_REPO%patch\extra\extensions-manifestv2.patch https://raw.githubusercontent.com/ungoogled-software/ungoogled-chromium/refs/heads/master/patches/core/ungoogled-chromium/extensions-manifestv2.patch

cmd
