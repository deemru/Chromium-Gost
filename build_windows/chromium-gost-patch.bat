cd /d %~dp0
call chromium-gost-env.bat

set DEPOT_TOOLS_WIN_TOOLCHAIN=0
set GOST_BRANCH=GOSTSSL-%CHROMIUM_TAG%

cd %CHROMIUM_PATH%\.git || goto :finish
cd %BORINGSSL_PATH%\.git || goto :finish

cd %CHROMIUM_PATH%
cmd /C "git format-patch HEAD~6..HEAD~5 --stdout > %CHROMIUM_GOST_REPO%patch\extensions-manifest-v2.stage.patch"
cmd /C "git format-patch HEAD~5..HEAD~4 --stdout > %CHROMIUM_GOST_REPO%patch\fixes.stage.patch"
cmd /C "git format-patch HEAD~4..HEAD~3 --stdout > %CHROMIUM_GOST_REPO%patch\gostssl-chromium.stage.patch"
cmd /C "git format-patch HEAD~3..HEAD~2 --stdout > %CHROMIUM_GOST_REPO%patch\extensions-bundled.stage.patch"
cmd /C "git format-patch HEAD~2..HEAD~1 --stdout > %CHROMIUM_GOST_REPO%patch\branding.stage.patch"
cmd /C "git format-patch HEAD~1 --stdout > %CHROMIUM_GOST_REPO%patch\services-gate.stage.patch"
cd %BORINGSSL_PATH%
cmd /C "git format-patch HEAD~1 --stdout > %CHROMIUM_GOST_REPO%patch\gostssl-boringssl.stage.patch"
cd %CHROMIUM_PATH%\third_party\search_engines_data\resources
cmd /C "git format-patch HEAD~1 --stdout > %CHROMIUM_GOST_REPO%patch\search_engines_data.stage.patch"

cmd
