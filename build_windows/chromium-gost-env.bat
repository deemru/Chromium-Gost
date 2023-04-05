set /p CHROMIUM_TAG=<..\VERSION
set /p CHROMIUM_FLAGS=<..\FLAGS
set CHROMIUM_PATH=u:\chromium\src
set BORINGSSL_PATH=%CHROMIUM_PATH%\third_party\boringssl\src
set DEPOT_TOOLS_PATH=u:\depot_tools
set CHROMIUM_GOST_REPO=%~dp0..\
set SEVENZIP_PATH="C:\Program Files\7-Zip\"
set CHROMIUM_PRIVATE_ARGS= 
if exist chromium-gost-env-private.bat call chromium-gost-env-private.bat
if exist %USERPROFILE%\chromium-gost-env-private.bat call %USERPROFILE%\chromium-gost-env-private.bat
set PATH=%DEPOT_TOOLS_PATH%;%DEPOT_TOOLS_PATH%\python-bin;%PATH%
