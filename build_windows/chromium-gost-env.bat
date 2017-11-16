set CHROMIUM_TAG=62.0.3202.94
set CHROMIUM_PATH=u:\chromium\src
set BORINGSSL_PATH=%CHROMIUM_PATH%\third_party\boringssl\src
set DEPOT_TOOLS_PATH=u:\depot_tools\
set CHROMIUM_GOST_REPO=%~dp0..\
set SEVENZIP_PATH="C:\Program Files\7-Zip\"
set CHROMIUM_PRIVATE_ARGS= 
if exist chromium-gost-env-private.bat call chromium-gost-env-private.bat
if exist %USERPROFILE%\chromium-gost-env-private.bat call %USERPROFILE%\chromium-gost-env-private.bat
