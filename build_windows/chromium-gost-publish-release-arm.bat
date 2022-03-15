cd /d %~dp0
call chromium-gost-env.bat

github-release upload --user deemru --repo chromium-gost --tag %CHROMIUM_TAG% --name chromium-gost-%CHROMIUM_TAG%-windows-arm-installer.exe --file RELEASEARM\chromium-gost-%CHROMIUM_TAG%-windows-arm-installer.exe

github-release upload --user deemru --repo chromium-gost --tag %CHROMIUM_TAG% --name chromium-gost-%CHROMIUM_TAG%-windows-arm.zip --file RELEASEARM\chromium-gost-%CHROMIUM_TAG%-windows-arm.zip

if "%1"=="" timeout 86400
