cd /d %~dp0
call chromium-gost-env.bat

github-release upload --user deemru --repo chromium-gost --tag %CHROMIUM_TAG% --name chromium-gost-%CHROMIUM_TAG%-windows-amd64-installer.exe --file RELEASE\chromium-gost-%CHROMIUM_TAG%-windows-amd64-installer.exe
github-release upload --user deemru --repo chromium-gost --tag %CHROMIUM_TAG% --name chromium-gost-%CHROMIUM_TAG%-windows-amd64.zip --file RELEASE\chromium-gost-%CHROMIUM_TAG%-windows-amd64.zip

if "%1"=="" timeout 86400
