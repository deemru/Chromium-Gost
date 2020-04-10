cd /d %~dp0
call chromium-gost-env.bat

github-release upload --user deemru --repo chromium-gost --tag %CHROMIUM_TAG% --name chromium-gost-%CHROMIUM_TAG%-windows-386-installer.exe --file RELEASE32\chromium-gost-%CHROMIUM_TAG%-windows-386-installer.exe

github-release upload --user deemru --repo chromium-gost --tag %CHROMIUM_TAG% --name chromium-gost-%CHROMIUM_TAG%-windows-386.zip --file RELEASE32\chromium-gost-%CHROMIUM_TAG%-windows-386.zip

if "%1"=="" timeout 86400
