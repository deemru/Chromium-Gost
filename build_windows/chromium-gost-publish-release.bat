cd /d %~dp0
call chromium-gost-env.bat

github-release release --user deemru --repo chromium-gost --tag %CHROMIUM_TAG% --draft
github-release upload --user deemru --repo chromium-gost --tag %CHROMIUM_TAG% --name chromium-gost-%CHROMIUM_TAG%-windows-386.7z --file RELEASE\chromium-gost-%CHROMIUM_TAG%-windows-386.7z

if "%1"=="" timeout 86400
