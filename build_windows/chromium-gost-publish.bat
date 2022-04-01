cd /d %~dp0
call chromium-gost-env.bat

github-release release --user deemru --repo chromium-gost --tag %CHROMIUM_TAG% --draft

if "%1"=="" timeout 86400
