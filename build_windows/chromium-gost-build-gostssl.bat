call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" x86
cd /d %~dp0
call chromium-gost-env.bat

set DATETIMEVERSION=%DATE:~3,1%
if "%DATETIMEVERSION%" == " " (
:: en-us
    set DATETIMEVERSION=%DATE:~10,4%,%DATE:~4,2%,%DATE:~7,2%,%TIME:~0,2%%TIME:~3,2%
) else (
:: ru-ru
    set DATETIMEVERSION=%DATE:~6,4%,%DATE:~3,2%,%DATE:~0,2%,%TIME:~0,2%%TIME:~3,2%
)

( echo #define DATETIMEVERSION %DATETIMEVERSION%) > gostssl_ver.rc
( echo #define CHROMIUM_TAG "%CHROMIUM_TAG%") >> gostssl_ver.rc

cl /c /Ox /Ot /GL /GF /GS /W4 /EHa /I%BORINGSSL_PATH%\include /I..\src\msspi\src /I..\src\msspi\third_party\cprocsp\include ../src/gostssl.cpp
cl /c /Ox /Ot /GL /GF /GS /W4 /EHa ../src/msspi/src/msspi.cpp
rc -r gostssl.rc

link /DLL /LTCG gostssl.obj msspi.obj gostssl.res crypt32.lib advapi32.lib /OUT:gostssl.dll

if "%1"=="" timeout 86400
