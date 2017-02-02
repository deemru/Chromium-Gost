call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" x86
cd /d %~dp0
call chromium-gost-env.bat

set DATETIMEVERSION=%DATE:~6,4%,%DATE:~3,2%,%DATE:~0,2%,%TIME:~0,2%%TIME:~3,2%
( echo #define DATETIMEVERSION %DATETIMEVERSION%) > gostssl_ver.rc
( echo #define CHROMIUM_TAG "%CHROMIUM_TAG%") >> gostssl_ver.rc

cl /c /Ox /Ot /GL /GF /GS /W4 /EHa /I%BORINGSSL_PATH%\include ../src/gostssl.cpp
cl /c /Ox /Ot /GL /GF /GS /W4 /EHa ../src/msspi/src/msspi.cpp
rc -r gostssl.rc

link /DLL /LTCG gostssl.obj msspi.obj gostssl.res crypt32.lib advapi32.lib /OUT:gostssl.dll
timeout 60
