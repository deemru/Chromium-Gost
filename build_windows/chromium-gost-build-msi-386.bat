@echo off
setlocal ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION

cd /d %~dp0
call chromium-gost-env.bat

rem Проверка наличия WiX
where candle.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] candle.exe not found. Add WiX bin to PATH or set WIX_PATH in chromium-gost-env.bat.
    exit /b 1
)

where light.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] light.exe not found. Add WiX bin to PATH or set WIX_PATH in chromium-gost-env.bat.
    exit /b 1
)

rem Определение имени файла mini-installer
set MINI_INSTALLER_FILE=chromium-gost-%CHROMIUM_TAG%-windows-386-installer.exe

rem Проверка наличия mini-installer
set MINI_INSTALLER_SOURCE=%~dp0RELEASE32\%MINI_INSTALLER_FILE%
if not exist "%MINI_INSTALLER_SOURCE%" (
    echo [ERROR] mini_installer not found: %MINI_INSTALLER_SOURCE%
    echo [ERROR] Run chromium-gost-build-release-386.bat first to build mini_installer.
    exit /b 1
)

rem Обработка версии из CHROMIUM_TAG
set RAW_VER=%CHROMIUM_TAG%
set WIX_PRODUCT_VERSION=
for /f "tokens=1 delims=-" %%A in ("%RAW_VER%") do set WIX_PRODUCT_VERSION=%%A
if not defined WIX_PRODUCT_VERSION (
    echo [ERROR] Failed to derive ProductVersion from CHROMIUM_TAG=%CHROMIUM_TAG%.
    exit /b 1
)

echo [INFO] Using ProductVersion=%WIX_PRODUCT_VERSION%

rem Подготовка рабочих директорий
set BUILD_DIR=%~dp0build
set WIX_DIR=%~dp0wix
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

rem Копирование mini-installer во временную директорию
set TEMP_SOURCE_DIR=%BUILD_DIR%\msi_source_386
if exist "%TEMP_SOURCE_DIR%" rmdir /s /q "%TEMP_SOURCE_DIR%"
mkdir "%TEMP_SOURCE_DIR%"
copy "%MINI_INSTALLER_SOURCE%" "%TEMP_SOURCE_DIR%\%MINI_INSTALLER_FILE%"
if errorlevel 1 (
    echo [ERROR] Failed to copy mini_installer.
    exit /b 1
)

rem Проверка, что файл скопирован
if not exist "%TEMP_SOURCE_DIR%\%MINI_INSTALLER_FILE%" (
    echo [ERROR] File not found after copy: %TEMP_SOURCE_DIR%\%MINI_INSTALLER_FILE%
    exit /b 1
)

for %%F in ("%TEMP_SOURCE_DIR%\%MINI_INSTALLER_FILE%") do (
    set FILE_SIZE=%%~zF
    echo [INFO] Copied mini-installer size: !FILE_SIZE! bytes
)

rem GUID для UpgradeCode и Component (386) - постоянный, не меняется между версиями
set GUID_386=3291d432-3232-3232-3232-326e8de5c532

echo [INFO] Compiling WiX sources (386)...
echo [INFO] SourceDir: %TEMP_SOURCE_DIR%
echo [INFO] MiniInstallerFile: %MINI_INSTALLER_FILE%
candle.exe ^
  -dSourceDir="%TEMP_SOURCE_DIR%" ^
  -dProductVersion=%WIX_PRODUCT_VERSION% ^
  -dPlatform=x86 ^
  -dUpgradeCode=%GUID_386% ^
  -dComponentGuid=%GUID_386% ^
  -dProgramFilesFolder=ProgramFilesFolder ^
  -dMiniInstallerFile=%MINI_INSTALLER_FILE% ^
  -out "%BUILD_DIR%\chromium-gost-386.wixobj" ^
  "%WIX_DIR%\chromium-gost.wxs"

if errorlevel 1 (
    echo [ERROR] candle.exe failed for 386.
    exit /b 1
)

echo [INFO] Linking MSI (386)...
light.exe ^
  -out "%~dp0RELEASE32\chromium-gost-%CHROMIUM_TAG%-windows-386.msi" ^
  "%BUILD_DIR%\chromium-gost-386.wixobj"

if errorlevel 1 (
    echo [ERROR] light.exe failed for 386.
    exit /b 1
)

echo [INFO] Done.
echo [INFO] MSI 386: %~dp0RELEASE32\chromium-gost-%CHROMIUM_TAG%-windows-386.msi

rem Очистка временных файлов
if exist "%TEMP_SOURCE_DIR%" rmdir /s /q "%TEMP_SOURCE_DIR%"

endlocal
exit /b 0
