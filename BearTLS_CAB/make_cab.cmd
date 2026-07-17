@echo off
setlocal
set SETUPDLL=%~1
set CONFIG=%~2
set PLATFORM=%~3
set OUTDIR=%~4
set PROJDIR=%~dp0
set ROOTDIR=%PROJDIR%..\
set STAGE=%PROJDIR%cab_staging\%PLATFORM%\%CONFIG%
set CABOUT=%PROJDIR%cab_output\%PLATFORM%\%CONFIG%
set CABWIZ=
set WM_SDK_ROOT=

rem Prefer the registered Windows Mobile 6 SDK location, including 32-bit
rem registrations queried from a 64-bit command prompt.
for /f "tokens=2,*" %%A in ('reg query "HKLM\SOFTWARE\Microsoft\Windows CE Tools\SDKs\Windows Mobile 6 Professional SDK" /v SDKRootDir 2^>nul ^| find /i "SDKRootDir"') do set "WM_SDK_ROOT=%%B"
if not defined WM_SDK_ROOT for /f "tokens=2,*" %%A in ('reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows CE Tools\SDKs\Windows Mobile 6 Professional SDK" /v SDKRootDir 2^>nul ^| find /i "SDKRootDir"') do set "WM_SDK_ROOT=%%B"
if defined WM_SDK_ROOT if exist "%WM_SDK_ROOT%Tools\CabWiz\cabwiz.exe" set "CABWIZ=%WM_SDK_ROOT%Tools\CabWiz\cabwiz.exe"

rem Fall back to locations derived from the machine's environment. These also
rem cover VS2008 and SDK installations on drives other than C:.
if not defined CABWIZ if defined VS90COMNTOOLS if exist "%VS90COMNTOOLS%..\..\SmartDevices\SDK\SDKTools\cabwiz.exe" set "CABWIZ=%VS90COMNTOOLS%..\..\SmartDevices\SDK\SDKTools\cabwiz.exe"
if not defined CABWIZ if defined ProgramFiles(x86) if exist "%ProgramFiles(x86)%\Windows Mobile 6 SDK\Tools\CabWiz\cabwiz.exe" set "CABWIZ=%ProgramFiles(x86)%\Windows Mobile 6 SDK\Tools\CabWiz\cabwiz.exe"
if not defined CABWIZ if defined ProgramFiles if exist "%ProgramFiles%\Windows Mobile 6 SDK\Tools\CabWiz\cabwiz.exe" set "CABWIZ=%ProgramFiles%\Windows Mobile 6 SDK\Tools\CabWiz\cabwiz.exe"
if not defined CABWIZ goto no_cabwiz

if exist "%STAGE%" rmdir /s /q "%STAGE%"
mkdir "%STAGE%" || exit /b 1
mkdir "%CABOUT%" 2>nul

copy /y "%ROOTDIR%BearTLS\%PLATFORM%\%CONFIG%\wm_https.dll" "%STAGE%\wm_https.dll" || exit /b 1
copy /y "%ROOTDIR%BearTLS\certs\roots.pem" "%STAGE%\roots.pem" || exit /b 1
copy /y "%SETUPDLL%" "%STAGE%\BearTLSSetup.dll" || exit /b 1
copy /y "%PROJDIR%BearTLS_CAB.inf" "%STAGE%\BearTLS_CAB.inf" || exit /b 1

set CPU=ARMV4I
echo %PLATFORM% | find "ARMV4)" >nul
if not errorlevel 1 set CPU=ARMV4

pushd "%STAGE%" || exit /b 1
"%CABWIZ%" BearTLS_CAB.inf /dest "%STAGE%" /cpu %CPU% /err cabwiz.err
set RC=%ERRORLEVEL%
if exist cabwiz.err type cabwiz.err
if exist *.CAB copy /y *.CAB "%CABOUT%\" >nul
if exist cabwiz.err copy /y cabwiz.err "%CABOUT%\cabwiz.err" >nul
popd
exit /b %RC%

:no_cabwiz
echo CabWiz.exe was not found. Install the Windows Mobile SDK or edit make_cab.cmd.
exit /b 1


