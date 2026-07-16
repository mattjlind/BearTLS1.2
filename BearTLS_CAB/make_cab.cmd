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
set CABWIZ=C:\Program Files (x86)\Windows Mobile 6 SDK\Tools\CabWiz\cabwiz.exe
if not exist "%CABWIZ%" set CABWIZ=C:\Program Files (x86)\Microsoft Visual Studio 9.0\SmartDevices\SDK\SDKTools\cabwiz.exe
if not exist "%CABWIZ%" set CABWIZ=C:\Program Files\Windows Mobile 6 SDK\Tools\CabWiz\cabwiz.exe
if not exist "%CABWIZ%" goto no_cabwiz

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


