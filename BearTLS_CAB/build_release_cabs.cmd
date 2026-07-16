@echo off
setlocal
set ROOT=%~dp0..
set MSBUILD=%WINDIR%\Microsoft.NET\Framework\v3.5\MSBuild.exe
if not exist "%MSBUILD%" goto no_msbuild

call :build "Pocket PC 2003 (ARMV4)" || exit /b 1
call :build "Windows Mobile 5.0 Pocket PC SDK (ARMV4I)" || exit /b 1
call :build "Windows Mobile 6 Professional SDK (ARMV4I)" || exit /b 1

echo Built BearTLS release CABs for WM2003, WM5, and WM6.
exit /b 0

:build
echo Building BearTLS_CAB Release^|%~1
"%MSBUILD%" "%ROOT%\BearTLS.sln" /t:BearTLS_CAB /p:Configuration=Release /p:Platform=%1
exit /b %ERRORLEVEL%

:no_msbuild
echo MSBuild 3.5 was not found.
exit /b 1
