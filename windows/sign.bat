@echo off
setlocal
REM Usage: sign.bat YourTestCert.pfx [password]
if "%~1"=="" (
  echo Usage: sign.bat path\to\testcert.pfx [password]
  echo Enable test signing first:
  echo   bcdedit /set testsigning on
  echo   shutdown /r /t 0
  exit /b 1
)
set PFX=%~1
set PASS=%~2
set OUT=%~dp0bin\x64\Release
if not exist "%OUT%\crossview.sys" (
  echo Build first ^(build.bat^).
  exit /b 1
)
if "%PASS%"=="" (
  signtool sign /fd SHA256 /td SHA256 /f "%PFX%" "%OUT%\crossview.sys"
) else (
  signtool sign /fd SHA256 /td SHA256 /f "%PFX%" /p "%PASS%" "%OUT%\crossview.sys"
)
if errorlevel 1 exit /b 1
echo signed %OUT%\crossview.sys
echo.
echo Load:
  echo   sc create CrossView type= kernel start= demand binPath= %OUT%\crossview.sys
echo   sc start CrossView
echo   %OUT%\cvscan.exe --fudmodule
echo   %OUT%\CrossView.exe
exit /b 0
