@echo off
setlocal enableextensions
REM CROSSVIEW — build driver + CLI + GUI for Windows 11 x64.
REM Requires: VS 2022 C++ tools + WDK 10 (same version as the SDK).

cd /d "%~dp0"

if not defined WindowsSdkDir (
  if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
  ) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    call "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
  ) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
  )
)

if not defined WindowsSdkDir (
  echo Could not locate vcvars64.bat. Open an "x64 Native Tools" prompt and re-run.
  exit /b 1
)

if not defined WindowsSdkVerBinPath (
  echo WDK / Windows SDK bin path missing. Install WDK 10 matching your SDK.
  exit /b 1
)

set OUT=%~dp0bin\x64\Release
mkdir "%OUT%" 2>nul
mkdir "%OUT%\obj" 2>nul

echo [1/3] kernel driver
cl /nologo /c /kernel /GS- /W3 /Zi /Od /D_AMD64_ /D_WIN64 /D_NDEBUG /DNTSTRSAFE_LIB ^
  /I"%~dp0shared" /Fo"%OUT%\obj\\" /Fd"%OUT%\obj\driver.pdb" ^
  driver\driver.c driver\scan.c driver\offsets.c
if errorlevel 1 exit /b 1

link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB ^
  /OUT:"%OUT%\crossview.sys" /PDB:"%OUT%\crossview.pdb" /DEBUG ^
  "%OUT%\obj\driver.obj" "%OUT%\obj\scan.obj" "%OUT%\obj\offsets.obj" ^
  ntoskrnl.lib hal.lib BufferOverflowK.lib libcntpr.lib ntstrsafe.lib fltMgr.lib
if errorlevel 1 exit /b 1

echo [2/3] cvscan.exe
cl /nologo /W3 /O2 /Zi /DUNICODE /D_UNICODE /Fe"%OUT%\cvscan.exe" /Fo"%OUT%\obj\cvscan.obj" ^
  /Fd"%OUT%\obj\cvscan.pdb" cli\cvscan.c advapi32.lib version.lib fwpuclnt.lib rpcrt4.lib
if errorlevel 1 exit /b 1

echo [3/3] CrossView.exe
cl /nologo /W3 /O2 /Zi /DUNICODE /D_UNICODE /Fe"%OUT%\CrossView.exe" /Fo"%OUT%\obj\gui.obj" ^
  /Fd"%OUT%\obj\gui.pdb" gui\main.c comctl32.lib user32.lib gdi32.lib dwmapi.lib
if errorlevel 1 exit /b 1

copy /Y inf\CrossView.inf "%OUT%\CrossView.inf" >nul
echo.
echo Output: %OUT%
echo Next: sign.bat YourTestCert.pfx [password]
exit /b 0
