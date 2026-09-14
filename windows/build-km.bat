@echo off
setlocal enableextensions
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
set KIT=C:\Program Files (x86)\Windows Kits\10
set VER=10.0.26100.0
set INCLUDE=%KIT%\Include\%VER%\km;%KIT%\Include\%VER%\shared;%INCLUDE%
set LIB=%KIT%\Lib\%VER%\km\x64;%LIB%
cd /d C:\Users\Rich\src\Crossview\windows
set OUT=%CD%\bin\x64\Release
mkdir "%OUT%" 2>nul
mkdir "%OUT%\obj" 2>nul
echo [1/3] kernel driver
cl /nologo /c /kernel /GS- /W3 /Zi /Od /D_AMD64_ /D_WIN64 /D_NDEBUG /DNTSTRSAFE_LIB /I"%CD%\shared" /Fo"%OUT%\obj\\" /Fd"%OUT%\obj\driver.pdb" driver\driver.c driver\scan.c driver\offsets.c
if errorlevel 1 exit /b 1
link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB /OUT:"%OUT%\crossview.sys" /PDB:"%OUT%\crossview.pdb" /DEBUG "%OUT%\obj\driver.obj" "%OUT%\obj\scan.obj" "%OUT%\obj\offsets.obj" ntoskrnl.lib hal.lib BufferOverflowK.lib libcntpr.lib ntstrsafe.lib fltMgr.lib
if errorlevel 1 exit /b 1
echo [2/3] cvscan.exe
cl /nologo /W3 /O2 /Zi /DUNICODE /D_UNICODE /Fe"%OUT%\cvscan.exe" /Fo"%OUT%\obj\cvscan.obj" /Fd"%OUT%\obj\cvscan.pdb" cli\cvscan.c advapi32.lib version.lib fwpuclnt.lib rpcrt4.lib
if errorlevel 1 exit /b 1
echo [3/3] CrossView.exe
cl /nologo /W3 /O2 /Zi /DUNICODE /D_UNICODE /Fe"%OUT%\CrossView.exe" /Fo"%OUT%\obj\gui.obj" /Fd"%OUT%\obj\gui.pdb" gui\main.c comctl32.lib user32.lib gdi32.lib dwmapi.lib
if errorlevel 1 exit /b 1
copy /Y inf\CrossView.inf "%OUT%\CrossView.inf" >nul
echo BUILD_OK
exit /b 0
