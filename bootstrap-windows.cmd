@echo Requires git installed and an account on github
@set STARTTIME=%time% 

git submodule update --init --recursive

if "%VSINSTALLDIR%"=="" call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

if exist ".\vcpkg\installed\x64-windows\include\openssl" goto VCPKG_INSTALLED

@echo cd to vcpkg
cd vcpkg
call bootstrap-vcpkg.bat

.\vcpkg install pcre:x64-windows
.\vcpkg install apr:x64-windows
.\vcpkg install curl:x64-windows
.\vcpkg install openssl:x64-windows
.\vcpkg install jansson:x64-windows

cd..

:VCPKG_INSTALLED

@echo Over changes to cjose so it compiles on windows
xcopy changes\*.* /r /q /y /s

@echo Downloading Apache http x32 and x64 zip files.
powershell .\download.ps1

call build.cmd

@echo Start Time %STARTTIME%
@echo Stop Time %time%
