@echo Requires git installed and an account on github
@set STARTTIME=%time% 

git submodule update --init --recursive

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

@echo cd to vcpkg
cd vcpkg
call bootstrap-vcpkg.bat

.\vcpkg install pcre:x64-windows
.\vcpkg install pcre:x86-windows
.\vcpkg install apr:x64-windows
.\vcpkg install apr:x86-windows
.\vcpkg install curl:x64-windows
.\vcpkg install curl:x86-windows
.\vcpkg install openssl:x64-windows
.\vcpkg install openssl:x86-windows
.\vcpkg install jansson:x64-windows
.\vcpkg install jansson:x86-windows
REM .\vcpkg integrate install

REM Please Note:  The paths to the vcpkg builds are set in the VS project files.  I couldn't get the 32bit and 64 bit to work correctly.  

cd..

@echo Over changes to cjose and mod_auth_openidc so they compile on windows
xcopy changes\*.* /r /q /y /s

@echo Downloading Apache http x32 and x64 zip files.
powershell .\download.ps1

call build.cmd

@echo Start Time %STARTTIME%
@echo Stop Time %time%

