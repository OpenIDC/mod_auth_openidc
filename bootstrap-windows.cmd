@echo Requires git installed and an account on github
@set STARTTIME=%time% 


SET /P TRUSTSUBMODULE=Do you want to reset all submodules? (Choose Y first time you run or retest) (Y/[N])?
IF /I "%TRUSTSUBMODULE%" NEQ "Y" GOTO SKIP_SUBMODULE

REM Remove all untracked content of the module
git submodule foreach --recursive git clean -xfd
REM Force all changed track files to be default values.
git submodule foreach --recursive git reset --hard
REM Update to the Latest and greatest in the submodule
git submodule sync --recursive
git submodule update --recursive --remote

@ECHO Copy over changes to cjose so they compile on windows
xcopy changes\*.* /r /q /y /s

:SKIP_SUBMODULE

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

@echo Downloading Apache http x32 and x64 zip files.
powershell .\download.ps1

call build.cmd

@echo Start Time %STARTTIME%
@echo Stop Time %time%
