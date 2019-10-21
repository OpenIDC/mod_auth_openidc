@echo Requires git installed and an account on github

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
call bootstrap-vcpkg.bat

REM these are not needed because they come with Apache
rem .\vcpkg install apr:x64-windows
rem .\vcpkg install apr:x86-windows
.\vcpkg install curl:x64-windows
.\vcpkg install curl:x86-windows
.\vcpkg install openssl:x64-windows
.\vcpkg install openssl:x86-windows
.\vcpkg install jansson:x64-windows
.\vcpkg install jansson:x86-windows
cd..
git clone https://github.com/cisco/cjose

@echo Over changes to cjose and mod_auth_openidc so they compile on windows
xcopy changes\*.* /r

@echo Copy Apache headers and libs to the local folder for building.  Make sure the next two lines are correct for your system.
REM TODO:  add curl to download the zip file and extract it locally.
mkdir include
mkdir lib
xcopy D:\spe\flexsort\Apache24\include\*.* include
xcopy D:\spe\flexsort\Apache24\lib\*.* lib


rem call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars32.bat"
