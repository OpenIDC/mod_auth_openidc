@echo Requires git installed and an account on github

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
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
.\vcpkg integrate install

cd..

@echo Over changes to cjose and mod_auth_openidc so they compile on windows
xcopy changes\*.* /r /q /y /s

@echo Downloading Apache http x32 and x64 zip files.
powershell .\download.ps1


rem call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars32.bat"
