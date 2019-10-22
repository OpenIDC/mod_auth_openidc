del target /s /q
del vcpkg/buildtrees /s /q
del vcpkg/installed /s /q
del vcpkg/downloads /s /q

del cjose/Release /s /q
del cjose/Win32 /s /q
del cjose/x64 /s /q

del x64 /s /q

del mod_auth_openidc.cpp
del mod_auth_openidc.sln
del mod_auth_openidc.vcxproj
del mod_auth_openidc.vcxproj.filters
del mod_auth_openidc.vcxproj.user
del stdafx.cpp
del stdafx.h
del targetver.h


call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
msbuild.exe "cjose/cjose.vcxproj" /p:Configuration=Release /p:Platform="x64" /t:Clean
msbuild.exe "mod_auth_openidc.vcxproj" /p:Configuration=Release /p:Platform="x64" /t:Clean

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars32.bat"
msbuild.exe "cjose/cjose.vcxproj" /p:Configuration=Release /p:Platform="win32" /t:Clean
msbuild.exe "mod_auth_openidc.vcxproj" /p:Configuration=Release /p:Platform="win32" /t:Clean
