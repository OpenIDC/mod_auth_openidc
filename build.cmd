call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

msbuild.exe "cjose/cjose.vcxproj" /p:Configuration=Release /p:Platform="x64"
msbuild.exe "mod_auth_openidc.vcxproj" /p:Configuration=Release /p:Platform="x64"

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars32.bat"
msbuild.exe "cjose/cjose.vcxproj" /p:Configuration=Release /p:Platform="win32"
msbuild.exe "mod_auth_openidc.vcxproj" /p:Configuration=Release /p:Platform="win32"


mkdir target
mkdir target\mod_auth_openidc
mkdir target\mod_auth_openidc\x64
mkdir target\mod_auth_openidc\x64\Release
mkdir target\mod_auth_openidc\x86
mkdir target\mod_auth_openidc\x86\Release
copy x64\Release\mod_auth_openidc.dll target\mod_auth_openidc\x64\Release\mod_auth_openidc.dll
copy win32\Release\mod_auth_openidc.dll target\mod_auth_openidc\x86\Release\mod_auth_openidc.dll

del target\mod_auth_openidc-2.4.0_3-win64-VS16.zip
del target\mod_auth_openidc-2.4.0_3-win32-VS16.zip

powershell Compress-Archive -Path target\mod_auth_openidc\x64\Release\mod_auth_openidc.dll -DestinationPath target\mod_auth_openidc-2.4.0_3-win64-VS16.zip
powershell Compress-Archive -Path target\mod_auth_openidc\x86\Release\mod_auth_openidc.dll -DestinationPath target\mod_auth_openidc-2.4.0_3-win32-VS16.zip