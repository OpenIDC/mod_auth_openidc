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

REM This next step is perplexing.  Something verifies the case of the dll that it is loading and libeay32.dll must be uppercase 
REM following the import statements. vcpkg creates a lower case dll, but the imports from the lib file have the dll name unppercase.
mkdir target\x64
del target\x64\LIBEAY32.dll
copy  vcpkg\installed\x64-windows\bin\libeay32.dll target\x64\LIBEAY32.dll

mkdir target\x86
del target\x86\LIBEAY32.dll
copy  vcpkg\installed\x86-windows\bin\libeay32.dll target\x86\LIBEAY32.dll

powershell Compress-Archive -Path target\x64\LIBEAY32.dll -DestinationPath target\mod_auth_openidc-2.4.0_3-win64-VS16.zip
powershell Compress-Archive -Path target\mod_auth_openidc\x64\Release\mod_auth_openidc.dll -Update -DestinationPath target\mod_auth_openidc-2.4.0_3-win64-VS16.zip

powershell Compress-Archive -Path target\x86\LIBEAY32.dll -DestinationPath target\mod_auth_openidc-2.4.0_3-win32-VS16.zip
powershell Compress-Archive -Path target\mod_auth_openidc\x86\Release\mod_auth_openidc.dll -Update -DestinationPath target\mod_auth_openidc-2.4.0_3-win32-VS16.zip