
mod_auth_openidc
================

#Overview

This project is to build mod_auth_openidc for Apache  64bit on Windows 10 and for Apache 32bit on Windows 7.

#Specific versions targeted
Apache	httpd-2.4.53-win64-VS16.zip
Php		php-7.3.10-Win32-VC15-x64.zip
Using Visual Studio 2019

#Automated Build Script
Clone this repository and run the script bootstrap-windows.cmd in the root repository.

#The basic build steps are as follows

Clone this repositoy to a folder.
Using vcpkg 

Step 1) PS D:\spe\github\vcpkg> .\bootstrap-vcpkg.bat
	Build these libraries
		Apache (>=2.0)	
		cjose (>=0.4.1)
		Done OpenSSL (>=0.9.8) (>=1.0.1 for Elliptic Curve support)
		Done Curl (>=?)
		Jansson (>=2.0) (JSON parser for C)
		pcre3 (>=?) (Regular Expressions support)
		pkg-config
		and if you want Redis support:
		hiredis (>=0.9.0) (Redis client for C)
Step 2)   .\vcpkg search apr
Step 3)   .\vcpkg install apr:x64-windows
Step 3.1) .\vcpkg install apr:x32-windows
Step 4)   .\vcpkg install curl:x64-windows
Step 4.1) .\vcpkg install curl:x32-windows
Step 5)   .\vcpkg install openssl:x64-windows
Step 5.1) .\vcpkg install openssl:x32-windows
Step 6) d:\spe\github git clone https://github.com/cisco/cjose
Step 7) .\vcpkg install jansson
Step 8) d:\spe\github git clone https://github.com/redis/hiredis

	PS D:\spe\github\vcpkg> .\vcpkg integrate remove
	User-wide integration was removed
	PS D:\spe\github\vcpkg> .\vcpkg integrate install
	Applied user-wide integration for this vcpkg root.
	
	All MSBuild C++ projects can now #include any installed libraries.
	Linking will be handled automatically.
	Installing new libraries will make them instantly available.
	
	CMake projects should use: "-DCMAKE_TOOLCHAIN_FILE=D:/spe/github/vcpkg/scripts/buildsystems/vcpkg.cmake"
	PS D:\spe\github\vcpkg>




#A big thank you to Microsoft and the vcpkg project for making this easier.