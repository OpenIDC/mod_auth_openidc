rem Apache httpd download
rem https://www.apachelounge.com/download/VS16/binaries/httpd-2.4.41-win32-VS16.zip
rem https://www.apachelounge.com/download/VS16/binaries/httpd-2.4.41-win64-VS16.zip

rem https://github.com/zmartzone/mod_auth_openidc was copied to https://github.com/dematic-spe/mod_auth_openidc
rem Build steps
rem 1) bootstrap-windows.cmd
rem 2) build.cmd
rem the output is in the tartet folder.
set yourcompany=xyz

set FILE=mod_auth_openidc-2.4.0_3-win32-VS16.zip
set EXTRAS=-Dfile=%FILE% -Durl=https://artifactory.%yourcompany%.com/artifactory/ThirdParty -DrepositoryId=ThirdParty -DgeneratePom=true
call mvn -B deploy:deploy-file -DgroupId=COTS.Apache.httpd -DartifactId=mod_auth_openidc -Dversion=2.4.0_4 -Dclassifier=win32-VS16 -Dpackaging=zip %EXTRAS%

set FILE=mod_auth_openidc-2.4.0_3-win64-VS16.zip
set EXTRAS=-Dfile=%FILE% -Durl=https://artifactory.%yourcompany%.com/artifactory/ThirdParty -DrepositoryId=ThirdParty -DgeneratePom=true
call mvn -B deploy:deploy-file -DgroupId=COTS.Apache.httpd -DartifactId=mod_auth_openidc -Dversion=2.4.0_4 -Dclassifier=win64-VS16 -Dpackaging=zip %EXTRAS%

pause