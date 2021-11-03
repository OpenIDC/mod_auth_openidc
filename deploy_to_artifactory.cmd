rem Apache httpd download
rem https://www.apachelounge.com/download/VS16/binaries/httpd-2.4.51-win64-VS16.zip

rem https://github.com/zmartzone/mod_auth_openidc was copied to https://github.com/dematic-spe/mod_auth_openidc
rem Build steps
rem 1) bootstrap-windows.cmd
rem 2) build.cmd
rem the output is in the tartet folder.
set yourcompany=dematic

set FILE=target\mod_auth_openidc-2.4.9_4-win64-VS16.zip
set EXTRAS=-Dfile=%FILE% -Durl=https://artifactory.%yourcompany%.com/artifactory/ThirdParty -DrepositoryId=ThirdParty -DgeneratePom=true
call mvn -B deploy:deploy-file -DgroupId=COTS.Apache.httpd -DartifactId=mod_auth_openidc -Dversion=2.4.9_4 -Dclassifier=win64-VS16 -Dpackaging=zip %EXTRAS%

pause