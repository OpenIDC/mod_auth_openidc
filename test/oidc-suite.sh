#!/bin/sh

CONF=/usr/local/conf/httpd.conf
MDIR=/Users/hzandbelt/projects/mod_auth_openidc/test/metadata
TMP=/tmp/httpd.conf

function rollover() {
  cat ${CONF} | sed '$ d' > ${TMP}
  echo "OIDCMetadataDir ${1}" >> ${TMP}
  sudo mv ${TMP} ${CONF}
  sudo /usr/local/bin/apachectl restart
}

./oidc-rp-certification.sh clean

for PROFILE in code id_token id_token+token code+token code+id_token code+id_token+token ; do
	rollover  ${MDIR}/${PROFILE}
	./oidc-rp-certification.sh ${PROFILE}
done

rollover "/Users/hzandbelt/projects/mod_auth_openidc/metadata"
