#!/bin/sh

CONF=/usr/local/conf/httpd.conf
TMP=/tmp/httpd.conf

pushd `dirname $0` > /dev/null
SCRIPTPATH=`pwd`
popd > /dev/null

MDIR="${SCRIPTPATH}/metadata"

function rollover() {
  cat ${CONF} | sed '$ d' > ${TMP}
  echo "OIDCMetadataDir ${1}" >> ${TMP}
  sudo mv ${TMP} ${CONF}
  sudo /usr/local/bin/apachectl restart
}

./oidc-rp-certification.sh clean

TESTS="code id_token id_token+token code+token code+id_token code+id_token+token"
TOTAL=`echo ${TESTS} | wc -w`
NR=0
for PROFILE in ${TESTS} ; do
	rollover  ${MDIR}/${PROFILE}
	./oidc-rp-certification.sh ${PROFILE} || continue
	NR=$((NR+1))
done

echo ""
printf " # SUCCESS: accumulated profile coverage %.2f%%\n" `echo "100 * ${NR} / ${TOTAL}" | bc -l`
echo ""	

rollover $(dirname ${SCRIPTPATH})/metadata
