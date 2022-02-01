#!/bin/sh

if [ -z "$1" ] ; then
	/opt/jboss/startup-scripts/keycloak.sh create &
	exit;
fi

PATH="${PATH}:${JBOSS_HOME}/bin"
		
while ! curl -k -s https://localhost:8443/auth/ > /dev/null ; do sleep 1 ; echo "."; done

kcadm.sh config truststore --trustpass password /opt/jboss/keycloak/standalone/configuration/application.keystore
kcadm.sh config credentials --server https://localhost:8443/auth --realm master --user "${KEYCLOAK_USER}" --password "${KEYCLOAK_PASSWORD}"

CID=$(kcadm.sh create clients \
	-r master \
	-s 'redirectUris=["https://localhost/protected/", "https://apache/protected/"]' \
	-s publicClient=false \
	-s clientAuthenticatorType=client-secret \
	-s clientId=myclient \
	-s secret=mysecret \
	-s enabled=true \
	-i)
kcadm.sh get clients/$CID/installation/providers/keycloak-oidc-keycloak-json
