#!/bin/sh

if [ -z "$1" ] ; then
	"$0" create &
	exit;
fi

PATH="${PATH}:${JBOSS_HOME}/bin"

while ! curl -k -s https://localhost:8443/auth/ > /dev/null ; do sleep 2 ; done

kcadm.sh config truststore --trustpass password /opt/jboss/keycloak/standalone/configuration/application.keystore
kcadm.sh config credentials --server https://localhost:8443/auth --realm master --user "${KEYCLOAK_USER}" --password "${KEYCLOAK_PASSWORD}"

# web client
CID=$(kcadm.sh create clients \
	-r master \
	-s 'redirectUris=["https://localhost/protected/", "https://apache/protected/"]' \
	-s publicClient=false \
	-s clientAuthenticatorType=client-secret \
	-s clientId=web_client \
	-s secret=mysecret \
	-s enabled=true \
	-i)
kcadm.sh get clients/$CID/installation/providers/keycloak-oidc-keycloak-json

# client credentials
CID=$(kcadm.sh create clients \
	-r master \
	-s serviceAccountsEnabled=true \
	-s publicClient=false \
	-s directAccessGrantsEnabled=true \
	-s clientAuthenticatorType=client-secret \
	-s clientId=cc_client \
	-s secret=mysecret \
	-s enabled=true \
	-i)
kcadm.sh get clients/$CID/installation/providers/keycloak-oidc-keycloak-json

# introspection
CID=$(kcadm.sh create clients \
	-r master \
	-s serviceAccountsEnabled=true \
	-s publicClient=false \
	-s clientAuthenticatorType=client-secret \
	-s clientId=introspect_client \
	-s secret=mysecret \
	-s enabled=true \
	-i)
kcadm.sh get clients/$CID/installation/providers/keycloak-oidc-keycloak-json
