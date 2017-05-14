#!/bin/bash

###########################################################################
# Copyright (C) 2016-2017 Ping Identity Corporation
#
# Script used to do automated OpenID Connect Relying Party Certification
# Testing for the mod_auth_openidc OIDC RP implementation for Apache HTTPd.
#
# @Version: 2.3.0, mod_auth_openidc >= v2.3.0
# 
# @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
#
###########################################################################

REDIRECT_URI="<THE-REDIRECT_URI-OF-YOUR-APACHE-MOD_AUTH_OPENIDC-INSTANCE>"
TARGET_URL="<YOUR-APPLICATION-URL-PROTECTED-BY-MOD_AUTH_OPENIDC>"
RP_NAME="<YOUR-RP-TEST-CLIENT-NAME>"
LOG_FILE="<YOUR-APACHE-ERROR-LOGFILE-WITH-DEBUG-MESSAGES>"

RP_TEST_PORT=8080
RP_TEST_HOST="rp.certification.openid.net"
COOKIE_JAR="/tmp/cookie.jar"

FLAGS="-s -k -b ${COOKIE_JAR} -c ${COOKIE_JAR}"

SETENV="$(dirname "$0")/setenv.sh"
if [[ -x "${SETENV}" ]]; then
	source "${SETENV}"
fi

RP_TEST_URL="https://${RP_TEST_HOST}:${RP_TEST_PORT}"
RP_TEST_URL_ENC="https%3A%2F%2F${RP_TEST_HOST}%3A${RP_TEST_PORT}"

TESTS="
	rp-discovery-webfinger-url
	rp-discovery-webfinger-http-href
	rp-discovery-webfinger-acct
	rp-discovery-webfinger-unknown-member
	rp-discovery-issuer-not-matching-config
	rp-discovery-openid-configuration
	rp-discovery-jwks_uri-keys
	rp-registration-dynamic
	rp-response_type-code
	rp-response_type-id_token
	rp-response_type-id_token+token
	rp-response_type-code+id_token
	rp-response_type-code+token
	rp-response_type-code+id_token+token
	rp-response_mode-form_post
	rp-claims_request-id_token
	rp-claims_request-userinfo
	rp-request_uri-enc
	rp-request_uri-sig+enc
	rp-request_uri-unsigned
	rp-request_uri-sig
	rp-scope-userinfo-claims
	rp-nonce-unless-code-flow
	rp-nonce-invalid
	rp-token_endpoint-client_secret_basic
	rp-token_endpoint-client_secret_post
	rp-token_endpoint-client_secret_jwt
	rp-token_endpoint-private_key_jwt
	rp-id_token-bad-sig-rs256
	rp-id_token-bad-sig-hs256
	rp-id_token-sig+enc
	rp-id_token-sig+enc-a128kw
	rp-id_token-sig-rs256
	rp-id_token-sig-hs256
	rp-id_token-sig-es256
	rp-id_token-sig-none
	rp-id_token-bad-c_hash
	rp-id_token-missing-c_hash
	rp-id_token-bad-at_hash
	rp-id_token-missing-at_hash
	rp-id_token-issuer-mismatch
	rp-id_token-iat
	rp-id_token-bad-sig-es256
	rp-id_token-aud
	rp-id_token-sub
	rp-id_token-kid-absent-single-jwks
	rp-id_token-kid-absent-multiple-jwks
	rp-key-rotation-op-sign-key
	rp-key-rotation-op-enc-key
	rp-claims-aggregated
	rp-claims-distributed
	rp-userinfo-bearer-header
	rp-userinfo-bearer-body
	rp-userinfo-sig
	rp-userinfo-sig+enc
	rp-userinfo-enc
	rp-userinfo-bad-sub-claim
"

TEST_ERR="
"

TESTS_OBSOLETE="
	rp_support_3rd_party_init_login
	rp-key-rotation-rp-sign-key
	rp-key-rotation-rp-enc-key
"

TESTS_UNSUPPORTED="
	rp-self-issued
"

# for f in `find . -name *.log` ; do tail -n 1 $f | grep -v " OK" ; done
# for f in `find . -name *.log` ; do echo $f && tail -n 1 $f | grep -v " OK" ; done
# mv rp-id_token-sig+enc.conf rp-id_token-sig%2Benc.conf && mv rp-request_uri-sig+enc.conf rp-request_uri-sig%2Benc.conf && mv rp-id_token-sig+enc-a128kw.conf rp-id_token-sig%2Benc-a128kw.conf
# for f in `ls *.conf` ; do ln -s $f rp.certification.openid.net%3A8080%2Fmod_auth_openidc%2F$f ; done

#w3m -dump https://rp.certification.openid.net:8080/list?profile=C | cut -d" " -f1 | grep "rp-"
TESTS_CODE="
	rp-response_type-code
	rp-scope-userinfo-claims
	rp-nonce-invalid
	rp-token_endpoint-client_secret_basic
	rp-id_token-aud
	rp-id_token-kid-absent-single-jwks
	rp-id_token-sig-none
	rp-id_token-issuer-mismatch
	rp-id_token-kid-absent-multiple-jwks
	rp-id_token-bad-sig-rs256
	rp-id_token-iat
	rp-id_token-sig-rs256
	rp-id_token-sub
	rp-userinfo-bad-sub-claim
	rp-userinfo-bearer-header
	rp-discovery-jwks_uri-keys
	rp-discovery-webfinger-http-href
	rp-discovery-webfinger-acct
	rp-discovery-webfinger-unknown-member
	rp-discovery-issuer-not-matching-config
	rp-discovery-webfinger-url
	rp-discovery-openid-configuration
	rp-registration-dynamic
	rp-request_uri-sig+enc
	rp-request_uri-sig
	rp-request_uri-unsigned
	rp-request_uri-enc
	rp-token_endpoint-private_key_jwt
	rp-token_endpoint-client_secret_jwt
	rp-token_endpoint-client_secret_post
	rp-id_token-sig+enc-a128kw
	rp-id_token-bad-sig-es256
	rp-id_token-sig+enc
	rp-id_token-sig-es256
	rp-id_token-bad-sig-hs256
	rp-id_token-sig-hs256
	rp-key-rotation-op-sign-key-native
	rp-key-rotation-op-sign-key
	rp-key-rotation-op-enc-key
	rp-claims-distributed
	rp-claims-aggregated
	rp-userinfo-sig+enc
	rp-userinfo-bearer-body
	rp-userinfo-sig
	rp-userinfo-enc
"

#w3m -dump https://rp.certification.openid.net:8080/list?profile=I | cut -d" " -f1 | grep "rp-"
TESTS_IDTOKEN="
	rp-response_type-id_token
	rp-scope-userinfo-claims
	rp-nonce-unless-code-flow
	rp-nonce-invalid
	rp-id_token-aud
	rp-id_token-kid-absent-single-jwks
	rp-id_token-issuer-mismatch
	rp-id_token-kid-absent-multiple-jwks
	rp-id_token-bad-sig-rs256
	rp-id_token-iat
	rp-id_token-sig-rs256
	rp-id_token-sub
	rp-discovery-jwks_uri-keys
	rp-discovery-webfinger-http-href
	rp-discovery-webfinger-acct
	rp-discovery-webfinger-unknown-member
	rp-discovery-issuer-not-matching-config
	rp-discovery-webfinger-url
	rp-discovery-openid-configuration
	rp-registration-dynamic
	rp-response_mode-form_post
	rp-request_uri-sig+enc
	rp-request_uri-sig
	rp-request_uri-unsigned
	rp-request_uri-enc
	rp-id_token-sig+enc-a128kw
	rp-id_token-bad-sig-es256
	rp-id_token-sig+enc
	rp-id_token-sig-es256
	rp-id_token-bad-sig-hs256
	rp-id_token-sig-hs256
	rp-key-rotation-op-sign-key-native
	rp-key-rotation-op-sign-key
	rp-key-rotation-op-enc-key
"

#w3m -dump https://rp.certification.openid.net:8080/list?profile=IT | cut -d" " -f1 | grep "rp-"
TESTS_IDTOKEN_TOKEN="
	rp-response_type-id_token+token
	rp-scope-userinfo-claims
	rp-nonce-unless-code-flow
	rp-nonce-invalid
	rp-id_token-aud
	rp-id_token-kid-absent-single-jwks
	rp-id_token-issuer-mismatch
	rp-id_token-bad-at_hash
	rp-id_token-kid-absent-multiple-jwks
	rp-id_token-bad-sig-rs256
	rp-id_token-iat
	rp-id_token-missing-at_hash
	rp-id_token-sig-rs256
	rp-id_token-sub
	rp-userinfo-bad-sub-claim
	rp-userinfo-bearer-header
	rp-discovery-jwks_uri-keys
	rp-discovery-webfinger-http-href
	rp-discovery-webfinger-acct
	rp-discovery-webfinger-unknown-member
	rp-discovery-issuer-not-matching-config
	rp-discovery-webfinger-url
	rp-discovery-openid-configuration
	rp-registration-dynamic
	rp-response_mode-form_post
	rp-request_uri-sig+enc
	rp-request_uri-sig
	rp-request_uri-unsigned
	rp-request_uri-enc
	rp-id_token-sig+enc-a128kw
	rp-id_token-bad-sig-es256
	rp-id_token-sig+enc
	rp-id_token-sig-es256
	rp-id_token-bad-sig-hs256
	rp-id_token-sig-hs256
	rp-key-rotation-op-sign-key-native
	rp-key-rotation-op-sign-key
	rp-key-rotation-op-enc-key
	rp-claims-distributed
	rp-claims-aggregated
	rp-userinfo-sig+enc
	rp-userinfo-bearer-body
	rp-userinfo-sig
	rp-userinfo-enc
"

#w3m -dump https://rp.certification.openid.net:8080/list?profile=CI | cut -d" " -f1 | grep "rp-"
TESTS_CODE_IDTOKEN="
		rp-response_type-code+id_token
		rp-scope-userinfo-claims
		rp-nonce-unless-code-flow
		rp-nonce-invalid
		rp-token_endpoint-client_secret_basic
		rp-id_token-aud
		rp-id_token-kid-absent-single-jwks
		rp-id_token-bad-c_hash
		rp-id_token-issuer-mismatch
		rp-id_token-kid-absent-multiple-jwks
		rp-id_token-missing-c_hash
		rp-id_token-bad-sig-rs256
		rp-id_token-iat
		rp-id_token-sig-rs256
		rp-id_token-sub
		rp-userinfo-bad-sub-claim
		rp-userinfo-bearer-header
		rp-discovery-jwks_uri-keys
		rp-discovery-webfinger-http-href
		rp-discovery-webfinger-acct
		rp-discovery-webfinger-unknown-member
		rp-discovery-issuer-not-matching-config
		rp-discovery-webfinger-url
		rp-discovery-openid-configuration
		rp-registration-dynamic
		rp-response_mode-form_post
		rp-request_uri-sig+enc
		rp-request_uri-sig
		rp-request_uri-unsigned
		rp-request_uri-enc
		rp-token_endpoint-private_key_jwt
		rp-token_endpoint-client_secret_jwt
		rp-token_endpoint-client_secret_post
		rp-id_token-sig+enc-a128kw
		rp-id_token-bad-sig-es256
		rp-id_token-sig+enc
		rp-id_token-sig-es256
		rp-id_token-bad-sig-hs256
		rp-id_token-sig-hs256
		rp-key-rotation-op-sign-key-native
		rp-key-rotation-op-sign-key
		rp-key-rotation-op-enc-key
		rp-claims-distributed
		rp-claims-aggregated
		rp-userinfo-sig+enc
		rp-userinfo-bearer-body
		rp-userinfo-sig
		rp-userinfo-enc
"

#w3m -dump https://rp.certification.openid.net:8080/list?profile=CIT | cut -d" " -f1 | grep "rp-"
TESTS_CODE_IDTOKEN_TOKEN="
	rp-response_type-code+id_token+token
	rp-scope-userinfo-claims
	rp-nonce-unless-code-flow
	rp-nonce-invalid
	rp-token_endpoint-client_secret_basic
	rp-id_token-aud
	rp-id_token-kid-absent-single-jwks
	rp-id_token-bad-c_hash
	rp-id_token-issuer-mismatch
	rp-id_token-bad-at_hash
	rp-id_token-kid-absent-multiple-jwks
	rp-id_token-missing-c_hash
	rp-id_token-bad-sig-rs256
	rp-id_token-iat
	rp-id_token-missing-at_hash
	rp-id_token-sig-rs256
	rp-id_token-sub
	rp-userinfo-bad-sub-claim
	rp-userinfo-bearer-header
	rp-discovery-jwks_uri-keys
	rp-discovery-webfinger-http-href
	rp-discovery-webfinger-acct
	rp-discovery-webfinger-unknown-member
	rp-discovery-issuer-not-matching-config
	rp-discovery-webfinger-url
	rp-discovery-openid-configuration
	rp-registration-dynamic
	rp-response_mode-form_post
	rp-request_uri-sig+enc
	rp-request_uri-sig
	rp-request_uri-unsigned
	rp-request_uri-enc
	rp-token_endpoint-private_key_jwt
	rp-token_endpoint-client_secret_jwt
	rp-token_endpoint-client_secret_post
	rp-id_token-sig+enc-a128kw
	rp-id_token-bad-sig-es256
	rp-id_token-sig+enc
	rp-id_token-sig-es256
	rp-id_token-bad-sig-hs256
	rp-id_token-sig-hs256
	rp-key-rotation-op-sign-key-native
	rp-key-rotation-op-sign-key
	rp-key-rotation-op-enc-key
	rp-claims-distributed
	rp-claims-aggregated
	rp-userinfo-sig+enc
	rp-userinfo-bearer-body
	rp-userinfo-sig
	rp-userinfo-enc
"

#w3m -dump https://rp.certification.openid.net:8080/list?profile=CT | cut -d" " -f1 | grep "rp-"
TESTS_CODE_TOKEN="
	rp-response_type-code+token
	rp-scope-userinfo-claims
	rp-nonce-unless-code-flow
	rp-nonce-invalid
	rp-token_endpoint-client_secret_basic
	rp-id_token-aud
	rp-id_token-kid-absent-single-jwks
	rp-id_token-issuer-mismatch
	rp-id_token-kid-absent-multiple-jwks
	rp-id_token-bad-sig-rs256
	rp-id_token-iat
	rp-id_token-sig-rs256
	rp-id_token-sub
	rp-userinfo-bad-sub-claim
	rp-userinfo-bearer-header
	rp-discovery-jwks_uri-keys
	rp-discovery-webfinger-http-href
	rp-discovery-webfinger-acct
	rp-discovery-webfinger-unknown-member
	rp-discovery-issuer-not-matching-config
	rp-discovery-webfinger-url
	rp-discovery-openid-configuration
	rp-registration-dynamic
	rp-response_mode-form_post
	rp-request_uri-sig+enc
	rp-request_uri-sig
	rp-request_uri-unsigned
	rp-request_uri-enc
	rp-id_token-sig+enc-a128kw
	rp-id_token-bad-sig-es256
	rp-id_token-sig+enc
	rp-id_token-sig-es256
	rp-id_token-bad-sig-hs256
	rp-id_token-sig-hs256
	rp-key-rotation-op-sign-key-native
	rp-key-rotation-op-sign-key
	rp-key-rotation-op-enc-key
	rp-claims-distributed
	rp-claims-aggregated
	rp-userinfo-sig+enc
	rp-userinfo-bearer-body
	rp-userinfo-sig
	rp-userinfo-enc
"

#w3m -dump https://rp.certification.openid.net:8080/list?profile=CNF | cut -d" " -f1 | grep "rp-"
TESTS_CONFIG="
	rp-discovery-jwks_uri-keys
	rp-discovery-issuer-not-matching-config
	rp-discovery-openid-configuration
	rp-id_token-sig-none
	rp-key-rotation-op-sign-key-native
	rp-key-rotation-op-sign-key
"

#w3m -dump https://rp.certification.openid.net:8080/list?profile=DYN | cut -d" " -f1 | grep "rp-"
TESTS_DYNAMIC="
	rp-discovery-jwks_uri-keys
	rp-discovery-webfinger-acct
	rp-discovery-issuer-not-matching-config
	rp-discovery-webfinger-url
	rp-discovery-openid-configuration
	rp-registration-dynamic
	rp-request_uri-sig
	rp-request_uri-unsigned
	rp-id_token-sig-none
	rp-key-rotation-op-sign-key-native
	rp-key-rotation-op-sign-key
	rp-userinfo-sig
"

if [ -z $1 ] ; then
	echo
	printf "Usage: ${0}\n\tall\n\tcode\n\tid_token\n\tid_token+token\n\tcode+id_token\n\tcode+token\n\tcode+id_token+token\n\tconfig\n\tdynamic${TESTS}"
	echo
	exit
fi

# printout a test message
function message() {
	local ID=$1
	local MSG=$2
	local PARAM=$3
	printf " [" && date +"%D %T" | tr -d '\n' && printf "] " && printf "%s: %s ... " "${ID}" "${MSG}"
	if [ "$PARAM" != "-n" ] ; then
		printf "\n"
	fi
}

# parse the location header value out of a curl -i response
function grep_location_header_value() {
	grep -i "Location:" | cut -d" " -f2 | tr -d '\r' | cut -d"#" -f2
	return $?
}

# find a pattern in the Apache log file
function find_in_logfile() {
	local TEST_ID=$1
	local MESSAGE=$2
	local NUMBER=$3
	local MATCH=$4
	local MATCH2=$5
	
	message "${TEST_ID}" "${MESSAGE}" "-n"
	if [ -z "${MATCH2}" ] ; then
		tail -n ${NUMBER} ${LOG_FILE} | grep -q "${MATCH}" && echo "OK" || { printf "ERROR:\n could not find \"%s\" in logfile\n" "${MATCH}" && false; }
	else
		tail -n ${NUMBER} ${LOG_FILE} | grep "${MATCH}" | grep -q "${MATCH2}" && echo "OK" || { printf "ERROR:\n could not find \"%s\" and \"%s\" in logfile\n" "${MATCH}" "${MATCH2}" && false; }
	fi
}

# create CSRF token to be supplied on subsequent call
function create_csrf() {
	local TEST_ID=$1

	message ${TEST_ID} "initiate CSRF" "-n"
	local RESPONSE=`echo ${FLAGS} -j | xargs curl ${TARGET_URL}`
	if [ $? -ne 0 ] ; then
		echo "ERROR"
		return -1
	fi
	CSRF=`echo "${RESPONSE}" | grep hidden | grep x_csrf | cut -d"\"" -f6`
	if [ $? -ne 0 ] ; then
		echo "ERROR"
		return -1
	else
		echo "OK"
	fi
}

# call the RP endpoint (=mod_auth_openidc's redirect URI) to kick off discovery and/or SSO
function initiate_sso() {
	local RP_ID=$1
	local TEST_ID=$2
	local ISSUER=$3
	local RESULT_PARAM=$4

	create_csrf "${TEST_ID}"

	message "${TEST_ID}" "initiate SSO" "-n"
	RESULT=`echo ${FLAGS} -i | xargs curl -G --data-urlencode "iss=${ISSUER}" --data-urlencode "target_link_uri=${TARGET_URL}" --data-urlencode "x_csrf=${CSRF}" ${REDIRECT_URI}`
	if [ $? -ne 0 ] ; then
		echo "ERROR"
		return -1
	fi

	if [ "${RESULT_PARAM}" != "nogrep" ] ; then
		RESULT=`echo "${RESULT}" | grep_location_header_value`
		if [ $? -ne 0 ] ; then
			echo "ERROR"
			return -1
		fi		
	fi

	if [ -z "${RESULT_PARAM}" ] ; then
		echo "OK"
	elif [ "${RESULT_PARAM}" == "authorization" ] ; then
		echo "${RESULT}" | grep -q "${RP_TEST_URL}/${RP_ID}/${TEST_ID}/authorization" && echo "OK" || { echo "ERROR: no authentication request found in redirect" && false; }
	fi
	# else it should be "nogrep" or "return"
}

function grep_location_header_value_result() {
	if [ $? -ne 0 ] ; then
		echo "ERROR: result is: \"${RESULT}\""
		return -1
	fi
	if `echo "${RESULT}" | head -1 | grep -q "HTTP/1.1 4"` ; then
		echo "ERROR: result is:\n${RESULT}"
		return -1
	fi
	RESULT=`echo "${RESULT}" | grep_location_header_value`
	if [ $? -ne 0 ] ; then
		echo "ERROR: could not parse Location header from: \"${RESULT}\""
		return -1
	else
		echo "OK"
	fi
}

# send an authentication request (passed in $2) to the OP
function send_authentication_request() {
	local TEST_ID=$1
	local REQUEST=$2
	
	message "${TEST_ID}" "send authentication request to OP" "-n"
	RESULT=`echo ${FLAGS} -i | xargs curl "${REQUEST}"`
	grep_location_header_value_result
}

# send an authentication response (passed in $2) to the RP
function send_authentication_response() {
	local TEST_ID=$1
	local RESPONSE=$2
	local RESPONSE_MODE=$3
	
	message ${TEST_ID} "return authentication response to RP" "-n"
	if [ -z "${RESPONSE_MODE}" ] || [ "${RESPONSE_MODE}" == query ] ; then
		RESULT=`echo ${FLAGS} -i | xargs curl "${RESPONSE}"`
	else
		RESULT=`echo ${FLAGS} -i | xargs curl -d "${RESPONSE}&response_mode=${RESPONSE_MODE}" ${REDIRECT_URI}`
	fi
	grep_location_header_value_result
}

# access the original URL that is passed in $2 (after authentication has succeeded)
function application_access() {
	local TEST_ID=$1
	local RETURN=$2

	message ${TEST_ID} "access application as authenticated user" "-n"
	RESULT=`echo ${FLAGS} | xargs curl "${RETURN}"`
	MATCH="\[OIDC_CLAIM_sub\]"
	echo "${RESULT}" | grep -q "${MATCH}" && echo "OK" || { printf "ERROR:\n could not find \"%s\" in client HTML output:\n%s\n" "${MATCH}" "${RESULT}" && false; }
}

# send a request and receive the response (possibly with an error)
function do_request_response() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"
	
	initiate_sso ${RP_ID} ${TEST_ID} ${ISSUER} || return -1
	send_authentication_request ${TEST_ID} ${RESULT} || return -1
	send_authentication_response ${TEST_ID} ${RESULT} ${RESPONSE_MODE} || return -1
}

# go through a regular flow from discovery to authenticated application access
function regular_flow() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	do_request_response ${RP_ID} ${TEST_ID} ${RESPONSE_MODE} || return -1
	application_access ${TEST_ID} ${RESULT} || return -1
}

################################################
# the RP certification tests, one per function #
################################################

function url_encode_id() {
	echo "${1//+/%2B}"	
}

function rp_discovery_webfinger_url() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	local USER_INPUT="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	create_csrf "${TEST_ID}"

	message "${TEST_ID}" "initiate URL based Discovery" "-n"
	RESULT=`echo ${FLAGS} -i | xargs curl -G --data-urlencode "disc_user=${USER_INPUT}" --data-urlencode "target_link_uri=${TARGET_URL}" --data-urlencode "x_csrf=${CSRF}" ${REDIRECT_URI}`
	if [ $? -ne 0 ] ; then
		echo "ERROR"
		return -1
	fi
	
	# check that the authentication request contains a login_hint parameter set to the URL value
	echo ${RESULT} | grep -q "&login_hint=" && echo "OK" || { printf "ERROR: could not find \"login_hint=\" in authorization request\n" && return -1; }

	# check that the webfinger request contains the URL"
	URL="${RP_TEST_URL}/.well-known/webfinger?resource=${RP_TEST_URL_ENC}%2F$(url_encode_id ${RP_ID})%2F${TEST_ID}&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"
	find_in_logfile "${TEST_ID}" "check webfinger request" 75 "oidc_util_http_get: get URL=\"${URL}\"" || return -1
	# check that the webfinger request contains the right issuer:"
	find_in_logfile "${TEST_ID}" "check webfinger issuer result" 75 "oidc_proto_webfinger_discovery: returning issuer \"${USER_INPUT}\" for resource \"${USER_INPUT}\" after doing successful webfinger-based discovery" || return -1
}

function rp_discovery_webfinger_acct() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	local ACCT="${RP_ID}.${TEST_ID}@${RP_TEST_HOST}:${RP_TEST_PORT}"

	initiate_sso ${RP_ID} ${TEST_ID} ${ACCT} "return" || return -1
	
	# check that the authentication request contains a login_hint parameter set to the acct: value
	echo ${RESULT} | grep -q "&login_hint=${RP_ID}" && echo "OK" || echo "ERROR"

	# check that the webfinger request contains acct:"
	URL="${RP_TEST_URL}/.well-known/webfinger?resource=acct%3A$(url_encode_id ${RP_ID}).${TEST_ID}%40${RP_TEST_HOST}%3A${RP_TEST_PORT}&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"
	find_in_logfile "${TEST_ID}" "check webfinger request" 75 "oidc_util_http_get: get URL=\"${URL}\"" || return -1
	# check that the webfinger request contains the right issuer:"
	find_in_logfile "${TEST_ID}" "check webfinger issuer result" 75 "oidc_proto_webfinger_discovery: returning issuer \"${RP_TEST_URL}/${RP_ID}/${TEST_ID}\" for resource \"acct:${ACCT}\" after doing successful webfinger-based discovery" || return -1
}

function rp_discovery_issuer_not_matching_config() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	initiate_sso ${RP_ID} "${TEST_ID}" "${ISSUER}" "nogrep" || return -1
	MATCH="Could not find valid provider metadata"
	echo "${RESULT}" | grep -q "${MATCH}" && echo "OK" || { printf "ERROR:\n could not find \"%s\" in client HTML output:\n%s\n" "${MATCH}" "${RESULT}" && return -1; }

	# make sure that we've got the right error message in the error log
	WRONG_ISSUER="https://example.com"
	find_in_logfile "${TEST_ID}" "check issuer mismatch error message" 15 "requested issuer (${ISSUER}) does not match the \"issuer\" value in the provider metadata file: ${WRONG_ISSUER}" || return -1
}

function rp_discovery_openid_configuration() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	# check that the authentication request is initiated to the discovered authorization endpoint
	initiate_sso "${RP_ID}" "${TEST_ID}" "${ISSUER}" "authorization" || return -1

	# check that the registration is initiated to the discovered endpoint: ${RP_ID}/${TEST_ID}/registration"
	# TODO: can only do this if the .provider file was cleaned up beforehand
	#find_in_logfile "${TEST_ID}" "check registration request" 75 "oidc_util_http_get: get URL=\"${URL}\""
}

function rp_discovery_jwks_uri_keys() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	
	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# make sure that we've validated and id_token correctly with the jwks discovered on the jwks_uri
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"
	find_in_logfile "${TEST_ID}" "check id_token parse result" 150 "oidc_proto_parse_idtoken: successfully parsed" "\"iss\": \"${ISSUER}\"" || return -1
	find_in_logfile "${TEST_ID}" "check JWK retrieval by \"kid\"" 150 "oidc_proto_get_key_from_jwks: found matching kid:" || return -1
	find_in_logfile "${TEST_ID}" "check id_token verification" 150 "oidc_proto_jwt_verify: JWT signature verification with algorithm \"RS256\" was successful" || return -1
}

function rp_registration_dynamic() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	# check that the authentication request is initiated to the discovered authorization endpoint
	initiate_sso ${RP_ID} "${TEST_ID}" "${ISSUER}" "authorization" || return -1

	# TODO: only when .client file is cleaned up
	# check that the registration is initiated and a successful client registration response is returned"
}

function rp_discovery_webfinger_unknown_member() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	local ACCT="${RP_ID}.${TEST_ID}@${RP_TEST_HOST}:${RP_TEST_PORT}"

	# check that the authentication request is initiated to the discovered authorization endpoint
	initiate_sso ${RP_ID} "${TEST_ID}" "${ACCT}" "authorization" || return -1

	# check that the webfinger request contains acct:
	URL="${RP_TEST_URL}/.well-known/webfinger?resource=acct%3A$(url_encode_id ${RP_ID}).${TEST_ID}%40${RP_TEST_HOST}%3A${RP_TEST_PORT}&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"
	find_in_logfile "${TEST_ID}" "check webfinger request" 75 "oidc_util_http_get: get URL=\"${URL}\"" || return -1
	# check that the response contains \"dummy\": \"foobar\""
	find_in_logfile "${TEST_ID}" "check webfinger response" 75 "oidc_util_http_call: response=" "\"dummy\": \"foobar\"" || return -1
}

function rp_discovery_webfinger_http_href() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	local ACCT="${RP_ID}.${TEST_ID}@${RP_TEST_HOST}:${RP_TEST_PORT}"

	# check that the authentication request is initiated to the discovered authorization endpoint
	initiate_sso ${RP_ID} "${TEST_ID}" "${ACCT}" "nogrep" || return -1
	
	MATCH="Could not resolve the provided account name to an OpenID Connect provider"
	echo "${RESULT}" | grep -q "${MATCH}" && echo "OK" || { printf "ERROR:\n could not find \"%s\" in client HTML output:\n%s\n" "${MATCH}" "${RESULT}" && return -1; }

	# check that the module choked on the plain HTTP href value
	find_in_logfile "${TEST_ID}" "check reject webfinger response" 50 "oidc_proto_webfinger_discovery: response JSON object contains an \"href\" value that is not a valid \"https\" URL" || return -1
}

function rp_response_type_code() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"response_type\" is set to \"code\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
		
	# check that the code authorization response handling is triggered
	find_in_logfile "${TEST_ID}" "check \"code\" response" 150 "oidc_proto_handle_authorization_response_code: enter" || return -1
}

function rp_response_type_id_token() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"response_type\" is set to \"id_token\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# check that the id_token authorization response handling is triggered
	find_in_logfile "${TEST_ID}" "check \"id_token\" response" 150 "oidc_proto_handle_authorization_response_idtoken: enter" || return -1
}

function rp_response_type_id_token_token() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"response_type\" is set to \"id_token token\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
		
	# check that the id_token token authorization response handling is triggered
	find_in_logfile "${TEST_ID}" "check \"id_token token\" response" 150 "oidc_proto_handle_authorization_response_idtoken_token: enter" || return -1	
}
		
function rp_response_type_code_id_token() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"response_type\" is set to \"code id_token\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
		
	# check that the code id_token authorization response handling is triggered
	find_in_logfile "${TEST_ID}" "check \"code id_token\" response" 150 "oidc_proto_authorization_response_code_idtoken: enter" || return -1
}
		
function rp_response_type_code_token() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"response_type\" is set to \"code token\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
		
	# check that the code token authorization response handling is triggered
	find_in_logfile "${TEST_ID}" "check \"code token\" response" 150 "oidc_proto_handle_authorization_response_code_token: enter" || return -1
}
		
function rp_response_type_code_id_token_token() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"response_type\" is set to \"code id_token token\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# check that the code id_token token authorization response handling is triggered
	find_in_logfile "${TEST_ID}" "check \"code id_token token\" response" 150 "oidc_proto_authorization_response_code_idtoken_token: enter"	 || return -1
}

function rp_response_mode_form_post() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"response_mode\" is set to \"form_post\""
	echo " * "

	initiate_sso ${RP_ID} "${TEST_ID}" "${ISSUER}" || return -1
		
	message "${TEST_ID}" "send authentication request to OP" "-n"
	RESULT=`echo ${FLAGS} | xargs curl "${RESULT}"`
	echo "OK"
	
#	echo "${RESULT}"
#	return -1
	
#	AT=`echo "${RESULT}" | grep "name=\"access_token" | cut -d"=" -f7-9 | cut -d "\"" -f2`
#	IDT=`echo "${RESULT}" | grep "name=\"id_token" | cut -d"=" -f4 | cut -d"\"" -f2`
#	STATE=`echo "${RESULT}" | grep "name=\"state" | cut -d"=" -f12 | cut -d"\"" -f2`

	AT=`echo "${RESULT}" | grep "name=\"access_token" | cut -d"=" -f4-6 | cut -d "\"" -f2`
	IDT=`echo "${RESULT}" | grep "name=\"id_token" | cut -d"=" -f4 | cut -d"\"" -f2`
	CODE=`echo "${RESULT}" | grep "name=\"code" | cut -d"=" -f4-6 | cut -d"\"" -f2`
	STATE=`echo "${RESULT}" | grep "name=\"state" | cut -d"=" -f4 | cut -d"\"" -f2`

	RESPONSE="state=${STATE}"
	if [ -n "${AT}" ] ; then
		RESPONSE="${RESPONSE}&access_token=${AT}"
	fi
	if [ -n "${IDT}" ] ; then
		RESPONSE="${RESPONSE}&id_token=${IDT}"
	fi
	if [ -n "${CODE}" ] ; then
		RESPONSE="${RESPONSE}&code=${CODE}"
	fi

#echo "####"
#echo ${RESULT}
#echo "####"
#echo ${RESPONSE}
#echo "####"
#echo ${CODE}
#echo "####"
#return -1

	send_authentication_response ${TEST_ID} "${RESPONSE}" form_post
	application_access ${TEST_ID} ${RESULT} || return -1

	# check that form_post authorization response handling is triggered
	find_in_logfile "${TEST_ID}" "check form_post response" 150 "oidc_handle_authorization_response: enter, response_mode=form_post" || return -1

	# check that id_token token is valid
	find_in_logfile "${TEST_ID}" "check valid id_token" 150 "oidc_proto_parse_idtoken: valid id_token for user" || return -1
}

function rp_claims_request_id_token() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"scope\" is set to \"openid\""
	echo " * [server] prerequisite: .conf exists and \"auth_request_params\" is set to e.g. \"claims=%7B%20%22id_token%22%3A%20%7B%20%22email%22%3A%20%7B%22essential%22%3A%20true%7D%20%7D%20%7D\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
	
	# make sure the id_token contains the email claim
	find_in_logfile "${TEST_ID}" "check email claim" 150 "oidc_proto_parse_idtoken: successfully parsed" "\"email\": \"diana@example.org\"" || return -1
	# check that we finished id_token validation succesfully
	find_in_logfile "${TEST_ID}" "check valid id_token" 150 "oidc_proto_parse_idtoken: valid id_token for user" || return -1
}

function rp_claims_request_userinfo() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"scope\" is set to \"openid\""
	echo " * [server] prerequisite: .conf exists and \"auth_request_params\" is set to e.g. \"claims=%7B%20%22userinfo%22%3A%20%7B%20%22email%22%3A%20%7B%22essential%22%3A%20true%7D%20%7D%20%7D\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
	
	# make sure the response from the userinfo endpoint contains the email claim
	find_in_logfile "${TEST_ID}" "check email claim" 150 "oidc_util_http_call: response=" "\"email\": \"diana@example.org\"" || return -1
}

function rp_request_uri_enc() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	
	echo " * "
	echo " * [server] prerequisite: .conf exists and \"request_object\" is set to e.g. \"{ \"crypto\": { \"crypt_alg\": \"A128KW\" } }"
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# check we created a request object that was encrypted 
	find_in_logfile "${TEST_ID}" "check encrypted request object" 200 "oidc_proto_create_request_uri: serialized request object JWT header" "\"alg\": \"A128KW\"" || return -1

	# check we sent request URI in the authorization request
	find_in_logfile "${TEST_ID}" "check request URI" 200 "oidc_util_hdr_table_set: Location:" "&request_uri=" || return -1

	# TODO: check resolving of request URI if on the same server
}

function rp_request_uri_sig_enc() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	
	echo " * "
	echo " * [server] prerequisite: .conf exists and \"request_object\" is set to e.g. \"{ \"crypto\": { \"sign_alg\": \"RS256\", \"crypt_alg\": \"A128KW\" } }"
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# check we created a request object that was encrypted 
	find_in_logfile "${TEST_ID}" "check encrypted request object" 200 "oidc_proto_create_request_uri: serialized request object JWT header" "\"alg\": \"RSA1_5\"" || return -1

	# check we sent request URI in the authorization request
	find_in_logfile "${TEST_ID}" "check request URI" 200 "oidc_util_hdr_table_set: Location:" "&request_uri=" || return -1
				
	# TODO: check resolving of request URI if on the same server
}

function rp_request_uri_unsigned() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"request_object\" is set to e.g. \"{ \"crypto\": { \"sign_alg\": \"none\" } }"
	echo " * "
	
	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# check we created a request object that was unsecured 
	find_in_logfile "${TEST_ID}" "check unsigned request object" 200 "oidc_proto_create_request_uri: serialized request object JWT header" "\"alg\":\"none\"" || return -1

	# check we sent request URI in the authorization request
	find_in_logfile "${TEST_ID}" "check request URI" 200 "oidc_util_hdr_table_set: Location:" "&request_uri=" || return -1

	# TODO: check resolving of request URI if on the same server
}

function rp_request_uri_sig() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	
	echo " * "
	echo " * [server] prerequisite: .conf exists and \"request_object\" is set to e.g. \"{ \"crypto\": { \"sign_alg\": \"HS256\" } }"
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# check we created a request object that was signed with the client secret
	find_in_logfile "${TEST_ID}" "check signed request object" 200 "oidc_proto_create_request_uri: serialized request object JWT header" "\"alg\": \"HS256\"" || return -1

	# check we sent request URI in the authorization request
	find_in_logfile "${TEST_ID}" "check request URI" 200 "oidc_util_hdr_table_set: Location:" "&request_uri=" || return -1

	# TODO: check resolving of request URI if on the same server
}

function rp_support_3rd_party_init_login() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	#https://localhost.pingidentity.nl/protected/?iss=https://rp.certification.openid.net:8080/rp-support_3rd_party_init_login/_/_/_/normal

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
		
	# check that the code authorization response handling is triggered
	find_in_logfile "${TEST_ID}" "check \"code\" response" 150 "oidc_proto_handle_authorization_response_code: enter"	 || return -1
}

function rp_scope_userinfo_claims() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	
	echo " * "
	echo " * [server] prerequisite: .conf exists and \"scope\" is set to \"openid email phone\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# make sure the headers contain the email claim
	find_in_logfile "${TEST_ID}" "check email claim in headers" 175 "oidc_util_hdr_table_set" "OIDC_CLAIM_email: diana@example.org" || return -1
	# make sure the headers contain the phone_number claim
	find_in_logfile "${TEST_ID}" "check phone claim in headers" 175 "oidc_util_hdr_table_set" "OIDC_CLAIM_phone_number: +46 90 7865000" || return -1
}

function rp_nonce_unless_code_flow() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"response_type\" is set to \"id_token\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# check that the nonce validates
	find_in_logfile "${TEST_ID}" "check nonce validation" 150 "oidc_proto_validate_nonce: nonce" "validated successfully" || return -1
}

function rp_nonce_invalid() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
				
	do_request_response ${RP_ID} ${TEST_ID} ${RESPONSE_MODE} || return -1
	
	# check that the nonce validation fails
	find_in_logfile "${TEST_ID}" "check nonce mismatch" 15 "oidc_proto_validate_nonce: the nonce value" "in the id_token did not match the one stored in the browser session" || return -1
}

function rp_token_endpoint_client_secret_basic() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"token_endpoint_auth\" is set to \"client_secret_basic\""
	echo " * "		

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# check that the token endpoint auth method is set to "client_secret_basic"
	find_in_logfile "${TEST_ID}" "check token endpoint auth method" 150 "oidc_proto_token_endpoint_request: token_endpoint_auth=client_secret_basic" || return -1

	# check that basic_auth is set to something other than "basic_auth=(null)"
	message "${TEST_ID}" "check basic auth" "-n"
	tail -n 150 ${LOG_FILE} | grep "oidc_util_http_call: url=${ISSUER}/token" | grep "grant_type=authorization_code" | grep -q "basic_auth=(null)" && { echo "ERROR: basic_auth found" && return -1; } || echo "OK"
	
	# check that the response from the token endpoint call is successful
	find_in_logfile "${TEST_ID}" "check token exchange response" 150 "oidc_util_http_call: response={" "\"id_token\": " || return -1
}

function rp_token_endpoint_client_secret_post() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"token_endpoint_auth\" is set to \"client_secret_post\""
	echo " * "		

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# check that the token endpoint auth method is set to "client_secret_post"
	find_in_logfile "${TEST_ID}" "check token endpoint auth method" 150 "oidc_proto_token_endpoint_request: token_endpoint_auth=client_secret_post" || return -1

	# check that the client_secret is passed 
	find_in_logfile "${TEST_ID}" "check post auth" 150 "oidc_util_http_call: url=${ISSUER}/token" "client_secret=" || return -1

	# check that the response from the token endpoint call is successful
	find_in_logfile "${TEST_ID}" "check token exchange response" 150 "oidc_util_http_call: response={" "\"id_token\": " || return -1
}

function  rp_token_endpoint_client_secret_jwt() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"token_endpoint_auth\" is set to \"client_secret_jwt\""
	echo " * "		

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# check that the token endpoint auth method is set to "client_secret_jwt"
	find_in_logfile "${TEST_ID}" "check token endpoint auth method" 150 "oidc_proto_token_endpoint_request: token_endpoint_auth=client_secret_jwt" || return -1

	# check that the client_assertion is passed 
	find_in_logfile "${TEST_ID}" "check client assertion auth" 150 "oidc_util_http_call: url=${ISSUER}/token" "client_assertion=" || return -1

	# check that the response from the token endpoint call is successful
	find_in_logfile "${TEST_ID}" "check token exchange response" 150 "oidc_util_http_call: response={" "\"id_token\": " || return -1
}

function  rp_token_endpoint_private_key_jwt() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"token_endpoint_auth\" is set to \"private_key_jwt\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# check that the token endpoint auth method is set to "private_key_jwt"
	find_in_logfile "${TEST_ID}" "check token endpoint auth method" 150 "oidc_proto_token_endpoint_request: token_endpoint_auth=private_key_jwt" || return -1

	# check that the client_assertion is passed 
	find_in_logfile "${TEST_ID}" "check client assertion auth" 150 "oidc_util_http_call: url=${ISSUER}/token" "client_assertion=" || return -1

	# check that the response from the token endpoint call is successful
	find_in_logfile "${TEST_ID}" "check token exchange response" 150 "oidc_util_http_call: response={" "\"id_token\": " || return -1
}

function rp_id_token_bad_sig_rs256() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	do_request_response ${RP_ID} ${TEST_ID} ${RESPONSE_MODE} || return -1

	find_in_logfile "${TEST_ID}" "check RS id_token" 30 "oidc_proto_parse_idtoken: successfully parsed" "\"alg\":\"RS256\"" || return -1
	find_in_logfile "${TEST_ID}" "check RS signature mismatch" 15 "oidc_proto_jwt_verify: JWT signature verification failed" "_cjose_jws_verify_sig_rs" || return -1
}

function rp_id_token_bad_sig_hs256() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	do_request_response ${RP_ID} ${TEST_ID} ${RESPONSE_MODE} || return -1

	find_in_logfile "${TEST_ID}" "check HS id_token" 30 "oidc_proto_parse_idtoken: successfully parsed" "\"alg\":\"HS256\"" || return -1
	find_in_logfile "${TEST_ID}" "check HS signature mismatch" 15 "oidc_proto_jwt_verify: JWT signature verification failed" "could not verify signature against any of the (1) provided keys" || return -1
}

function rp_id_token_sig_enc() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"id_token_encrypted_response_alg\" is set to e.g. \"RSA1_5\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	find_in_logfile "${TEST_ID}" "check encrypted id_token" 150 "oidc_proto_parse_idtoken: enter: id_token header" "\"alg\":\"RSA1_5\"" || return -1
	find_in_logfile "${TEST_ID}" "check decryption result" 150 "oidc_proto_parse_idtoken: successfully parsed (and possibly decrypted) JWT" || return -1
}

function rp_id_token_sig_enc_a128kw() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"id_token_encrypted_response_alg\" is set to e.g. \"A128KW\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	find_in_logfile "${TEST_ID}" "check encrypted id_token" 150 "oidc_proto_parse_idtoken: enter: id_token header" "\"alg\":\"A128KW\"" || return -1
	find_in_logfile "${TEST_ID}" "check decryption result" 150 "oidc_proto_parse_idtoken: successfully parsed (and possibly decrypted) JWT" || return -1
}

function rp_id_token_sig_rs256() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	
	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
		
	find_in_logfile "${TEST_ID}" "check RS id_token" 150 "oidc_proto_parse_idtoken: successfully parsed" "\"alg\":\"RS256\"" || return -1
}

function rp_id_token_sig_hs256() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	
	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
		
	find_in_logfile "${TEST_ID}" "check HS id_token" 150 "oidc_proto_parse_idtoken: successfully parsed" "\"alg\":\"HS256\"" || return -1
}

function rp_id_token_sig_es256() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
		
	find_in_logfile "${TEST_ID}" "check ES id_token" 150 "oidc_proto_parse_idtoken: successfully parsed" "\"alg\":\"ES256\"" || return -1
}

function rp_id_token_sig_none() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# make sure we were using the code flow
	find_in_logfile "${TEST_ID}" "check code flow" 150 "oidc_util_http_post_form: post data=\"grant_type=authorization_code&code=" || return -1
	# make sure the id_token has alg "none" set
	find_in_logfile "${TEST_ID}" "check alg none" 150 "oidc_proto_parse_idtoken: successfully parsed" "JWT with header={\"alg\":\"none\"}" || return -1
	# check that we finished id_token validation succesfully
	find_in_logfile "${TEST_ID}" "check valid id_token" 150 "oidc_proto_parse_idtoken: valid id_token for user" || return -1
}

function rp_id_token_bad_c_hash() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"response_type\" is set to \"code id_token token\""
	echo " * "

	do_request_response ${RP_ID} ${TEST_ID} ${RESPONSE_MODE} || return -1

	find_in_logfile "${TEST_ID}" "check c_hash mismatch" 15 "oidc_proto_validate_code: could not validate code against \"c_hash\"" || return -1
}

function rp_id_token_missing_c_hash() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"response_type\" is set to \"code id_token token\""
	echo " * "

	do_request_response ${RP_ID} ${TEST_ID} ${RESPONSE_MODE} || return -1

	find_in_logfile "${TEST_ID}" "check c_hash missing" 15 "oidc_proto_validate_hash_value" "no c_hash found in id_token" || return -1
}

function rp_id_token_bad_at_hash() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"response_type\" is set to \"code id_token token\""
	echo " * "

	do_request_response ${RP_ID} ${TEST_ID} ${RESPONSE_MODE} || return -1

	find_in_logfile "${TEST_ID}" "check at_hash mismatch" 15 "oidc_proto_validate_access_token: could not validate access token against \"at_hash\"" || return -1
}

function rp_id_token_missing_at_hash() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"response_type\" is set to \"code id_token token\""
	echo " * "

	do_request_response ${RP_ID} ${TEST_ID} ${RESPONSE_MODE} || return -1

	find_in_logfile "${TEST_ID}" "check at_hash missing" 15 "oidc_proto_validate_hash_value" "no at_hash found in id_token" || return -1
}

function rp_id_token_issuer_mismatch() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	do_request_response ${RP_ID} ${TEST_ID} ${RESPONSE_MODE} || return -1

	find_in_logfile "${TEST_ID}" "check issuer mismatch" 30 "oidc_proto_validate_jwt: requested issuer (${ISSUER}) does not match received \"iss\" value in id_token (https://example.org/)" || return -1
	find_in_logfile "${TEST_ID}" "check abort" 30 "oidc_proto_parse_idtoken: id_token payload could not be validated, aborting" || return -1
}

function rp_id_token_iat() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	do_request_response ${RP_ID} ${TEST_ID} ${RESPONSE_MODE} || return -1

	find_in_logfile "${TEST_ID}" "check missing iat" 30 "oidc_proto_validate_iat: JWT did not contain an \"iat\" number value" || return -1
	find_in_logfile "${TEST_ID}" "check abort" 30 "oidc_proto_parse_idtoken: id_token payload could not be validated, aborting" || return -1
}

function rp_id_token_bad_sig_es256() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	do_request_response ${RP_ID} ${TEST_ID} ${RESPONSE_MODE} || return -1

	find_in_logfile "${TEST_ID}" "check EC id_token" 30 "oidc_proto_parse_idtoken: successfully parsed" "\"alg\":\"ES256\"" || return -1
	find_in_logfile "${TEST_ID}" "check EC signature mismatch" 15 "oidc_proto_jwt_verify: JWT signature verification failed" "_cjose_jws_verify_sig_ec" || return -1
}

function rp_id_token_aud() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	do_request_response ${RP_ID} ${TEST_ID} ${RESPONSE_MODE} || return -1

	find_in_logfile "${TEST_ID}" "check aud mismatch" 15 "oidc_proto_validate_aud_and_azp: our configured client_id (" ") could not be found in the array of values for \"aud\" claim" || return -1
}

function rp_id_token_sub() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	do_request_response ${RP_ID} ${TEST_ID} ${RESPONSE_MODE} || return -1
	
	find_in_logfile "${TEST_ID}" "check missing sub" 30 "oidc_proto_validate_idtoken: id_token JSON payload did not contain the required-by-spec \"sub\" string value" || return -1
	find_in_logfile "${TEST_ID}" "check abort" 30 "oidc_proto_parse_idtoken: id_token payload could not be validated, aborting" || return -1
}

function rp_id_token_kid_absent_single_jwks() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	find_in_logfile "${TEST_ID}" "check missing kid" 150 "oidc_proto_get_key_from_jwks: search for kid \"(null)\"" || return -1
	#find_in_logfile "${TEST_ID}" "check abort" 30 "oidc_proto_parse_idtoken: id_token signature could not be validated, aborting" || return -1
	find_in_logfile "${TEST_ID}" "check single JWK" 150 "oidc_proto_get_keys_from_jwks_uri: returning 1 key(s)" || return -1
	find_in_logfile "${TEST_ID}" "check signature verification" 150 "oidc_proto_jwt_verify: JWT signature verification with algorithm \"RS256\" was successful" || return -1
}

function rp_id_token_kid_absent_multiple_jwks() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	#do_request_response ${RP_ID} ${TEST_ID} ${RESPONSE_MODE} || return -1

	#find_in_logfile "${TEST_ID}" "check missing JWK" 30 "oidc_proto_jwt_verify: JWT signature verification failed" "could not verify signature against any of the"
	#find_in_logfile "${TEST_ID}" "check abort" 30 "oidc_proto_parse_idtoken: id_token signature could not be validated, aborting"

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	find_in_logfile "${TEST_ID}" "check missing kid" 150 "oidc_proto_get_key_from_jwks: search for kid \"(null)\"" || return -1
	find_in_logfile "${TEST_ID}" "check multiple JWKs" 150 "oidc_proto_get_keys_from_jwks_uri: returning 2 key(s)" || return -1
	find_in_logfile "${TEST_ID}" "check signature verification" 150 "oidc_proto_jwt_verify: JWT signature verification with algorithm \"RS256\" was successful" || return -1
}

function rp_key_rotation_op_sign_key() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
	
	# make sure we tried to use keys from cache first and missed
	find_in_logfile "${TEST_ID}" "check JWKs cache miss" 150 "oidc_proto_get_keys_from_jwks_uri: could not find a key in the cached JSON Web Keys" || return -1
	# and we did a forced refresh
	find_in_logfile "${TEST_ID}" "check JWKs refresh" 150 "oidc_metadata_jwks_get: doing a forced refresh of the JWKs" || return -1
	# then we found a match
	find_in_logfile "${TEST_ID}" "check matching kid" 150 "oidc_proto_get_key_from_jwks: found matching kid:" "rotated_rsa" || return -1
	# and it verified succesfully
	find_in_logfile "${TEST_ID}" "check verification" 150 "oidc_proto_jwt_verify: JWT signature verification" "was successful" || return -1
}

function rp_key_rotation_op_sign_key_native() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
	
	# make sure we tried to use keys from cache first and missed
	#find_in_logfile "${TEST_ID}" "check JWKs cache miss" 150 "oidc_proto_get_keys_from_jwks_uri: could not find a key in the cached JSON Web Keys" || return -1
	# and we did a forced refresh
	#find_in_logfile "${TEST_ID}" "check JWKs refresh" 150 "oidc_metadata_jwks_get: doing a forced refresh of the JWKs" || return -1
	# then we found a match
	find_in_logfile "${TEST_ID}" "check matching kid" 150 "oidc_proto_get_key_from_jwks: found matching kid:" "rotated_rsa" || return -1
	# and it verified succesfully
	find_in_logfile "${TEST_ID}" "check verification" 150 "oidc_proto_jwt_verify: JWT signature verification" "was successful" || return -1
}

function rp_key_rotation_op_enc_key() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	
	echo " * "
	echo " * [server] prerequisite: .conf exists and \"request_object\" is set to e.g. \"{ \"crypto\": { \"crypt_alg\": \"RSA1_5\" } }"
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
	
	# check we created a request object that was encrypted 
	find_in_logfile "${TEST_ID}" "check encrypted request object" 200 "oidc_proto_create_request_uri: serialized request object JWT header" "\"alg\": \"RSA1_5\"" || return -1

	# check we sent request URI in the authorization request
	find_in_logfile "${TEST_ID}" "check request URI" 200 "oidc_util_hdr_table_set: Location:" "&request_uri=" || return -1

	# check that we refreshed keys
	find_in_logfile "${TEST_ID}" "check JWKS refresh" 200 "oidc_metadata_jwks_get: doing a forced refresh of the JWKs from URI" || return -1
	
	# get the kid we used for encryption
	KIDA=`tail -n 200 ${LOG_FILE} | grep  "oidc_proto_create_request_uri: serialized request object JWT header" | cut -d{ -f2 | cut -d: -f4 | cut -d"\"" -f2`
	message "${TEST_ID}" "kid #1 ${KIDA}"
		
	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
	
	# check we created a request object that was encrypted 
	find_in_logfile "${TEST_ID}" "check encrypted request object" 200 "oidc_proto_create_request_uri: serialized request object JWT header" "\"alg\": \"RSA1_5\"" || return -1

	# check we sent request URI in the authorization request
	find_in_logfile "${TEST_ID}" "check request URI" 200 "oidc_util_hdr_table_set: Location:" "&request_uri=" || return -1

	# check that we refreshed keys
	find_in_logfile "${TEST_ID}" "check JWKS refresh" 200 "oidc_metadata_jwks_get: doing a forced refresh of the JWKs from URI" || return -1
	
	# get the kid we used for encryption
	KIDB=`tail -n 200 ${LOG_FILE} | grep  "oidc_proto_create_request_uri: serialized request object JWT header" | cut -d{ -f2 | cut -d: -f4 | cut -d"\"" -f2`
	message "${TEST_ID}" "kid #2 ${KIDB}"
				
	# check that the kid's from the two tests differ
	message "${TEST_ID}" "check different kids" "-n"
	if [ "${KIDA}" != "${KIDB}" ] ; then echo "OK"; else echo "ERROR" && return -1; fi
}

function rp_claims_aggregated() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	
	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# check that aggregated claims were returned and processed
	find_in_logfile "${TEST_ID}" "check eye_color aggregated claim" 150 "oidc_proto_resolve_composite_claims: processing:" "eye_color: src1" || return -1
	find_in_logfile "${TEST_ID}" "check shoe_size aggregated claim" 150 "oidc_proto_resolve_composite_claims: processing:" "shoe_size: src1" || return -1
	
	# check that aggregated claims were flattened in to headers
	find_in_logfile "${TEST_ID}" "check flattened eye_color claim" 75 "oidc_util_hdr_table_set" "OIDC_CLAIM_eye_color: blue" || return -1
	find_in_logfile "${TEST_ID}" "check flattened shoe_size claim" 75 "oidc_util_hdr_table_set" "OIDC_CLAIM_shoe_size: 8" || return -1
}

function rp_claims_distributed() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1

	# check that distributed claim was returned and processed
	find_in_logfile "${TEST_ID}" "check age distributed claim" 150 "oidc_proto_resolve_composite_claims: processing:" "age: src1" || return -1

	# check that distributed claim was flattened in to a header
	find_in_logfile "${TEST_ID}" "check flattened age claim" 75 "oidc_util_hdr_table_set" "OIDC_CLAIM_age: 30" || return -1
}

function rp_userinfo_bearer_header() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
	
	# check userinfo endpoint access
	find_in_logfile "${TEST_ID}" "check userinfo endpoint access" 150 "oidc_proto_resolve_userinfo: enter, endpoint=${ISSUER}" || return -1

	# find access token	
	AT=`tail -n 150 ${LOG_FILE} | grep "oidc_proto_resolve_userinfo: enter, endpoint=${ISSUER}/userinfo, access_token=" | cut -d"," -f3 | cut -d"=" -f2-`

	# check bearer token usage in header
	find_in_logfile "${TEST_ID}" "check bearer token header" 150 "oidc_util_http_call: url=${ISSUER}/userinfo" "bearer_token=${AT}" || return -1

	# check valid JSON result
	find_in_logfile "${TEST_ID}" "check valid JSON result" 150 "oidc_util_http_call: response={" "}" || return -1
	
	# check no error
	find_in_logfile "${TEST_ID}" "check no error" 150 "oidc_proto_resolve_userinfo: id_token_sub=" "user_info_sub=" || return -1
}

function rp_userinfo_bearer_body() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3	
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
	
	# check userinfo endpoint access
	find_in_logfile "${TEST_ID}" "check userinfo endpoint access" 150 "oidc_proto_resolve_userinfo: enter, endpoint=${ISSUER}" || return -1

	# check bearer token usage in POST body
	find_in_logfile "${TEST_ID}" "check bearer token POST param" 150 "oidc_util_http_post_form: post" "access_token=" || return -1
	
	# check valid JSON result
	find_in_logfile "${TEST_ID}" "check valid JSON result" 150 "oidc_util_http_call: response={" "}" || return -1
	
	# check no error
	find_in_logfile "${TEST_ID}" "check no error" 150 "oidc_proto_resolve_userinfo: id_token_sub=" "user_info_sub=" || return -1
}

function rp_userinfo_sig() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"userinfo_signed_response_alg\" is set to e.g. \"RS256\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
	
	# check we got a signed JWT in the response from the userinfo endpoint
	find_in_logfile "${TEST_ID}" "check JWT response" 150 "oidc_user_info_response_validate: JWT header=" "\"alg\":\"RS256\"" || return -1
		
	# check the JWT verified successfully
	find_in_logfile "${TEST_ID}" "check JWT verification" 150 "oidc_user_info_response_validate: successfully verified signed JWT returned from userinfo endpoint" || return -1
}

function rp_userinfo_sig_enc() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"userinfo_signed_response_alg\" is set to e.g. \"RS256\""
	echo " * [server] prerequisite: .conf exists and \"userinfo_encrypted_response_alg\" is set to e.g. \"A128KW\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
	
	# check we got a JWE in the response from the userinfo endpoint
	find_in_logfile "${TEST_ID}" "check JWE response" 150 "oidc_user_info_response_validate: JWT header=" "\"alg\":\"A128KW\"" || return -1
	# check the JWE was decrypted successfully
	find_in_logfile "${TEST_ID}" "check JWE decryption" 150 "oidc_user_info_response_validate: successfully decrypted JWE returned from userinfo endpoint" || return -1
	# check we got a signed JWT in the JWE
	find_in_logfile "${TEST_ID}" "check JWT in JWE response" 150 "oidc_user_info_response_validate: successfully parsed JWT" "\"alg\":\"RS256\"" || return -1
	# check the JWT verified successfully
	find_in_logfile "${TEST_ID}" "check JWT verification" 150 "oidc_user_info_response_validate: successfully verified signed JWT returned from userinfo endpoint" || return -1
}

function rp_userinfo_enc() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"userinfo_encrypted_response_alg\" is set to e.g. \"RSA1_5\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
	
	# check we got a JWE in the response from the userinfo endpoint
	find_in_logfile "${TEST_ID}" "check JWE response" 150 "oidc_user_info_response_validate: JWT header=" "\"alg\":\"RSA1_5\"" || return -1
	# check the JWE was decrypted successfully
	find_in_logfile "${TEST_ID}" "check JWE decryption" 150 "oidc_user_info_response_validate: successfully decrypted JWE returned from userinfo endpoint" || return -1
}

function rp_userinfo_bad_sub_claim() {
	local RP_ID=$1
	local TEST_ID=$2
	local RESPONSE_MODE=$3

	# test a regular flow up until successful authenticated application access
	regular_flow "${RP_ID}" "${TEST_ID}" "${RESPONSE_MODE}" || return -1
	
	# check that the sub claim did not match
	find_in_logfile "${TEST_ID}" "check sub mismatch" 150 "oidc_proto_resolve_userinfo: \"sub\" claim" "returned from userinfo endpoint does not match the one in the id_token" || return -1
	# check that the claims from the userinfo endpoint were discarded
	find_in_logfile "${TEST_ID}" "check claims discarded" 150 "oidc_retrieve_claims_from_userinfo_endpoint" "failed, nothing will be stored in the session" || return -1
}

function test_name_to_function() {
	echo ${1} | tr "\-+" "\_\_"
}

function execute_test() {
	local PROFILE="${1}"	
	local TEST_ID="${2}"
	local NR="${3}"
	local TOTAL="${4}"
	local RESPONSE_TYPE="${5}"
	
	local RP_ID="${RP_NAME}-${PROFILE}" 

	echo ""
	printf " # [%s - %s/%s]: %s [%s]\n" "${PROFILE}" $((NR+1)) ${TOTAL} "${TEST_ID}" "${RESPONSE_TYPE}"
	echo ""
	eval `test_name_to_function "${TEST_ID}"` "${RP_ID}" "${TEST_ID}" "${RESPONSE_TYPE}"
}

function execute_profile() {
	PROFILE="$1"
	RESPONSE_TYPE="$2"
	TESTS="$3"
	mkdir -p "profile/${PROFILE}"
	TOTAL=`echo ${TESTS} | wc -w`
	NR=0
	for TEST_ID in $TESTS; do
		execute_test "${PROFILE}" "${TEST_ID}" "${NR}" "${TOTAL}" "${RESPONSE_TYPE}" \
			| tee "profile/${PROFILE}/${TEST_ID}.log" ; \
			test ${PIPESTATUS[0]} -eq 0 \
			|| exit
		NR=$((NR+1))
	done
	echo ""
	printf " # SUCCESS: [%s] profile coverage %.2f%%\n" "${PROFILE}" `echo "100 * ${NR} / ${TOTAL}" | bc -l`
	echo ""	
	test  ${NR} -eq ${TOTAL}
}

if [ "$1" == "clean" ] ; then
	rm -rf profile
	cd metadata
	for profile in `find * -maxdepth 0 -type d` ; do
		rm -f ${profile}/*.provider ${profile}/*.client
	done
	exit
fi

if [ "$1" == "all" ] ; then
	TOTAL=`echo ${TESTS} ${TESTS_UNSUPPORTED} ${TEST_ERR} | wc -w`
	NR=0
	for TEST_ID in $TESTS; do
		execute_test "all" "${TEST_ID}" "${NR}" "${TOTAL}" query
		NR=$((NR+1))
	done
	echo ""
	printf " # SUCCESS: coverage %.2f%%\n" `echo "100 * ${NR} / ${TOTAL}" | bc -l`
	echo ""		
elif [ "$1" == "code" ] ; then
	execute_profile "$1" query "${TESTS_CODE}"
elif [ "$1" == "id_token" ] ; then
	execute_profile "$1" fragment "${TESTS_IDTOKEN}"
elif [ "$1" == "id_token+token" ] ; then
	execute_profile "$1" fragment "${TESTS_IDTOKEN_TOKEN}"
elif [ "$1" == "code+id_token" ] ; then
	execute_profile "$1" fragment "${TESTS_CODE_IDTOKEN}"
elif [ "$1" == "code+token" ] ; then
	execute_profile "$1" fragment "${TESTS_CODE_TOKEN}"
elif [ "$1" == "code+id_token+token" ] ; then
	execute_profile "$1" fragment "${TESTS_CODE_IDTOKEN_TOKEN}"
elif [ "$1" == "config" ] ; then
	execute_profile "$1" query "${TESTS_CONFIG}"
elif [ "$1" == "dynamic" ] ; then
	execute_profile "$1" query "${TESTS_DYNAMIC}"
else				
	execute_test "test" "${1}" 0 1 "${2}"
fi
