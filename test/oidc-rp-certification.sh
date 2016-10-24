#!/bin/bash

###########################################################################
# Copyright (C) 2016 Ping Identity Corporation
#
# Script used to do automated OpenID Connect Relying Party Certification
# Testing for the mod_auth_openidc OIDC RP implementation for Apache HTTPd.
#
# @Version: 2.0.1, mod_auth_openidc >= v2.0.1rc6
# 
# @Author: Hans Zandbelt - hzandbelt@pingidentity.com
#
###########################################################################

REDIRECT_URI="<THE-REDIRECT_URI-OF-YOUR-APACHE-MOD_AUTH_OPENIDC-INSTANCE>"
TARGET_URL="<YOUR-APPLICATION-URL-PROTECTED-BY-MOD_AUTH_OPENIDC>"
RP_ID="<YOUR-RP-TEST-CLIENT-IDENTIFIER>"
LOG_FILE="<YOUR-APACHE-ERROR-LOGFILE-WITH-DEBUG-MESSAGES>"

RP_TEST_URL="https://rp.certification.openid.net:8080"
COOKIE_JAR="/tmp/cookie.jar"

FLAGS="-s -k -b ${COOKIE_JAR} -c ${COOKIE_JAR}"

SETENV="$(dirname "$0")/setenv.sh"
if [[ -x "${SETENV}" ]]; then
	source "${SETENV}"
fi

TESTS="
	rp_discovery_issuer_not_matching_config
	rp_discovery_jwks_uri_keys
	rp_discovery_openid_configuration
	rp_discovery_webfinger_acct
	rp_discovery_webfinger_http_href
	rp_discovery_webfinger_unknown_member
	rp_discovery_webfinger_url
	rp_registration_dynamic
	rp_response_type_code
	rp_token_endpoint_client_secret_basic
	rp_token_endpoint_client_secret_post
	rp_token_endpoint_client_secret_jwt
	rp_token_endpoint_private_key_jwt
	rp_id_token_aud
	rp_id_token_bad_sig_es256
	rp_id_token_bad_sig_hs256
	rp_id_token_bad_sig_rs256
	rp_id_token_iat
	rp_id_token_issuer_mismatch
	rp_id_token_kid_absent_multiple_jwks
	rp_id_token_kid_absent_single_jwks
	rp_id_token_sig_enc
	rp_id_token_sig_none
	rp_id_token_sub
	rp_claims_request_id_token
	rp_claims_request_userinfo
	rp_scope_userinfo_claims
	rp_key_rotation_op_sign_key
	rp_userinfo_bad_sub_claim
	rp_userinfo_bearer_header
	rp_userinfo_bearer_body
	rp_userinfo_sig
	rp_userinfo_enc
	rp_userinfo_sig_enc	
	rp_request_uri_sig
	rp_request_uri_unsigned
	rp_request_uri_enc
	rp_request_uri_sig_enc
	rp_key_rotation_op_enc_key
"

if [ -z $1 ] ; then
	echo
	printf "Usage: ${0}\n\tall${TESTS}"
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
		tail -n ${NUMBER} ${LOG_FILE} | grep -q "${MATCH}" && echo "OK" || { printf "ERROR:\n could not find \"%s\" in logfile\n" "${MATCH}" && exit; }
	else
		tail -n ${NUMBER} ${LOG_FILE} | grep "${MATCH}" | grep -q "${MATCH2}" && echo "OK" || { printf "ERROR:\n could not find \"%s\" and \"%s\" in logfile\n" "${MATCH}" "${MATCH2}" && exit; }
	fi
}

# create CSRF token to be supplied on subsequent call
function create_csrf() {
	local TEST_ID=$1

	message ${TEST_ID} "initiate CSRF" "-n"
	local RESPONSE=`echo ${FLAGS} -j | xargs curl ${TARGET_URL}`
	if [ $? -ne 0 ] ; then
		echo "ERROR"
		exit
	fi
	CSRF=`echo "${RESPONSE}" | grep hidden | grep x_csrf | cut -d"\"" -f6`
	if [ $? -ne 0 ] ; then
		echo "ERROR"
		exit
	else
		echo "OK"
	fi
}

# call the RP endpoint (=mod_auth_openidc's redirect URI) to kick off discovery and/or SSO
function initiate_sso() {
	local TEST_ID=$1
	local ISSUER=$2
	local RESULT_PARAM=$3

	create_csrf "${TEST_ID}"

	message "${TEST_ID}" "initiate SSO" "-n"
	RESULT=`echo ${FLAGS} -i | xargs curl -G --data-urlencode "iss=${ISSUER}" --data-urlencode "target_link_uri=${TARGET_URL}" --data-urlencode "x_csrf=${CSRF}" ${REDIRECT_URI}`
	if [ $? -ne 0 ] ; then
		echo "ERROR"
		exit
	fi

	if [ "${RESULT_PARAM}" != "nogrep" ] ; then
		RESULT=`echo "${RESULT}" | grep_location_header_value`
		if [ $? -ne 0 ] ; then
			echo "ERROR"
			exit
		fi		
	fi

	if [ -z "${RESULT_PARAM}" ] ; then
		echo "OK"
	elif [ "${RESULT_PARAM}" == "authorization" ] ; then
		echo "${RESULT}" | grep -q "${RP_TEST_URL}/${RP_ID}/${TEST_ID}/authorization" && echo "OK" || { echo "ERROR: no authentication request found in redirect" && exit; }
	fi
	# else it should be "nogrep" or "return"
}

function grep_location_header_value_result() {
	if [ $? -ne 0 ] ; then
		echo "ERROR: result is: \"${RESULT}\""
		exit
	fi
	if `echo "${RESULT}" | head -1 | grep -q "HTTP/1.1 4"` ; then
		echo "ERROR: result is:\n${RESULT}"
		exit
	fi
	RESULT=`echo "${RESULT}" | grep_location_header_value`
	if [ $? -ne 0 ] ; then
		echo "ERROR: could not parse Location header from: \"${RESULT}\""
		exit
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
		
	message ${TEST_ID} "return authentication response to RP" "-n"
	RESULT=`echo ${FLAGS} -i | xargs curl "${RESPONSE}"`
	grep_location_header_value_result
}

# access the original URL that is passed in $2 (after authentication has succeeded)
function application_access() {
	local TEST_ID=$1
	local RETURN=$2

	message ${TEST_ID} "access application as authenticated user" "-n"
	RESULT=`echo ${FLAGS} | xargs curl "${RETURN}"`
	MATCH="\[OIDC_CLAIM_sub\]"
	echo "${RESULT}" | grep -q "${MATCH}" && echo "OK" || { printf "ERROR:\n could not find \"%s\" in client HTML output:\n%s\n" "${MATCH}" "${RESULT}" && exit; }
}

# go through a regular flow from discovery to authenticated application access
function regular_flow() {
	local TEST_ID=$1
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	initiate_sso ${TEST_ID} ${ISSUER}
	send_authentication_request ${TEST_ID} ${RESULT}
	send_authentication_response ${TEST_ID} ${RESULT}
	application_access ${TEST_ID} ${RESULT}
}

################################################
# the RP certification tests, one per function #
################################################

function rp_discovery_issuer_not_matching_config() {
	local TEST_ID="rp-discovery-issuer-not-matching-config"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	initiate_sso "${TEST_ID}" "${ISSUER}" "nogrep"
	MATCH="Could not find valid provider metadata"
	echo "${RESULT}" | grep -q "${MATCH}" && echo "OK" || { printf "ERROR:\n could not find \"%s\" in client HTML output:\n%s\n" "${MATCH}" "${RESULT}" && exit; }

	# make sure that we've got the right error message in the error log
	WRONG_ISSUER="https://example.com"
	find_in_logfile "${TEST_ID}" "check issuer mismatch error message" 15 "requested issuer (${ISSUER}) does not match the \"issuer\" value in the provider metadata file: ${WRONG_ISSUER}"
}

function rp_discovery_jwks_uri_keys() {
	local TEST_ID="rp-discovery-jwks_uri-keys"
	
	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"

	# make sure that we've validated and id_token correctly with the jwks discovered on the jwks_uri
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"
	find_in_logfile "${TEST_ID}" "check id_token parse result" 125 "oidc_proto_parse_idtoken: successfully parsed" "\"iss\": \"${ISSUER}\""
	find_in_logfile "${TEST_ID}" "check JWK retrieval by \"kid\"" 125 "oidc_proto_get_key_from_jwks: found matching kid:"
	find_in_logfile "${TEST_ID}" "check id_token verification" 125 "oidc_proto_jwt_verify: JWT signature verification with algorithm \"RS256\" was successful"
}

function rp_discovery_openid_configuration() {
	local TEST_ID="rp-discovery-openid-configuration"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	# check that the authentication request is initiated to the discovered authorization endpoint
	initiate_sso "${TEST_ID}" "${ISSUER}" "authorization"

	# check that the registration is initiated to the discovered endpoint: ${RP_ID}/${TEST_ID}/registration"
	# TODO: can only do this if the .provider file was cleaned up beforehand
	#find_in_logfile "${TEST_ID}" "check registration request" 75 "oidc_util_http_get: get URL=\"${URL}\""
}

function rp_discovery_webfinger_acct() {
	local TEST_ID="rp-discovery-webfinger-acct"
	local DOMAIN=`echo ${RP_TEST_URL} | cut -d"/" -f3`
	local ACCT="${RP_ID}.${TEST_ID}@${DOMAIN}"

	initiate_sso ${TEST_ID} ${ACCT} "return"
	
	# check that the authentication request contains a login_hint parameter set to the acct: value
	echo ${RESULT} | grep -q "&login_hint=${RP_ID}" && echo "OK" || echo "ERROR"

	# check that the webfinger request contains acct:"
	URL="${RP_TEST_URL}/.well-known/webfinger?resource=acct%3A${RP_ID}.${TEST_ID}%40rp.certification.openid.net%3A8080&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"
	find_in_logfile "${TEST_ID}" "check webfinger request" 75 "oidc_util_http_get: get URL=\"${URL}\""
	# check that the webfinger request contains the right issuer:"
	find_in_logfile "${TEST_ID}" "check webfinger issuer result" 75 "oidc_proto_webfinger_discovery: returning issuer \"https://rp.certification.openid.net:8080/mod_auth_openidc/rp-discovery-webfinger-acct\" for resource \"acct:${ACCT}\" after doing successful webfinger-based discovery"
}

function rp_discovery_webfinger_http_href() {
	local TEST_ID="rp-discovery-webfinger-http-href"
	local DOMAIN=`echo ${RP_TEST_URL} | cut -d"/" -f3`
	local ACCT="${RP_ID}.${TEST_ID}@${DOMAIN}"

	# check that the authentication request is initiated to the discovered authorization endpoint
	initiate_sso "${TEST_ID}" "${ACCT}" "nogrep"
	
	MATCH="Could not resolve the provided account name to an OpenID Connect provider"
	echo "${RESULT}" | grep -q "${MATCH}" && echo "OK" || { printf "ERROR:\n could not find \"%s\" in client HTML output:\n%s\n" "${MATCH}" "${RESULT}" && exit; }

	# check that the module choked on the plain HTTP href value
	find_in_logfile "${TEST_ID}" "check webfinger response" 50 "oidc_proto_webfinger_discovery: response JSON object contains an \"href\" value that is not a valid \"https\" URL"
}

function rp_discovery_webfinger_unknown_member() {
	local TEST_ID="rp-discovery-webfinger-unknown-member"
	local DOMAIN=`echo ${RP_TEST_URL} | cut -d"/" -f3`
	local ACCT="${RP_ID}.${TEST_ID}@${DOMAIN}"

	# check that the authentication request is initiated to the discovered authorization endpoint
	initiate_sso "${TEST_ID}" "${ACCT}" "authorization"

	# check that the webfinger request contains acct:
	URL="${RP_TEST_URL}/.well-known/webfinger?resource=acct%3A${RP_ID}.${TEST_ID}%40rp.certification.openid.net%3A8080&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"
	find_in_logfile "${TEST_ID}" "check webfinger request" 75 "oidc_util_http_get: get URL=\"${URL}\""
	# check that the response contains \"dummy\": \"foobar\""
	find_in_logfile "${TEST_ID}" "check webfinger response" 75 "oidc_util_http_call: response=" "\"dummy\": \"foobar\""
}

function rp_discovery_webfinger_url() {
	local TEST_ID="rp-discovery-webfinger-url"
	local USER_INPUT="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	create_csrf "${TEST_ID}"

	message "${TEST_ID}" "initiate URL based Discovery" "-n"
	RESULT=`echo ${FLAGS} -i | xargs curl -G --data-urlencode "disc_user=${USER_INPUT}" --data-urlencode "target_link_uri=${TARGET_URL}" --data-urlencode "x_csrf=${CSRF}" ${REDIRECT_URI}`
	if [ $? -ne 0 ] ; then
		echo "ERROR"
		exit
	fi
	
	# check that the authentication request contains a login_hint parameter set to the URL value
	echo ${RESULT} | grep -q "&login_hint=" && echo "OK" || { printf "ERROR: could not find \"login_hint=\" in authorization request\n" && exit; }

	# check that the webfinger request contains the URL"
	URL="${RP_TEST_URL}/.well-known/webfinger?resource=https%3A%2F%2Frp.certification.openid.net%3A8080%2F${RP_ID}%2F${TEST_ID}&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"
	find_in_logfile "${TEST_ID}" "check webfinger request" 75 "oidc_util_http_get: get URL=\"${URL}\""
	# check that the webfinger request contains the right issuer:"
	find_in_logfile "${TEST_ID}" "check webfinger issuer result" 75 "oidc_proto_webfinger_discovery: returning issuer \"https://rp.certification.openid.net:8080/mod_auth_openidc/rp-discovery-webfinger-url\" for resource \"${USER_INPUT}\" after doing successful webfinger-based discovery"
}

function rp_registration_dynamic() {
	local TEST_ID="rp-registration-dynamic"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	# check that the authentication request is initiated to the discovered authorization endpoint
	initiate_sso "${TEST_ID}" "${ISSUER}" "authorization"

	# TODO: only when .client file is cleaned up
	# check that the registration is initiated and a successful client registration response is returned"
}

function rp_response_type_code() {
	local TEST_ID="rp-response_type-code"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"response_type\" is set to \"code\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"
		
	# check that the code is returned by the OP to the redirect URI"
	find_in_logfile "${TEST_ID}" "check response type" 150 "oidc_check_user_id: incoming request:" "&code="	
}

function rp_token_endpoint_client_secret_basic() {
	local TEST_ID="rp-token_endpoint-client_secret_basic"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"token_endpoint_auth\" is set to \"client_secret_basic\""
	echo " * "		

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"

	# check that the token endpoint auth method is set to "client_secret_basic"
	find_in_logfile "${TEST_ID}" "check token endpoint auth method" 125 "oidc_proto_token_endpoint_request: token_endpoint_auth=client_secret_basic"

	# check that basic_auth is set to something other than "basic_auth=(null)"
	message "${TEST_ID}" "check basic auth" "-n"
	tail -n 125 ${LOG_FILE} | grep "oidc_util_http_call: url=${ISSUER}/token" | grep "grant_type=authorization_code" | grep -q "basic_auth=(null)" && { echo "ERROR: basic_auth found" && exit; } || echo "OK"
	
	# check that the response from the token endpoint call is successful
	find_in_logfile "${TEST_ID}" "check token exchange response" 125 "oidc_util_http_call: response={" "\"id_token\": "
}

function rp_token_endpoint_client_secret_post() {
	local TEST_ID="rp-token_endpoint-client_secret_post"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"token_endpoint_auth\" is set to \"client_secret_post\""
	echo " * "		

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"

	# check that the token endpoint auth method is set to "client_secret_post"
	find_in_logfile "${TEST_ID}" "check token endpoint auth method" 125 "oidc_proto_token_endpoint_request: token_endpoint_auth=client_secret_post"

	# check that the client_secret is passed 
	find_in_logfile "${TEST_ID}" "check post auth" 125 "oidc_util_http_call: url=${ISSUER}/token" "client_secret="

	# check that the response from the token endpoint call is successful
	find_in_logfile "${TEST_ID}" "check token exchange response" 125 "oidc_util_http_call: response={" "\"id_token\": "
}

function  rp_token_endpoint_client_secret_jwt() {
	local TEST_ID="rp-token_endpoint-client_secret_jwt"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"token_endpoint_auth\" is set to \"client_secret_jwt\""
	echo " * "		

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"

	# check that the token endpoint auth method is set to "client_secret_jwt"
	find_in_logfile "${TEST_ID}" "check token endpoint auth method" 125 "oidc_proto_token_endpoint_request: token_endpoint_auth=client_secret_jwt"

	# check that the client_assertion is passed 
	find_in_logfile "${TEST_ID}" "check client assertion auth" 125 "oidc_util_http_call: url=${ISSUER}/token" "client_assertion="

	# check that the response from the token endpoint call is successful
	find_in_logfile "${TEST_ID}" "check token exchange response" 125 "oidc_util_http_call: response={" "\"id_token\": "		
}

function  rp_token_endpoint_private_key_jwt() {
	local TEST_ID="rp-token_endpoint-private_key_jwt"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"token_endpoint_auth\" is set to \"private_key_jwt\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"

	# check that the token endpoint auth method is set to "private_key_jwt"
	find_in_logfile "${TEST_ID}" "check token endpoint auth method" 125 "oidc_proto_token_endpoint_request: token_endpoint_auth=private_key_jwt"

	# check that the client_assertion is passed 
	find_in_logfile "${TEST_ID}" "check client assertion auth" 125 "oidc_util_http_call: url=${ISSUER}/token" "client_assertion="

	# check that the response from the token endpoint call is successful
	find_in_logfile "${TEST_ID}" "check token exchange response" 125 "oidc_util_http_call: response={" "\"id_token\": "
}

function rp_id_token_aud() {
	local TEST_ID="rp-id_token-aud"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	initiate_sso ${TEST_ID} ${ISSUER}
	send_authentication_request ${TEST_ID} ${RESULT}
	send_authentication_response ${TEST_ID} ${RESULT}
		
	find_in_logfile "${TEST_ID}" "check aud mismatch" 15 "oidc_proto_validate_aud_and_azp: our configured client_id (" ") could not be found in the array of values for \"aud\" claim"
}

function rp_id_token_bad_sig_es256() {
	local TEST_ID="rp-id_token-bad-sig-es256"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"
		
	initiate_sso ${TEST_ID} ${ISSUER}
	send_authentication_request ${TEST_ID} ${RESULT}
	send_authentication_response ${TEST_ID} ${RESULT}

	find_in_logfile "${TEST_ID}" "check EC id_token" 30 "oidc_proto_parse_idtoken: successfully parsed" "\"alg\":\"ES256\""
	find_in_logfile "${TEST_ID}" "check EC signature mismatch" 15 "oidc_proto_jwt_verify: JWT signature verification failed" "_cjose_jws_verify_sig_ec"
}

function rp_id_token_bad_sig_hs256() {
	local TEST_ID="rp-id_token-bad-sig-hs256"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	initiate_sso ${TEST_ID} ${ISSUER}
	send_authentication_request ${TEST_ID} ${RESULT}
	send_authentication_response ${TEST_ID} ${RESULT}

	find_in_logfile "${TEST_ID}" "check HS id_token" 30 "oidc_proto_parse_idtoken: successfully parsed" "\"alg\":\"HS256\""
	find_in_logfile "${TEST_ID}" "check HS signature mismatch" 15 "oidc_proto_jwt_verify: JWT signature verification failed" "could not verify signature against any of the (1) provided keys"
}

function rp_id_token_bad_sig_rs256() {
	local TEST_ID="rp-id_token-bad-sig-rs256"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	initiate_sso ${TEST_ID} ${ISSUER}
	send_authentication_request ${TEST_ID} ${RESULT}
	send_authentication_response ${TEST_ID} ${RESULT}

	find_in_logfile "${TEST_ID}" "check RS id_token" 30 "oidc_proto_parse_idtoken: successfully parsed" "\"alg\":\"RS256\""
	find_in_logfile "${TEST_ID}" "check RS signature mismatch" 15 "oidc_proto_jwt_verify: JWT signature verification failed" "_cjose_jws_verify_sig_rs"
}

function rp_id_token_iat() {
	local TEST_ID="rp-id_token-iat"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	initiate_sso ${TEST_ID} ${ISSUER}
	send_authentication_request ${TEST_ID} ${RESULT}
	send_authentication_response ${TEST_ID} ${RESULT}

	find_in_logfile "${TEST_ID}" "check missing iat" 30 "oidc_proto_validate_iat: JWT did not contain an \"iat\" number value"
	find_in_logfile "${TEST_ID}" "check abort" 30 "oidc_proto_parse_idtoken: id_token payload could not be validated, aborting"
}

function rp_id_token_issuer_mismatch() {
	local TEST_ID="rp-id_token-issuer-mismatch"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	initiate_sso ${TEST_ID} ${ISSUER}
	send_authentication_request ${TEST_ID} ${RESULT}
	send_authentication_response ${TEST_ID} ${RESULT}

	find_in_logfile "${TEST_ID}" "check issuer mismatch" 30 "oidc_proto_validate_jwt: requested issuer (${ISSUER}) does not match received \"iss\" value in id_token (https://example.org/)"
	find_in_logfile "${TEST_ID}" "check abort" 30 "oidc_proto_parse_idtoken: id_token payload could not be validated, aborting"
}

function rp_id_token_kid_absent_multiple_jwks() {
	local TEST_ID="rp-id_token-kid-absent-multiple-jwks"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	initiate_sso ${TEST_ID} ${ISSUER}
	send_authentication_request ${TEST_ID} ${RESULT}
	send_authentication_response ${TEST_ID} ${RESULT}

	find_in_logfile "${TEST_ID}" "check missing JWK" 30 "oidc_proto_jwt_verify: JWT signature verification failed" "could not verify signature against any of the"
	find_in_logfile "${TEST_ID}" "check abort" 30 "oidc_proto_parse_idtoken: id_token signature could not be validated, aborting"

	# test a regular flow up until successful authenticated application access
	#regular_flow "${TEST_ID}"
}

function rp_id_token_kid_absent_single_jwks() {
	local TEST_ID="rp-id_token-kid-absent-single-jwks"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"

	find_in_logfile "${TEST_ID}" "check missing kid" 150 "oidc_proto_get_key_from_jwks: search for kid \"(null)\""
	#find_in_logfile "${TEST_ID}" "check abort" 30 "oidc_proto_parse_idtoken: id_token signature could not be validated, aborting"
	find_in_logfile "${TEST_ID}" "check signature verification" 150 "oidc_proto_jwt_verify: JWT signature verification with algorithm \"RS256\" was successful"
}

function rp_id_token_sig_enc() {
	local TEST_ID="rp-id_token-sig+enc"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"id_token_encrypted_response_alg\" is set to e.g. \"A128KW\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"

	find_in_logfile "${TEST_ID}" "check encrypted id_token" 125 "oidc_proto_parse_idtoken: enter: id_token header={\"alg\":\"A128KW\""
	find_in_logfile "${TEST_ID}" "check decryption result" 125 "oidc_proto_parse_idtoken: successfully parsed (and possibly decrypted) JWT"
}

function rp_id_token_sig_none() {
	local TEST_ID="rp-id_token-sig-none"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"

	# make sure we were using the code flow
	find_in_logfile "${TEST_ID}" "check code flow" 125 "oidc_util_http_post_form: post data=\"grant_type=authorization_code&code="
	# make sure the id_token has alg "none" set
	find_in_logfile "${TEST_ID}" "check alg none" 125 "oidc_proto_parse_idtoken: successfully parsed" "JWT with header={\"alg\":\"none\"}"
	# check that we finished id_token validation succesfully
	find_in_logfile "${TEST_ID}" "check valid id_token" 125 "oidc_proto_parse_idtoken: valid id_token for user"
}

function rp_id_token_sub() {
	local TEST_ID="rp-id_token-sub"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	initiate_sso ${TEST_ID} ${ISSUER}
	send_authentication_request ${TEST_ID} ${RESULT}
	send_authentication_response ${TEST_ID} ${RESULT}
	
	find_in_logfile "${TEST_ID}" "check missing sub" 30 "oidc_proto_validate_idtoken: id_token JSON payload did not contain the required-by-spec \"sub\" string value"
	find_in_logfile "${TEST_ID}" "check abort" 30 "oidc_proto_parse_idtoken: id_token payload could not be validated, aborting"
}

function rp_claims_request_id_token() {
	local TEST_ID="rp-claims_request-id_token"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"scope\" is set to \"openid\""
	echo " * [server] prerequisite: .conf exists and \"auth_request_params\" is set to e.g. \"claims=%7B%20%22id_token%22%3A%20%7B%20%22email%22%3A%20%7B%22essential%22%3A%20true%7D%20%7D%20%7D\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"
	
	# make sure the id_token contains the email claim
	find_in_logfile "${TEST_ID}" "check email claim" 125 "oidc_proto_parse_idtoken: successfully parsed" "\"email\": \"diana@example.org\""
	# check that we finished id_token validation succesfully
	find_in_logfile "${TEST_ID}" "check valid id_token" 125 "oidc_proto_parse_idtoken: valid id_token for user"		
}

function rp_claims_request_userinfo() {
	local TEST_ID="rp-claims_request-userinfo"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"scope\" is set to \"openid\""
	echo " * [server] prerequisite: .conf exists and \"auth_request_params\" is set to e.g. \"claims=%7B%20%22userinfo%22%3A%20%7B%20%22email%22%3A%20%7B%22essential%22%3A%20true%7D%20%7D%20%7D\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"
	
	# make sure the response from the userinfo endpoint contains the email claim
	find_in_logfile "${TEST_ID}" "check email claim" 125 "oidc_util_http_call: response=" "\"email\": \"diana@example.org\""
}

function rp_scope_userinfo_claims() {
	local TEST_ID="rp-scope-userinfo-claims"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"scope\" is set to \"openid email phone\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"
	
	# make sure the response from the userinfo endpoint contains the email claim
	find_in_logfile "${TEST_ID}" "check email claim" 125 "oidc_util_http_call: response=" "\"email\": \"diana@example.org\""
	# make sure the response from the userinfo endpoint contains the phone_number claim
	find_in_logfile "${TEST_ID}" "check phone claim" 125 "oidc_util_http_call: response=" "\"phone_number\": \"+46 90 7865000\""
}

function rp_key_rotation_op_sign_key() {
	local TEST_ID="rp-key-rotation-op-sign-key"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"
	
	# make sure we tried to use keys from cache first and missed
	find_in_logfile "${TEST_ID}" "check JWKs cache miss" 125 "oidc_proto_get_keys_from_jwks_uri: could not find a key in the cached JSON Web Keys"
	# and we did a forced refresh
	find_in_logfile "${TEST_ID}" "check JWKs refresh" 125 "oidc_metadata_jwks_get: doing a forced refresh of the JWKs"
	# then we found a match
	find_in_logfile "${TEST_ID}" "check matching kid" 125 "oidc_proto_get_key_from_jwks: found matching kid:" "rotated_rsa"
	# and it verified succesfully
	find_in_logfile "${TEST_ID}" "check verification" 125 "oidc_proto_jwt_verify: JWT signature verification" "was successful"				
}

function rp_userinfo_bad_sub_claim() {
	local TEST_ID="rp-userinfo-bad-sub-claim"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"
	
	# check that the sub claim did not match
	find_in_logfile "${TEST_ID}" "check sub mismatch" 125 "oidc_proto_resolve_userinfo: \"sub\" claim" "returned from userinfo endpoint does not match the one in the id_token"
	# check that the claims from the userinfo endpoint were discarded
	find_in_logfile "${TEST_ID}" "check claims discarded" 125 "oidc_retrieve_claims_from_userinfo_endpoint" "failed, nothing will be stored in the session"
}

function rp_userinfo_bearer_header() {
	local TEST_ID="rp-userinfo-bearer-header"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"
	
	# check userinfo endpoint access
	find_in_logfile "${TEST_ID}" "check userinfo endpoint access" 125 "oidc_proto_resolve_userinfo: enter, endpoint=${ISSUER}"

	# find access token	
	AT=`tail -n 125 ${LOG_FILE} | grep "oidc_proto_resolve_userinfo: enter, endpoint=${ISSUER}/userinfo, access_token=" | cut -d"," -f3 | cut -d"=" -f2-`

	# check bearer token usage in header
	find_in_logfile "${TEST_ID}" "check bearer token header" 125 "oidc_util_http_call: url=${ISSUER}/userinfo" "bearer_token=${AT}"

	# check valid JSON result
	find_in_logfile "${TEST_ID}" "check valid JSON result" 125 "oidc_util_http_call: response={" "}"
	
	# check no error
	find_in_logfile "${TEST_ID}" "check no error" 125 "oidc_proto_resolve_userinfo: id_token_sub=" "user_info_sub="
}

function rp_userinfo_bearer_body() {
	local TEST_ID="rp-userinfo-bearer-body"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"
	
	# check userinfo endpoint access
	find_in_logfile "${TEST_ID}" "check userinfo endpoint access" 125 "oidc_proto_resolve_userinfo: enter, endpoint=${ISSUER}"

	# check bearer token usage in POST body
	find_in_logfile "${TEST_ID}" "check bearer token POST param" 125 "oidc_util_http_post_form: post" "access_token="
	
	# check valid JSON result
	find_in_logfile "${TEST_ID}" "check valid JSON result" 125 "oidc_util_http_call: response={" "}"
	
	# check no error
	find_in_logfile "${TEST_ID}" "check no error" 125 "oidc_proto_resolve_userinfo: id_token_sub=" "user_info_sub="
}

function rp_userinfo_sig() {
	local TEST_ID="rp-userinfo-sig"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"userinfo_signed_response_alg\" is set to e.g. \"RS256\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"
	
	# check we got a signed JWT in the response from the userinfo endpoint
	find_in_logfile "${TEST_ID}" "check JWT response" 125 "oidc_user_info_response_validate: JWT header=" "\"alg\":\"RS256\""
		
	# check the JWT verified successfully
	find_in_logfile "${TEST_ID}" "check JWT verification" 125 "oidc_user_info_response_validate: successfully verified signed JWT returned from userinfo endpoint"
}

function rp_userinfo_enc() {
	local TEST_ID="rp-userinfo-enc"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"userinfo_encrypted_response_alg\" is set to e.g. \"RSA1_5\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"
	
	# check we got a JWE in the response from the userinfo endpoint
	find_in_logfile "${TEST_ID}" "check JWE response" 125 "oidc_user_info_response_validate: JWT header=" "\"alg\":\"RSA1_5\""
		# check the JWE was decrypted successfully
	find_in_logfile "${TEST_ID}" "check JWE decryption" 125 "oidc_user_info_response_validate: successfully decrypted JWE returned from userinfo endpoint"
}


function rp_userinfo_sig_enc() {
	local TEST_ID="rp-userinfo-sig+enc"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"userinfo_signed_response_alg\" is set to e.g. \"RS256\""
	echo " * [server] prerequisite: .conf exists and \"userinfo_encrypted_response_alg\" is set to e.g. \"A128KW\""
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"
	
	# check we got a JWE in the response from the userinfo endpoint
	find_in_logfile "${TEST_ID}" "check JWE response" 125 "oidc_user_info_response_validate: JWT header=" "\"alg\":\"A128KW\""
	# check the JWE was decrypted successfully
	find_in_logfile "${TEST_ID}" "check JWE decryption" 125 "oidc_user_info_response_validate: successfully decrypted JWE returned from userinfo endpoint"
	# check we got a signed JWT in the JWE
	find_in_logfile "${TEST_ID}" "check JWT in JWE response" 125 "oidc_user_info_response_validate: successfully parsed JWT" "\"alg\":\"RS256\""				
	# check the JWT verified successfully
	find_in_logfile "${TEST_ID}" "check JWT verification" 125 "oidc_user_info_response_validate: successfully verified signed JWT returned from userinfo endpoint"
}

function rp_request_uri_sig() {
	local TEST_ID="rp-request_uri-sig"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"
	
	echo " * "
	echo " * [server] prerequisite: .conf exists and \"request_object\" is set to e.g. \"{ \"crypto\": { \"sign_alg\": \"HS256\" } }"
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"

	# check we created a request object that was signed with the client secret
	find_in_logfile "${TEST_ID}" "check signed request object" 150 "oidc_proto_create_request_uri: serialized request object JWT header" "\"alg\": \"HS256\""

	# check we sent request URI in the authorization request
	find_in_logfile "${TEST_ID}" "check request URI" 150 "oidc_proto_authorization_request: adding outgoing header" "&request_uri="

	# TODO: check resolving of request URI if on the same server
}

function rp_request_uri_unsigned() {
	local TEST_ID="rp-request_uri-unsigned"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"

	echo " * "
	echo " * [server] prerequisite: .conf exists and \"request_object\" is set to e.g. \"{ \"crypto\": { \"sign_alg\": \"none\" } }"
	echo " * "
	
	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"	

	# check we created a request object that was unsecured 
	find_in_logfile "${TEST_ID}" "check unsigned request object" 150 "oidc_proto_create_request_uri: serialized request object JWT header" "\"alg\":\"none\""

	# check we sent request URI in the authorization request
	find_in_logfile "${TEST_ID}" "check request URI" 150 "oidc_proto_authorization_request: adding outgoing header" "&request_uri="

	# TODO: check resolving of request URI if on the same server
}

function rp_request_uri_enc() {
	local TEST_ID="rp-request_uri-enc"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"
	
	echo " * "
	echo " * [server] prerequisite: .conf exists and \"request_object\" is set to e.g. \"{ \"crypto\": { \"crypt_alg\": \"A128KW\" } }"
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"
	
	# check we created a request object that was encrypted 
	find_in_logfile "${TEST_ID}" "check encrypted request object" 150 "oidc_proto_create_request_uri: serialized request object JWT header" "\"alg\": \"A128KW\""

	# check we sent request URI in the authorization request
	find_in_logfile "${TEST_ID}" "check request URI" 150 "oidc_proto_authorization_request: adding outgoing header" "&request_uri="

	# TODO: check resolving of request URI if on the same server
}

function rp_request_uri_sig_enc() {
	local TEST_ID="rp-request_uri-sig+enc"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"
	
	echo " * "
	echo " * [server] prerequisite: .conf exists and \"request_object\" is set to e.g. \"{ \"crypto\": { \"sign_alg\": \"RS256\", \"crypt_alg\": \"A128KW\" } }"
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"	

	# check we created a request object that was encrypted 
	find_in_logfile "${TEST_ID}" "check encrypted request object" 150 "oidc_proto_create_request_uri: serialized request object JWT header" "\"alg\": \"RSA1_5\""

	# check we sent request URI in the authorization request
	find_in_logfile "${TEST_ID}" "check request URI" 150 "oidc_proto_authorization_request: adding outgoing header" "&request_uri="
				
	# TODO: check resolving of request URI if on the same server
}

function rp_key_rotation_op_enc_key() {
	local TEST_ID="rp-key-rotation-op-enc-key"
	local ISSUER="${RP_TEST_URL}/${RP_ID}/${TEST_ID}"
	
	echo " * "
	echo " * [server] prerequisite: .conf exists and \"request_object\" is set to e.g. \"{ \"crypto\": { \"crypt_alg\": \"RSA1_5\" } }"
	echo " * "

	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"
	
	# check we created a request object that was encrypted 
	find_in_logfile "${TEST_ID}" "check encrypted request object" 150 "oidc_proto_create_request_uri: serialized request object JWT header" "\"alg\": \"RSA1_5\""

	# check we sent request URI in the authorization request
	find_in_logfile "${TEST_ID}" "check request URI" 150 "oidc_proto_authorization_request: adding outgoing header" "&request_uri="

	# check that we refreshed keys
	find_in_logfile "${TEST_ID}" "check JWKS refresh" 150 "oidc_metadata_jwks_get: doing a forced refresh of the JWKs from URI"
	
	# get the kid we used for encryption
	KIDA=`tail -n 150 ${LOG_FILE} | grep  "oidc_proto_create_request_uri: serialized request object JWT header" | cut -d{ -f2 | cut -d: -f4 | cut -d"\"" -f2`
	message "${TEST_ID}" "kid #1 ${KIDA}"
		
	# test a regular flow up until successful authenticated application access
	regular_flow "${TEST_ID}"
	
	# check we created a request object that was encrypted 
	find_in_logfile "${TEST_ID}" "check encrypted request object" 150 "oidc_proto_create_request_uri: serialized request object JWT header" "\"alg\": \"RSA1_5\""

	# check we sent request URI in the authorization request
	find_in_logfile "${TEST_ID}" "check request URI" 150 "oidc_proto_authorization_request: adding outgoing header" "&request_uri="

	# check that we refreshed keys
	find_in_logfile "${TEST_ID}" "check JWKS refresh" 150 "oidc_metadata_jwks_get: doing a forced refresh of the JWKs from URI"
	
	# get the kid we used for encryption
	KIDB=`tail -n 150 ${LOG_FILE} | grep  "oidc_proto_create_request_uri: serialized request object JWT header" | cut -d{ -f2 | cut -d: -f4 | cut -d"\"" -f2`
	message "${TEST_ID}" "kid #2 ${KIDB}"
				
	# check that the kid's from the two tests differ
	message "${TEST_ID}" "check different kids" "-n"
	if [ "${KIDA}" != "${KIDB}" ] ; then echo "OK"; else echo "ERROR" && exit; fi
}

function execute_test() {
	local TEST_ID="${1}"
	local NR="${2}"
	local TOTAL="${3}"
	
	echo ""
	printf " # test [%s/%s]: %s\n" $((NR+1)) ${TOTAL} "${TEST_ID}"
	echo ""
	eval "${TEST_ID}"
}

if [ $1 != "all" ] ; then
		execute_test "${1}" 0 1
else
	TOTAL=`echo ${TESTS} | wc -w`
	NR=0
	for TEST_ID in $TESTS; do
		execute_test "${TEST_ID}" "${NR}" "${TOTAL}"
		NR=$((NR+1))
	done
	echo ""
	printf " # SUCCESS: coverage %.2f%%\n" `echo "100 * ${NR} / ${TOTAL}" | bc -l`
	echo ""
fi

#
# OLD:
#
# exec_implicit "${1}" "${CSRF}"
# if [[ $? -eq 0 ]] ; then echo "yes" ; else echo "no"; fi

#
# Implicit, parsing out fragment encoded response and posting to RP
#
# presumes that the implicit grant is pre-configured in a pre-existing <issuer.conf file...
#
function exec_implicit() {
  local BEHAVIOR=$1
  local CSRF=$2
  local ISSUER="${RP_TEST_URL}/${RP_ID}/_/_/${BEHAVIOR}/normal"
  echo " [${BEHAVIOR}] initiate SSO..."
  REQUEST=`echo ${FLAGS} -i | xargs curl -G --data-urlencode "iss=${ISSUER}" --data-urlencode "target_link_uri=${TARGET_URL}" --data-urlencode "x_csrf=${CSRF}" ${REDIRECT_URI} | grep_location_header_value`
  echo " [${BEHAVIOR}] send authentication request to OP..."
  POST_DATA=`echo ${FLAGS} -i | xargs curl "${REQUEST}" | grep_location_header_value`
  echo " [${BEHAVIOR}] return authentication response to RP..."
  RESULT=`echo ${FLAGS} | xargs curl -L -d "${POST_DATA}&response_mode=fragment" ${REDIRECT_URI}`
  echo " [${BEHAVIOR}] parsing result..."
  echo "${RESULT}" | grep -q "\[Cookie\] => mod_auth_openidc_session="
}

