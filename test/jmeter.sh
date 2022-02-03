#!/bin/bash

apk update && apk add --no-cache netcat-openbsd

while ! curl -k -s https://keycloak:8443/auth/ > /dev/null ; do sleep 1 ;  done
while ! curl -k -s https://apache:443/auth/ > /dev/null ; do sleep 1 ; done

sleep 5

/entrypoint.sh -JTHREADS=${THREADS} -JLOOP=${LOOP} -n -t /tmp/mod_auth_openidc.jmx > /tmp/mod_auth_openidc.log
cat /tmp/mod_auth_openidc.log | tail -n 10
grep "summary =" /tmp/mod_auth_openidc.log | grep "Err:     0 (0.00%)" || exit 1

#echo -e "GET /containers/json HTTP/1.0\r\n" | \
#	/usr/bin/nc -U /var/run/docker.sock

#NAME=mod_auth_openidc-apache-1
NAME=mod_auth_openidc_apache_1
echo -e "POST /containers/${NAME}/kill?signal=TERM HTTP/1.0\r\n" | \
	/usr/bin/nc -U /var/run/docker.sock

sleep infinity & PID=$!
trap "kill $PID" INT TERM

wait
