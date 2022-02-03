#!/bin/bash

# install utilities needed for accessing the Docker API
apk update && apk add --no-cache jq curl

# wait for Keycloak to start
while ! curl -k -s https://keycloak:8443/auth/ > /dev/null ; do sleep 2 ;  done
# wait for Apache/mod_auth_openidc to start (in Valgrind)
while ! curl -k -s https://apache:443/auth/ > /dev/null ; do sleep 2 ; done

# give Keycloak time to run startup scripts to create clients
sleep 5

# run headless JMeter for a number of threads/loops and record results in a logfile
/entrypoint.sh -JTHREADS=${THREADS} -JLOOP=${LOOP} -n -t /tmp/mod_auth_openidc.jmx > /tmp/mod_auth_openidc.log

# verify that there were no errors in the logfile that JMeter produced
cat /tmp/mod_auth_openidc.log | tail -n 10
grep "summary =" /tmp/mod_auth_openidc.log | grep "Err:     0 (0.00%)" || exit 1

# find out the container id of the Apache server
ID=$(curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | jq -r 'map(select(.Names[] | contains ("apache"))) | .[] .Id')
# send SIGTERM to Apache so Valgrind terminates and prints out the heap/leak summary
curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/${ID}/kill?signal=TERM 

# wait until we receive a SIGTERM ourselves to ensure that the Apache
# exits first and terminates docker-compose --abort-on-container-exit 
sleep infinity & PID=$!
trap "kill $PID" INT TERM

wait
