#!/bin/bash

# need to forward SIGTERM to child process that runs Valgrind
_term() { 
  echo "Caught SIGTERM signal!" 
  kill -TERM "$child" 2>/dev/null
}
trap _term SIGTERM

. /etc/apache2/envvars

/usr/bin/valgrind \
	--leak-check=full \
	--show-leak-kinds=definite \
	--trace-children=yes \
	--error-exitcode=1 \
	--show-possibly-lost=no \
	--read-inline-info=yes \
	--keep-debuginfo=yes \
	--undef-value-errors=no \
	--log-file=/tmp/valgrind.log \
	/usr/sbin/apache2 -DFOREGROUND &

child=$! 

# wait for Keycloak to start (JMeter will requests start after that)
while ! curl -k -s https://keycloak:8443/auth/ > /dev/null ; do sleep 2 ;  done
sleep 10;

# interrupt the Apache/Valgrind process with graceful restarts
for i in {1..5}; do
	sleep 10;
	/usr/sbin/apache2 -k graceful
done

# wait for Valgrind to exit after getting a SIGTERM from JMeter
wait "$child"

# check semaphores and shared memory cleanup
/usr/sbin/apache2 -k stop
sleep 5;
ipcs -u | grep "segments allocated 0" || exit -1
ipcs -u | grep "allocated semaphores = 0" || exit -1

# wait until the logfile has been written and closed...
while ! tail -n 25 /tmp/valgrind.log | grep "ERROR SUMMARY" > /dev/null ; do sleep 1; done
# print results and summary
cat /tmp/valgrind.log

# verify (distro dependent) memory leaks
RESULT=$([[ -f /tmp/valgrind.result ]] && cat /tmp/valgrind.result || echo "definitely lost: 0 bytes in 0 blocks")
tail -n 15 /tmp/valgrind.log | grep -A1 "LEAK SUMMARY" | grep "${RESULT}"
