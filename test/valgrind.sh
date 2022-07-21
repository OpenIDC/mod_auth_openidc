#!/bin/bash

# need to forward SIGTERM to child process that runs Valgrind
_term() { 
  echo "Caught SIGTERM signal!" 
  kill -TERM "$child" 2>/dev/null
}
trap _term SIGTERM

a2enconf openidc
source /etc/apache2/envvars

valgrind \
	--leak-check=full \
	--error-exitcode=1 \
	--show-possibly-lost=no \
	--read-inline-info=yes \
	--keep-debuginfo=yes \
	--undef-value-errors=no \
	--log-file=/tmp/valgrind.log \
	/usr/sbin/apache2 -X &

child=$! 
wait "$child"

# wait until the logfile has been written and closed...
while ! tail -n 25 /tmp/valgrind.log | grep "ERROR SUMMARY" > /dev/null ; do sleep 1; done
# print results and summary
cat /tmp/valgrind.log
# verify that there are no memory leaks found
grep -A1 "LEAK SUMMARY" /tmp/valgrind.log | grep -q "definitely lost: 0 bytes in 0 blocks"
