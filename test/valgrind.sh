#!/bin/bash

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

sleep 5

cat /tmp/valgrind.log
grep -A1 "LEAK SUMMARY" /tmp/valgrind.log | grep "definitely lost: 0 bytes in 0 blocks"
