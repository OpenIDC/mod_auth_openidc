#!/bin/sh
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  Licensed under the Apache License,
# Version 2.0 (the "License"); you may not use this file except in
# compliance with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Copyright (C) 2017-2026 ZmartZone Holding BV - hans.zandbelt@openidc.com
#
# build.sh -- compile the fuzz targets as real libFuzzer binaries (clang +
# AddressSanitizer/UndefinedBehaviorSanitizer). This is the path for actual
# fuzzing; `make check` already replays the seed corpora through the same
# targets built with the ordinary compiler (see run-fuzzers.sh).
#
# Prerequisites:
#   - clang (with the fuzzer + sanitizer runtimes)
#   - a prior `./configure && make` so the static convenience library
#     src/.libs/libauth_openidc.a exists
#
# Flags are derived from pkg-config and apxs. If a dependency is packaged
# differently on your system, override without editing this file, e.g.:
#   FUZZ_LIBS="-lcjose -lhiredis" CC=clang-18 ./build.sh
#
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

: "${CC:=clang}"
: "${APXS:=apxs}"
: "${SANITIZE:=fuzzer,address,undefined}"
: "${OUT:=$here/build}"
: "${FUZZ_CFLAGS:=}"
: "${FUZZ_LIBS:=}"

lib="$root/src/.libs/libauth_openidc.a"
if [ ! -f "$lib" ]; then
	echo "error: $lib not found -- run ./configure && make at the repo root first" >&2
	exit 1
fi

# core dependencies resolved via pkg-config; cjose/hiredis/jq are appended
# directly since they do not always ship a .pc file
pkgs="apr-1 apr-util-1 jansson libcurl libcrypto libssl libpcre2-8"
apache_inc=$($APXS -q INCLUDEDIR 2>/dev/null || echo /usr/include/apache2)

cflags="-g -O1 -fsanitize=$SANITIZE -DFUZZING \
	-I$root/src -I$root/test -I$apache_inc \
	$(pkg-config --cflags $pkgs) $FUZZ_CFLAGS"
libs="$(pkg-config --libs $pkgs) -lcjose -lhiredis -ljq -lz -lldap -llber \
	-lm -lrt -lpthread $FUZZ_LIBS"

mkdir -p "$OUT"
for t in base64 url jwt json; do
	src="$here/fuzz_$t.c"
	[ -f "$src" ] || continue
	echo "building $OUT/fuzz_$t"
	# shellcheck disable=SC2086
	$CC $cflags "$src" "$root/test/util.c" "$root/test/stub.c" "$lib" $libs -o "$OUT/fuzz_$t"
done

cat <<EOF

built libFuzzer targets in: $OUT

run one, e.g.:
  $OUT/fuzz_url  -max_len=1024 $here/corpus/url
  $OUT/fuzz_jwt  -max_len=4096 $here/corpus/jwt
  $OUT/fuzz_json -max_len=8192 $here/corpus/json

seed the url corpus with the curated open-redirect payloads:
  i=0; while IFS= read -r line; do
    printf '%s' "\$line" > "$here/corpus/url/payload-\$i"; i=\$((i+1))
  done < $root/test/open-redirect-payload-list.txt
EOF
