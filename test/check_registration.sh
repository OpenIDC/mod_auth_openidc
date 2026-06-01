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
# check_registration.sh
#
# Fail the build when a libcheck test body is defined with START_TEST(...)
# but never wired into a suite via tcase_add_test(...).  Such a test compiles
# cleanly yet silently never runs, so `make check` stays green while the test
# does nothing.  This script runs as part of `make check`.
#
# Notes:
#  - POSIX sh only: $(SHELL) is dash on the CI/build hosts, so no bashisms.
#  - Every grep uses -a (force text): some test sources embed non-text bytes
#    as test vectors (e.g. test_util.c).  Without -a, GNU grep prints
#    "binary file matches" and suppresses -o output, hiding that file's tests
#    from this check entirely.

set -eu

# Locate the test sources: prefer $srcdir (exported by the Automake test
# harness, and the only correct value under a VPATH/distcheck build), and fall
# back to the directory holding this script.
dir="${srcdir:-}"
[ -n "$dir" ] || dir=$(dirname "$0")

tmp_def=$(mktemp)
tmp_reg=$(mktemp)
trap 'rm -f "$tmp_def" "$tmp_reg"' EXIT

status=0
checked=0

for f in "$dir"/test_*.c; do
	# unexpanded glob (no sources found) leaves the literal pattern
	[ -e "$f" ] || continue
	checked=$((checked + 1))

	# names defined:      START_TEST (   name
	grep -aoE 'START_TEST[[:space:]]*\([[:space:]]*[A-Za-z_][A-Za-z0-9_]*' "$f" 2>/dev/null |
		sed -E 's/.*\([[:space:]]*//' | sort -u >"$tmp_def"

	# names registered:   tcase_add_test (   tcase ,   name
	grep -aoE 'tcase_add_test[[:space:]]*\([^,]*,[[:space:]]*[A-Za-z_][A-Za-z0-9_]*' "$f" 2>/dev/null |
		sed -E 's/.*,[[:space:]]*//' | sort -u >"$tmp_reg"

	# defined but never registered = silently dead tests
	missing=$(comm -23 "$tmp_def" "$tmp_reg")
	if [ -n "$missing" ]; then
		status=1
		base=$(basename "$f")
		echo "$missing" | while IFS= read -r name; do
			[ -n "$name" ] || continue
			echo "ERROR: $base: START_TEST($name) is never registered" \
				"with tcase_add_test() -- it will not run" >&2
		done
	fi
done

if [ "$checked" -eq 0 ]; then
	echo "ERROR: no test_*.c sources found under '$dir' -- cannot verify registration" >&2
	exit 1
fi

if [ "$status" -eq 0 ]; then
	echo "PASS: registration check -- every START_TEST in $checked file(s) is wired into a suite"
else
	echo "FAIL: register the test(s) above with a tcase_add_test(...) call in the suite builder" >&2
fi

exit "$status"
