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
# run-fuzzers.sh
#
# Replay each fuzz target's seed corpus through its standalone (non-libFuzzer)
# binary as part of `make check`. This is a regression guard, not a fuzzing
# run: it keeps the targets compiling and proves they survive the known-nasty
# inputs (notably the 800+ open-redirect payloads). A crash/abort in any
# target fails the build. Real fuzzing is a separate clang/libFuzzer build;
# see build.sh.
#
# POSIX sh: $(SHELL) is dash on the build hosts.

set -u

# corpus + payload lists live in srcdir; the binaries are in the builddir cwd
dir="${srcdir:-}"
[ -n "$dir" ] || dir=$(dirname "$0")/..

status=0
replayed=0

# replay <binary> <args...>  (binary lives in the builddir)
replay() {
	bin=$1
	shift
	if [ ! -x "./$bin" ]; then
		echo "SKIP: $bin not built"
		return
	fi
	replayed=$((replayed + 1))
	echo "fuzz: $bin $*"
	# the module logs each rejected input to stderr; keep that out of the
	# normal log and surface it only when a target actually crashes
	errlog=$(mktemp)
	if ! "./$bin" "$@" >/dev/null 2>"$errlog"; then
		echo "FAILED: $bin exited non-zero -- it crashed, or an input was unreadable"
		cat "$errlog"
		status=1
	fi
	rm -f "$errlog"
}

replay fuzz_base64 "$dir"/fuzz/corpus/base64/*
replay fuzz_jwt "$dir"/fuzz/corpus/jwt/*
replay fuzz_json "$dir"/fuzz/corpus/json/*
replay fuzz_url "$dir"/fuzz/corpus/url/*
# the curated open-redirect payloads, one input per line
replay fuzz_url --lines "$dir"/open-redirect-payload-list.txt
replay fuzz_cookie "$dir"/fuzz/corpus/cookie/*
replay fuzz_response_header "$dir"/fuzz/corpus/response_header/*
replay fuzz_form_params "$dir"/fuzz/corpus/form_params/*
replay fuzz_metadata "$dir"/fuzz/corpus/metadata/*
replay fuzz_state_cookie "$dir"/fuzz/corpus/state_cookie/*
replay fuzz_jwks "$dir"/fuzz/corpus/jwks/*
replay fuzz_discovery_response "$dir"/fuzz/corpus/discovery_response/*
replay fuzz_pem_key "$dir"/fuzz/corpus/pem_key/*

# a run in which every target was skipped proves nothing: report it as a failure
# rather than as a pass, so a build-condition or rename that stops producing the
# binaries cannot leave this test silently green
if [ "$replayed" -eq 0 ]; then
	echo "FAIL: no fuzz target was replayed -- none of the binaries were built"
	exit 1
fi

if [ "$status" -eq 0 ]; then
	echo "PASS: $replayed fuzz seed corpora replayed with no crashes"
else
	echo "FAIL: a fuzz target failed -- reproduce with ./<target> <file>"
fi

exit "$status"
