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

# version_lt A B : true when dotted version A is strictly older than B
version_lt() {
	local a="$1"
	local b="$2"
	if [ "$a" != "$b" ] && [ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" = "$a" ]; then
		return 0
	fi
	return 1
}

# cjose below 0.6.2.8 has a memory-safety bug in its RSA content-encryption-key
# decrypt: a failed RSA-OAEP/RSA1_5 unwrap leaves jwe->cek_len at (size_t)-1, so
# the next candidate key's _cjose_release_cek() memsets SIZE_MAX bytes and
# crashes. The jwe-rsa-oaep-gcm-rfc seed drives exactly that, because the fixture
# offers two RSA keys and oidc_jwe_decrypt_any() tries the wrong one first about
# 70% of the time (APR hash order). It is a real crash, not a test artifact, but
# it lives in cjose and is fixed in 0.6.2.8; on an older cjose skip only that one
# seed so the rest of the jwt corpus still runs. CJOSE_VERSION is set by the
# Makefile from what configure linked; fall back to pkg-config for an ad-hoc run,
# and when the version cannot be determined, run everything (a crash then still
# fails the build loudly rather than silently dropping coverage).
skip_jwe_rsa_oaep=no
cjose_version="${CJOSE_VERSION:-}"
[ -n "$cjose_version" ] || cjose_version=$(pkg-config --modversion cjose 2>/dev/null || echo "")
if [ -n "$cjose_version" ] && version_lt "$cjose_version" 0.6.2.8; then
	skip_jwe_rsa_oaep=yes
fi

replay fuzz_base64 "$dir"/fuzz/corpus/base64/*
if [ "$skip_jwe_rsa_oaep" = yes ]; then
	echo "SKIP: fuzz_jwt/jwe-rsa-oaep-gcm-rfc -- cjose $cjose_version < 0.6.2.8 has an RSA-CEK memory-safety bug (fixed in 0.6.2.8)"
	set --
	for f in "$dir"/fuzz/corpus/jwt/*; do
		case "$f" in
		*/jwe-rsa-oaep-gcm-rfc) ;;
		*) set -- "$@" "$f" ;;
		esac
	done
	replay fuzz_jwt "$@"
else
	replay fuzz_jwt "$dir"/fuzz/corpus/jwt/*
fi
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
replay fuzz_backchannel_logout "$dir"/fuzz/corpus/backchannel_logout/*
replay fuzz_authz_response "$dir"/fuzz/corpus/authz_response/*
replay fuzz_current_url "$dir"/fuzz/corpus/current_url/*
replay fuzz_bearer_token "$dir"/fuzz/corpus/bearer_token/*
replay fuzz_redirect_uri "$dir"/fuzz/corpus/redirect_uri/*
replay fuzz_post_preserve "$dir"/fuzz/corpus/post_preserve/*
replay fuzz_strings "$dir"/fuzz/corpus/strings/*

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
