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
# check_conf_reference.sh
#
# Fail the build when auth_openidc.conf -- the shipped reference config, and the
# canonical directive documentation -- has drifted from the code.
#
# It drifts silently: the file is data, never compiled and never parsed by the
# test suite, so a directive added without a corresponding entry, or an option
# list that no longer matches the values the parser accepts, ships as-is. Both
# have happened: the OIDCMetricsData syntax line offered a "requests" class that
# does not exist (Apache refuses to start on it) while omitting "provider", and
# the "logout" class was missing entirely for a release.
#
# Three checks, all mechanical:
#  1. every directive macro in src/cfg/directives.h is documented
#  2. every documented directive resolves to a real macro (no leftovers)
#  3. the OIDCMetricsData class list matches the OM_CLASS_* set in src/metrics.c
#
# Check 3 is deliberately specific rather than general: mapping an arbitrary
# "[a|b|c]" syntax line back to the oidc_cfg_option_t array its parser uses is
# not mechanically derivable from the source, so only this list -- the one that
# actually broke, and whose source of truth is a plain table -- is pinned.
#
# Notes:
#  - POSIX sh only: $(SHELL) is dash on the CI/build hosts, so no bashisms.
#  - Locating an input is fatal, never a skip: a check that cannot find what it
#    checks must not report success.

set -eu

# Prefer $srcdir (exported by the Automake test harness, correct under
# VPATH/distcheck where the test dir and the source root are siblings).
dir="${srcdir:-}"
[ -n "$dir" ] || dir=$(dirname "$0")

find_input() {
	want=$1
	for cand in "$dir/../$want" "../$want" "$(dirname "$0")/../$want"; do
		if [ -f "$cand" ]; then
			echo "$cand"
			return 0
		fi
	done
	echo "ERROR: cannot locate $want -- cannot verify the reference config" >&2
	return 1
}

directives=$(find_input src/cfg/directives.h)
conf=$(find_input auth_openidc.conf)
metrics=$(find_input src/metrics.c)

tmp_defined=$(mktemp)
tmp_documented=$(mktemp)
tmp_valid=$(mktemp)
tmp_listed=$(mktemp)
trap 'rm -f "$tmp_defined" "$tmp_documented" "$tmp_valid" "$tmp_listed"' EXIT

status=0

# --- 1 + 2: directive coverage ------------------------------------------------
#
# Definitions are '#define OIDCFoo "OIDCFoo"'. Documentation is a syntax line at
# the start of a line, '#OIDCFoo ...' -- prose and examples inside comments are
# indented ('#   OIDCFoo ...') and so are not mistaken for one.

sed -n 's/^#define[[:space:]][[:space:]]*\(OIDC[A-Za-z0-9_]*\)[[:space:]][[:space:]]*".*/\1/p' \
	"$directives" | sort -u >"$tmp_defined"
sed -n 's/^#\(OIDC[A-Za-z0-9_]*\)\([[:space:]].*\)*$/\1/p' "$conf" | sort -u >"$tmp_documented"

count=$(wc -l <"$tmp_defined" | tr -d ' ')
if [ "$count" -lt 100 ]; then
	echo "ERROR: only $count directive macros found in $directives -- the extraction is broken" >&2
	exit 1
fi

while IFS= read -r d; do
	[ -n "$d" ] || continue
	status=1
	echo "ERROR: $d is defined in src/cfg/directives.h but not documented in auth_openidc.conf" >&2
done <<EOF
$(comm -23 "$tmp_defined" "$tmp_documented")
EOF

while IFS= read -r d; do
	[ -n "$d" ] || continue
	status=1
	echo "ERROR: $d is documented in auth_openidc.conf but is not a directive" >&2
done <<EOF
$(comm -13 "$tmp_defined" "$tmp_documented")
EOF

# --- 3: the OIDCMetricsData class list ----------------------------------------
#
# Valid classes are the OM_CLASS_* values, except "claim", which the validator
# special-cases into the "claim.id_token.*"/"claim.userinfo.*" prefixes.

sed -n 's/^#define[[:space:]][[:space:]]*OM_CLASS_[A-Z_]*[[:space:]][[:space:]]*"\([^"]*\)".*/\1/p' \
	"$metrics" | grep -v '^claim$' >"$tmp_valid"
printf 'claim.id_token.*\nclaim.userinfo.*\n' >>"$tmp_valid"
sort -u -o "$tmp_valid" "$tmp_valid"

sed -n 's/^#OIDCMetricsData[[:space:]]*\[\(.*\)\][+*]*[[:space:]]*$/\1/p' "$conf" |
	tr '|' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | sed '/^$/d' | sort -u >"$tmp_listed"

if [ ! -s "$tmp_listed" ]; then
	echo "ERROR: could not parse the OIDCMetricsData syntax line in auth_openidc.conf" >&2
	status=1
else
	while IFS= read -r c; do
		[ -n "$c" ] || continue
		status=1
		echo "ERROR: OIDCMetricsData documents \"$c\", which is not a metrics class --" \
			"Apache refuses to start on it" >&2
	done <<EOF
$(comm -13 "$tmp_valid" "$tmp_listed")
EOF

	while IFS= read -r c; do
		[ -n "$c" ] || continue
		status=1
		echo "ERROR: metrics class \"$c\" is missing from the OIDCMetricsData syntax line" >&2
	done <<EOF
$(comm -23 "$tmp_valid" "$tmp_listed")
EOF
fi

if [ "$status" -eq 0 ]; then
	echo "PASS: auth_openidc.conf documents all $count directives and the OIDCMetricsData classes match"
else
	echo "FAIL: update auth_openidc.conf to match the code (see the errors above)" >&2
fi

exit "$status"
