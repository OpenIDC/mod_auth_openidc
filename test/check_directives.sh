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
# check_directives.sh
#
# Fail the build when a member of the per-directory config struct
# (oidc_dir_cfg_t in src/cfg/dir.c) is not handled in BOTH
# oidc_cfg_dir_config_create() (its create-time default) and
# oidc_cfg_dir_config_merge() (its base/add merge rule).
#
# Those two sites fail silently when forgotten: a directive added without a
# create default or a merge rule still compiles and its setter/getter still
# work, but the value is wrong in a merged (per-location) config -- it falls
# back to the apr_pcalloc(0) zero instead of the inherited or default value.
# This is the empty/sentinel-handling regression class that config merging
# has historically suffered from. This script runs as part of `make check`.
#
# Notes:
#  - POSIX sh only: $(SHELL) is dash on the CI/build hosts, so no bashisms.
#  - Adding a per-dir directive therefore means: struct member, create
#    default, merge rule, the OIDC_CFG_DIR_MEMBER_FUNCS{,_*} declaration
#    (dir.h) + definition (dir.c), and the OIDC_CFG_CMD_DIR entry (cmds.c).

set -eu

# Locate src/cfg/dir.c: prefer $srcdir (exported by the Automake test harness,
# correct under VPATH/distcheck where the test dir and src dir are siblings in
# the unpacked source tree), then fall back to build-relative paths.
dir="${srcdir:-}"
[ -n "$dir" ] || dir=$(dirname "$0")

src=""
for cand in "$dir/../src/cfg/dir.c" "../src/cfg/dir.c" "$(dirname "$0")/../src/cfg/dir.c"; do
	if [ -f "$cand" ]; then
		src="$cand"
		break
	fi
done

if [ -z "$src" ]; then
	echo "ERROR: cannot locate src/cfg/dir.c -- cannot verify directive coverage" >&2
	exit 1
fi

tmp_members=$(mktemp)
tmp_create=$(mktemp)
tmp_merge=$(mktemp)
trap 'rm -f "$tmp_members" "$tmp_create" "$tmp_merge"' EXIT

# struct members: identifiers terminated by ';' inside the struct block.
# Strip C comments (// and /* */, including multi-line spans) and skip
# preprocessor lines before extracting, so a stray 'word;' inside a comment or
# macro is not mistaken for a member. Without this, a trailing annotation like
# 'int foo; /* rename to bar; */' or a block-comment continuation line would
# inject a phantom member and fail the build with a confusing error. Plain
# index()/substr() only -- no dynamic regex -- so it stays gawk/mawk portable.
awk '
	/^struct oidc_dir_cfg_t \{/ { inside = 1; next }
	inside && /^\};/ { inside = 0 }
	!inside { next }
	{
		line = $0
		if (incomment) {		# inside an open /* ... that began earlier
			p = index(line, "*/")
			if (p == 0) next	# whole line is still commented out
			line = substr(line, p + 2)
			incomment = 0
		}
		while ((p = index(line, "/*")) > 0) {	# strip /* ... */ spans
			tail = substr(line, p + 2)
			q = index(tail, "*/")
			if (q == 0) { line = substr(line, 1, p - 1); incomment = 1; break }
			line = substr(line, 1, p - 1) substr(tail, q + 2)
		}
		p = index(line, "//")			# strip // to end of line
		if (p > 0) line = substr(line, 1, p - 1)
		if (line ~ /^[ \t]*#/) next		# skip preprocessor directives
		print line
	}' "$src" |
	grep -aoE '[A-Za-z_][A-Za-z0-9_]*;' | tr -d ';' | sort -u >"$tmp_members"

# members assigned (c->member) inside each function, up to its 'return c;'.
# Match the function-opening line with a literal index() lookup, not a dynamic
# regex: passing a regex through awk -v is not portable -- gawk strips the '\('
# escape (warning, then a fatal "Unmatched (" because the bare paren is then an
# invalid ERE) while mawk keeps it. index() is a plain substring search, so the
# '(' is literal and no escaping is needed.
extract_assigns() {
	sig=$1
	awk -v sig="$sig" 'index($0, sig){f=1} f&&/return c;/{f=0} f' "$src" |
		grep -aoE 'c->[A-Za-z_][A-Za-z0-9_]*' | sed 's/c->//' | sort -u
}
extract_assigns 'oidc_cfg_dir_config_create(apr_pool_t' >"$tmp_create"
extract_assigns 'oidc_cfg_dir_config_merge(apr_pool_t' >"$tmp_merge"

count=$(wc -l <"$tmp_members" | tr -d ' ')
if [ "$count" -eq 0 ]; then
	echo "ERROR: no oidc_dir_cfg_t members found in $src -- parser out of date?" >&2
	exit 1
fi

status=0
report() {
	# label = which oidc_cfg_dir_config_*() site, file = members missing from that site
	label=$1
	file=$2
	while IFS= read -r m; do
		[ -n "$m" ] || continue
		status=1
		echo "ERROR: oidc_dir_cfg_t.$m is not handled in oidc_cfg_dir_config_$label()" \
			"-- a merged config will get the zero default, not the configured/inherited value" >&2
	done <"$file"
}

comm -23 "$tmp_members" "$tmp_create" >"$tmp_create.miss" || true
comm -23 "$tmp_members" "$tmp_merge" >"$tmp_merge.miss" || true
report create "$tmp_create.miss"
report merge "$tmp_merge.miss"
rm -f "$tmp_create.miss" "$tmp_merge.miss"

if [ "$status" -eq 0 ]; then
	echo "PASS: directive coverage -- all $count oidc_dir_cfg_t members are initialized and merged"
else
	echo "FAIL: wire the member(s) above into oidc_cfg_dir_config_create() and/or _merge() in src/cfg/dir.c" >&2
fi

exit "$status"
