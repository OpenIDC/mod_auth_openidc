#!/bin/sh
#
# Licensed to the Apache Software Foundation (ASF) under one or more contributor license
# agreements.  Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Copyright (C) 2017-2026 ZmartZone Holding BV - hans.zandbelt@openidc.com
#
# gen-tags.sh -- exact tags for the config accessors that cfg/ generates with token-pasting macros.
#
# Those names (oidc_cfg_provider_issuer_get, oidc_cmd_dir_pass_claims_as_set, ...) are assembled by
# the preprocessor from a struct member name, so they exist in no source line and neither grep nor
# ctags can find them. The previous approach reconstructed them with regexes over the generator
# CALL sites; measured against the linked symbol table it invented 91 names that exist nowhere and
# missed 82 that do -- the whole cfg/cache.c family was wrong, because that generator prepends
# "cache_" to the member name.
#
# This asks the compiler instead. Each translation unit is preprocessed with the real build flags,
# and every function DEFINITION (a signature followed by a body, as opposed to the declarations the
# headers expand to) is recorded against the file and line of the generator call it came from,
# which the preprocessor's line markers give us. The result cannot drift from what is compiled: a
# new generator macro, a renamed member or a changed prefix is picked up with no change here.
#
# Tags carry a line-number address rather than a search pattern, because there is no text in the
# source to search for -- the address is the macro call site, which is where you want to land.
#
# Usage:  CPP="<compiler> -E <flags>" gen-tags.sh <source.c>...  > cfgtags
# Editors: point at the extra file, e.g. vim ':set tags=./tags,./cfgtags'.

set -eu

if [ -z "${CPP:-}" ]; then
	echo "gen-tags.sh: CPP is not set; run this through 'make cfgtags'" >&2
	exit 1
fi

for src in "$@"; do
	# shellcheck disable=SC2086 # CPP is a command plus flags and must word-split
	${CPP} "${src}" 2>/dev/null | awk -v src="${src}" '
		# line markers reset our position in the original sources: # <line> "<file>"
		/^# [0-9]+ "/ {
			line = $2
			file = $3
			gsub(/"/, "", file)
			next
		}
		{
			# a definition is a signature followed by a body; the headers expand to
			# declarations ending in ";", which must not be tagged
			s = $0
			while (match(s, /oidc_(cfg|cmd)_[A-Za-z0-9_]+[ \t]*\(/)) {
				name = substr(s, RSTART, RLENGTH)
				sub(/[ \t]*\($/, "", name)
				rest = substr(s, RSTART + RLENGTH)
				# reject a match that is only the tail of a longer identifier, so that
				# the file-local _oidc_cfg_* helpers keep their leading underscore.
				# s is always a suffix of the line, so the char before RSTART is the
				# real predecessor; at RSTART == 1 it is the "(" we just consumed.
				pre = (RSTART > 1) ? substr(s, RSTART - 1, 1) : "("
				# a macro expansion puts the whole definition on one line; an ordinary
				# multi-line signature is left to plain ctags, which can already see it
				if (pre !~ /[A-Za-z0-9_]/ && match(rest, /^[^;{]*\)[ \t]*\{/))
					print name "\t" file "\t" line ";\"\tf"
				s = rest
			}
			line++
		}
	'
done
