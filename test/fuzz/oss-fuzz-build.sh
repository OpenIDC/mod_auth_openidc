#!/bin/bash -eu
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
# oss-fuzz-build.sh -- build the fuzz targets inside an OSS-Fuzz base-builder
# container. Kept in this tree (rather than in google/oss-fuzz) so that adding a
# target, a seed corpus or a dictionary is a change here and nowhere else; the
# oss-fuzz-side build.sh does nothing but call this.
#
# Contract with OSS-Fuzz: use $CC/$CFLAGS/$LIB_FUZZING_ENGINE, write the target
# binaries to $OUT with no extension, and ship each target's seeds as
# $OUT/<target>_seed_corpus.zip. Locally this is not the fuzzing path -- use
# test/fuzz/build.sh for that, and `make check` for the regression replay.

: "${SRC:=/src}"
: "${OUT:=/out}"
: "${WORK:=/work}"
: "${CC:=clang}"
: "${CFLAGS:=-g -O1 -fsanitize=address,undefined}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"

root="$SRC/mod_auth_openidc"

# ---------------------------------------------------------------------------
# dependencies
#
# All of them are the distro packages the Dockerfile installs, cjose and jansson
# included. Those two used to be built from source under $CFLAGS so the sanitizers
# and the coverage report could see inside them, but that tied every nightly build
# to their upstream build systems: when cjose's main branch dropped autotools for
# CMake (2026-09-12) the autoreconf here failed and no build ran for days. The
# distro packages are what the module is built and tested against everywhere
# else, and configure finds cjose through PKG_CHECK_MODULES(CJOSE, cjose), so
# nothing needs pointing anywhere. The price: ASan only sees this module's own
# code, and coverage stops at the library boundary -- the parsers behind
# fuzz_json and fuzz_jwt are exercised as the black boxes the distro ships.
#
# Transitional: until the Dockerfile that installs libcjose-dev and libjansson-dev
# is merged (google/oss-fuzz#16139) the previous one is what builds the image,
# and it clones both trees into $SRC instead. So that the two halves of the
# switch can land in either order, build whatever was cloned -- provided it
# still has an autotools build, which is what OpenIDC/cjose's default branch
# (0.8.x) carries -- and put its pkg-config files first. Once the clones are
# gone this block is a no-op and can be deleted.
# ---------------------------------------------------------------------------
prefix="$WORK/deps"

build_dep() {
	name=$1
	shift
	echo "=== building $name from $SRC/$name"
	cd "$SRC/$name"
	# Always regenerate, never reuse a committed ./configure: cjose keeps its
	# generated autotools files (configure, Makefile.in, aclocal.m4) in git, built
	# by a newer automake than the base image carries. Reusing them makes make fire
	# its maintainer rebuild rules and invoke an aclocal-<newer> that is not
	# installed, which fails the build well after configure has appeared to succeed.
	autoreconf -fi
	./configure --prefix="$prefix" --disable-shared --enable-static "$@" >/dev/null
	make -j"$(nproc)" >/dev/null
	make install >/dev/null
}

if [[ -f "$SRC/jansson/configure.ac" ]]; then
	build_dep jansson
fi
if [[ -f "$SRC/cjose/configure.ac" ]]; then
	if [[ -f "$prefix/include/jansson.h" ]]; then
		build_dep cjose --with-jansson="$prefix"
	else
		build_dep cjose
	fi
fi
if [[ -d "$prefix/lib/pkgconfig" ]]; then
	export PKG_CONFIG_PATH="$prefix/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
fi

# ---------------------------------------------------------------------------
# the module itself: only the static convenience library is needed. The loadable
# module (mod_auth_openidc.la) is linked by apxs and is deliberately not built --
# nothing here loads it, and apxs would drag in the server's own link flags.
# ---------------------------------------------------------------------------
cd "$root"

# configure folds `apxs -q CFLAGS` into APACHE_CFLAGS, and the distro httpd is built
# with -flto=auto -ffat-lto-objects. Under LTO the sanitizer-coverage module
# constructors end up in comdat sections the linker discards, and every object in
# libauth_openidc.a then fails to link with "defined in discarded section". automake
# puts $(CFLAGS) after $(AM_CFLAGS), so -fno-lto here overrides what apxs supplied.
#
# -include stddef.h: the builder's apr.h (1.7.2) does not include <stddef.h>, so
# offsetof is undefined when apr_general.h is preprocessed and APR_OFFSETOF falls
# back to the &((struct apr_bucket *)NULL)->link idiom inside APR_RING_SENTINEL.
# UBSan's null check flags that address computation as "member access within
# null pointer" although nothing is dereferenced, which killed every target that
# passes a brigade (APR_BRIGADE_INSERT_TAIL in oidc_util_http_send, the
# ap_get_brigade stub) on the libfuzzer-undefined leg. With offsetof defined
# up front APR uses the builtin and the false positive is gone.
export CFLAGS="$CFLAGS -fno-lto -include stddef.h"

./autogen.sh
./configure \
	--with-apxs=/usr/bin/apxs \
	--without-jq --without-hiredis \
	--disable-shared
# An engine/sanitizer switch over a locally mounted tree (helper.py
# build_fuzzers with a source path) leaves objects compiled with the previous
# run's flags, which make considers up to date and links into the new targets
# (undefined __afl_area_ptr and the like). Start clean; this is a no-op in the
# pristine OSS-Fuzz container.
make -C src clean >/dev/null 2>&1 || true
make -C src libauth_openidc.la -j"$(nproc)"

lib="$root/src/.libs/libauth_openidc.a"
[[ -f "$lib" ]] || { echo "error: $lib was not built" >&2; exit 1; }

# The optional-feature macros (USE_MEMCACHE, USE_LIBHIREDIS, ...) live only in
# automake's AM_CFLAGS -- configure never puts them in config.h -- and they
# change the layout of oidc_cfg_t (cfg/cache.h embeds per-backend members by
# value). The harness TUs below, test/util.c included, compile against the same
# headers by hand, so they must see exactly the set the library was built with
# or a by-value oidc_cfg_t in a target is sized for a different struct than the
# one the library reads (fuzz_url, 2026-08-21: global-buffer-overflow on every
# input, hidden by the <10% broken-target tolerance). Ask make for the
# AM_CFLAGS the library compile used rather than re-deriving them here -- and
# ask make, not grep: automake keeps the disabled conditional branches in the
# generated Makefile as commented-out lines, which a grep would pick up too.
feature_cflags=$(make -s -C "$root/src" --eval='oidc-print-am-cflags: ; @echo $(AM_CFLAGS)' oidc-print-am-cflags |
	tr ' ' '\n' | grep -E '^-D(USE_[A-Z0-9_]+|SSL_SUPPORT)$' | sort -u | tr '\n' ' ')
echo "feature flags: ${feature_cflags:-(none)}"

# ---------------------------------------------------------------------------
# targets
#
# Same three-file link as test/fuzz/build.sh -- the target, the libcheck test
# fixture (a post-config'd request_rec + oidc_cfg_t) and the Apache server stubs
# -- with $LIB_FUZZING_ENGINE in place of -fsanitize=fuzzer so OSS-Fuzz can
# select the engine.
# ---------------------------------------------------------------------------
# one entry per test/fuzz/fuzz_<name>.c; keep in sync with build.sh, run-fuzzers.sh and ../Makefile.am
targets="base64 url jwt json cookie response_header form_params metadata state_cookie jwks discovery_response pem_key backchannel_logout authz_response current_url bearer_token redirect_uri post_preserve strings"

apache_inc=$(apxs -q INCLUDEDIR 2>/dev/null || echo /usr/include/apache2)
pkgs="cjose jansson apr-1 apr-util-1 libcrypto libssl libcurl libpcre2-8"
inc="-I$root/src -I$root/test -I$apache_inc $(pkg-config --cflags $pkgs)"
libs="$(pkg-config --libs $pkgs) -lz -lm -lrt -lpthread"

for t in $targets; do
	src="$root/test/fuzz/fuzz_$t.c"
	[[ -f "$src" ]] || continue
	echo "=== building fuzz_$t"
	# shellcheck disable=SC2086
	$CC $CFLAGS $inc -DFUZZING $feature_cflags \
		"$src" "$root/test/util.c" "$root/test/stub.c" \
		"$lib" $libs $LIB_FUZZING_ENGINE \
		-Wl,-rpath,'$ORIGIN/lib' \
		-o "$OUT/fuzz_$t"
done

# ---------------------------------------------------------------------------
# The runner image is not the builder image: cjose, jansson, apr, apr-util,
# curl, openssl and pcre2 come from build-time distro packages that do not exist
# there, and a target that dynamically links them dies with "error while loading
# shared libraries" -- which is what check_build reports as a broken build. Ship
# them next to the binaries; the rpath above resolves them relative to $OUT.
# ---------------------------------------------------------------------------
mkdir -p "$OUT/lib"
for t in $targets; do
	[[ -f "$OUT/fuzz_$t" ]] || continue
	ldd "$OUT/fuzz_$t" | awk '/=> \//{print $3}'
done | sort -u | grep -vE '/(libc|libm|libdl|librt|libpthread|libstdc\+\+|libgcc_s|ld-linux)[.-]' \
     | while read -r so; do cp -n "$so" "$OUT/lib/" 2>/dev/null || true; done

# ---------------------------------------------------------------------------
# seed corpora and dictionaries
#
# fuzz_url additionally gets the curated open-redirect payload list, one input
# per file -- the same 834 payloads test_handle.c asserts are all rejected.
# ---------------------------------------------------------------------------
for t in $targets; do
	seed="$WORK/seed_$t"
	rm -rf "$seed" && mkdir -p "$seed"
	cp "$root"/test/fuzz/corpus/"$t"/* "$seed"/ 2>/dev/null || true
	if [[ "$t" = "url" ]]; then
		i=0
		while IFS= read -r line; do
			printf '%s' "$line" > "$seed/payload-$i"
			i=$((i + 1))
		done < "$root/test/open-redirect-payload-list.txt"
	fi
	(cd "$seed" && zip -qr "$OUT/fuzz_${t}_seed_corpus.zip" .)
done

for d in "$root"/test/fuzz/dict/*.dict; do
	[[ -f "$d" ]] && cp "$d" "$OUT/fuzz_$(basename "$d" .dict).dict"
done

echo "built: $(ls "$OUT"/fuzz_* | tr '\n' ' ')"
