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
prefix="$WORK/deps"
mkdir -p "$prefix"

# ---------------------------------------------------------------------------
# instrumented dependencies
#
# Only the libraries the targets actually parse through are built from source:
# jansson (fuzz_json, and every JOSE payload) and cjose (fuzz_jwt). apr,
# apr-util, openssl, curl and pcre2 come from the distro -- uninstrumented, so
# ASan still catches our own overflows but coverage stops at their boundary.
# Promoting those to source builds is the obvious next step if the coverage
# report shows the frontier sitting there.
# ---------------------------------------------------------------------------
build_dep() {
	name=$1
	shift
	echo "=== building $name"
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

build_dep jansson
build_dep cjose --with-jansson="$prefix"

# configure.ac locates cjose with PKG_CHECK_MODULES(CJOSE, cjose) -- there is no
# --with-cjose; the instrumented build is selected by putting its .pc first
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig:${PKG_CONFIG_PATH:-}"

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
export CFLAGS="$CFLAGS -fno-lto"

./autogen.sh
./configure \
	--with-apxs=/usr/bin/apxs \
	--without-jq --without-hiredis \
	--disable-shared
make -C src libauth_openidc.la -j"$(nproc)"

lib="$root/src/.libs/libauth_openidc.a"
[ -f "$lib" ] || { echo "error: $lib was not built" >&2; exit 1; }

# ---------------------------------------------------------------------------
# targets
#
# Same three-file link as test/fuzz/build.sh -- the target, the libcheck test
# fixture (a post-config'd request_rec + oidc_cfg_t) and the Apache server stubs
# -- with $LIB_FUZZING_ENGINE in place of -fsanitize=fuzzer so OSS-Fuzz can
# select the engine.
# ---------------------------------------------------------------------------
apache_inc=$(apxs -q INCLUDEDIR 2>/dev/null || echo /usr/include/apache2)
inc="-I$root/src -I$root/test -I$apache_inc -I$prefix/include \
     $(pkg-config --cflags apr-1 apr-util-1 libcrypto libssl libcurl libpcre2-8)"
libs="$prefix/lib/libcjose.a $prefix/lib/libjansson.a \
      $(pkg-config --libs apr-1 apr-util-1 libcrypto libssl libcurl libpcre2-8) \
      -lz -lm -lrt -lpthread"

for t in base64 url jwt json; do
	src="$root/test/fuzz/fuzz_$t.c"
	[ -f "$src" ] || continue
	echo "=== building fuzz_$t"
	# shellcheck disable=SC2086
	$CC $CFLAGS $inc -DFUZZING \
		"$src" "$root/test/util.c" "$root/test/stub.c" \
		"$lib" $libs $LIB_FUZZING_ENGINE \
		-Wl,-rpath,'$ORIGIN/lib' \
		-o "$OUT/fuzz_$t"
done

# ---------------------------------------------------------------------------
# The runner image is not the builder image: apr, apr-util, curl, openssl and
# pcre2 come from build-time distro packages that do not exist there, and a
# target that dynamically links them dies with "error while loading shared
# libraries" -- which is what check_build reports as a broken build. Ship them
# next to the binaries; the rpath above resolves them relative to $OUT.
#
# Building these from source as static libraries instead would drop the copy and
# instrument them at the same time; it is the better end state, and the reason
# this is worth doing first is that it is what makes check_build pass at all.
# ---------------------------------------------------------------------------
mkdir -p "$OUT/lib"
for t in base64 url jwt json; do
	[ -f "$OUT/fuzz_$t" ] || continue
	ldd "$OUT/fuzz_$t" | awk '/=> \//{print $3}'
done | sort -u | grep -vE '/(libc|libm|libdl|librt|libpthread|libstdc\+\+|libgcc_s|ld-linux)[.-]' \
     | while read -r so; do cp -n "$so" "$OUT/lib/" 2>/dev/null || true; done

# ---------------------------------------------------------------------------
# seed corpora and dictionaries
#
# fuzz_url additionally gets the curated open-redirect payload list, one input
# per file -- the same 834 payloads test_handle.c asserts are all rejected.
# ---------------------------------------------------------------------------
for t in base64 url jwt json; do
	seed="$WORK/seed_$t"
	rm -rf "$seed" && mkdir -p "$seed"
	cp "$root"/test/fuzz/corpus/"$t"/* "$seed"/ 2>/dev/null || true
	if [ "$t" = "url" ]; then
		i=0
		while IFS= read -r line; do
			printf '%s' "$line" > "$seed/payload-$i"
			i=$((i + 1))
		done < "$root/test/open-redirect-payload-list.txt"
	fi
	(cd "$seed" && zip -qr "$OUT/fuzz_${t}_seed_corpus.zip" .)
done

for d in "$root"/test/fuzz/dict/*.dict; do
	[ -f "$d" ] && cp "$d" "$OUT/fuzz_$(basename "$d" .dict).dict"
done

echo "built: $(ls "$OUT"/fuzz_* | tr '\n' ' ')"
