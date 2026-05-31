AM_CFLAGS = -I${top_srcdir}/src @APACHE_CFLAGS@ @OPENSSL_CFLAGS@ @CURL_CFLAGS@ @JANSSON_CFLAGS@ @CJOSE_CFLAGS@ @PCRE_CFLAGS@
# -I$(srcdir) lets the fuzz targets under fuzz/ include the test fixture "util.h"
AM_CPPFLAGS = @APACHE_CPPFLAGS@ -I$(srcdir)
AM_LDFLAGS = @APACHE_LDFLAGS@
if CODE_COVERAGE_ENABLED
AM_LDFLAGS += --coverage
endif
LIBADD = $(CODE_COVERAGE_LIBS) @APACHE_LIBS@ @OPENSSL_LIBS@ @CURL_LIBS@ @JANSSON_LIBS@ @CJOSE_LIBS@ @PCRE_LIBS@

if HAVE_LIBHIREDIS
AM_CFLAGS += -DUSE_LIBHIREDIS @HIREDIS_CFLAGS@
LIBADD += @HIREDIS_LIBS@
endif

if HAVE_MEMCACHE
AM_CFLAGS += -DUSE_MEMCACHE
endif

if HAVE_LIBJQ
AM_CFLAGS += -DUSE_LIBJQ @JQ_CFLAGS@
LIBADD += @JQ_LIBS@
endif

if HAVE_LIBBROTLI
AM_CFLAGS += -DUSE_LIBBROTLI @LIBBROTLIENC_CFLAGS@ @LIBBROTLIDEC_CFLAGS@
LIBADD += @LIBBROTLIENC_LIBS@ @LIBBROTLIDEC_LIBS@
endif

if HAVE_LIBZ
AM_CFLAGS += -DUSE_ZLIB @ZLIB_CFLAGS@
LIBADD += @ZLIB_LIBS@
endif

noinst_HEADERS = \
	util.h \
	check_util.h \
	http_server.h \
	fuzz/fuzz.h

LDADD = ${top_builddir}/src/libauth_openidc.la ${LIBADD}

noinst_PROGRAMS = test-cmd

test_cmd_SOURCES = \
	test-cmd.c \
	util.c \
	stub.c

if HAVE_CHECK

noinst_LTLIBRARIES = libtest.la

libtest_la_CFLAGS = ${AM_CFLAGS} -fPIC

libtest_la_SOURCES = \
	util.c \
	check_util.c \
	http_server.c \
	stub.c

AM_CFLAGS += @CHECK_CFLAGS@
LDADD += libtest.la @CHECK_LIBS@

oidc_unit_tests = \
	test_cfg \
	test_util \
	test_jose \
	test_http \
	test_cache \
	test_proto \
	test_handle \
	test_state \
	test_session \
	test_oauth \
	test_metadata \
	test_metrics

# fuzz targets: each pairs a libFuzzer entry point (fuzz/fuzz_*.c) with the
# standalone corpus-replay driver (fuzz/standalone.c) so it builds with the
# ordinary toolchain. They are built here but not listed in TESTS directly --
# they need corpus paths as arguments, so fuzz/run-fuzzers.sh drives them.
# Real fuzzing is a separate clang/libFuzzer build; see fuzz/build.sh.
oidc_fuzz_targets = \
	fuzz_base64 \
	fuzz_url \
	fuzz_jwt \
	fuzz_json

fuzz_base64_SOURCES = fuzz/fuzz_base64.c fuzz/standalone.c
fuzz_url_SOURCES = fuzz/fuzz_url.c fuzz/standalone.c
fuzz_jwt_SOURCES = fuzz/fuzz_jwt.c fuzz/standalone.c
fuzz_json_SOURCES = fuzz/fuzz_json.c fuzz/standalone.c

check_PROGRAMS = $(oidc_unit_tests) $(oidc_fuzz_targets)

# the libcheck binaries plus two source/corpus guards: check_registration.sh
# (every START_TEST body is wired into a suite) and fuzz/run-fuzzers.sh (the
# fuzz targets survive their seed corpora). The fuzz binaries themselves are
# driven by that script, not run directly.
TESTS = $(oidc_unit_tests) check_registration.sh fuzz/run-fuzzers.sh

endif

# TEST_EXTENSIONS is read at automake time and so must be unconditional; the
# .sh handler drives check_registration.sh, the only non-program in TESTS.
TEST_EXTENSIONS = .sh
SH_LOG_COMPILER = $(SHELL)
dist_check_SCRIPTS = check_registration.sh fuzz/run-fuzzers.sh

EXTRA_DIST = \
	ecpriv.key \
	eccert.pem \
	private.pem \
	public.pem \
	certificate.pem \
	open-redirect-payload-list.txt \
	post_preserve.template \
	post_restore.template \
	fuzz/corpus \
	fuzz/build.sh \
	fuzz/README.md

clean-local:
	rm -f *.gcno

${oidc_unit_tests:%=%.valgrind}: ${oidc_unit_tests}
	CK_FORK=no valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=definite --errors-for-leak-kinds=definite --read-inline-info=yes --keep-debuginfo=yes ./$$(basename $@ .valgrind)

valgrind: ${oidc_unit_tests:%=%.valgrind}

CODE_COVERAGE_LCOV_SHOPTS = --ignore-errors inconsistent --ignore-errors unused

@CODE_COVERAGE_RULES@
