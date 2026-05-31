AM_CFLAGS = -I${top_srcdir}/src @APACHE_CFLAGS@ @OPENSSL_CFLAGS@ @CURL_CFLAGS@ @JANSSON_CFLAGS@ @CJOSE_CFLAGS@ @PCRE_CFLAGS@
AM_CPPFLAGS = @APACHE_CPPFLAGS@
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
	http_server.h

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

check_PROGRAMS = \
	test_cfg \
	test_util \
	test_jose \
	test_http \
	test_cache \
	test_proto \
	test_handle \
	test_oauth \
	test_metadata \
	test_metrics

# the compiled libcheck binaries, plus a source-level guard that fails the
# build if a START_TEST body is never wired into a suite with tcase_add_test
# (such a test compiles but silently never runs); see check_registration.sh
TESTS = $(check_PROGRAMS) check_registration.sh

endif

# TEST_EXTENSIONS is read at automake time and so must be unconditional; the
# .sh handler drives check_registration.sh, the only non-program in TESTS.
TEST_EXTENSIONS = .sh
SH_LOG_COMPILER = $(SHELL)
dist_check_SCRIPTS = check_registration.sh

EXTRA_DIST = \
	ecpriv.key \
	eccert.pem \
	private.pem \
	public.pem \
	certificate.pem \
	open-redirect-payload-list.txt \
	post_preserve.template \
	post_restore.template

clean-local:
	rm -f *.gcno

${check_PROGRAMS:%=%.valgrind}: ${check_PROGRAMS}
	CK_FORK=no valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=definite --errors-for-leak-kinds=definite --read-inline-info=yes --keep-debuginfo=yes ./$$(basename $@ .valgrind)

valgrind: ${check_PROGRAMS:%=%.valgrind}

CODE_COVERAGE_LCOV_SHOPTS = --ignore-errors inconsistent --ignore-errors unused

@CODE_COVERAGE_RULES@
