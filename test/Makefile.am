AM_CFLAGS = -I${top_srcdir}/src @APACHE_CFLAGS@ @OPENSSL_CFLAGS@ @CURL_CFLAGS@ @JANSSON_CFLAGS@ @CJOSE_CFLAGS@ @PCRE_CFLAGS@
AM_CPPFLAGS = @APACHE_CPPFLAGS@
AM_LDFLAGS = --coverage @APACHE_LDFLAGS@
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

noinst_HEADERS = helper.h

LDADD = ${top_builddir}/src/libauth_openidc.la ${LIBADD}

noinst_PROGRAMS = test-cmd
test_cmd_SOURCES = test-cmd.c stub.c
test_cmd_CFLAGS = ${AM_CFLAGS} -fPIC

TESTS = test

test_SOURCES = test.c stub.c
test_CFLAGS = ${AM_CFLAGS} -fPIC

if HAVE_CHECK

TESTS += test_jose
test_jose_CFLAGS = @CHECK_CFLAGS@ ${AM_CFLAGS}
test_jose_LDADD = @CHECK_LIBS@ ${LDADD}
test_jose_SOURCES = test_jose.c helper.c stub.c

TESTS += test_util
test_util_CFLAGS = @CHECK_CFLAGS@ ${AM_CFLAGS}
test_util_LDADD = @CHECK_LIBS@ ${LDADD}
test_util_SOURCES = test_util.c helper.c stub.c

TESTS += test_cfg
test_cfg_CFLAGS = @CHECK_CFLAGS@ ${AM_CFLAGS}
test_cfg_LDADD = @CHECK_LIBS@ ${LDADD}
test_cfg_SOURCES = test_cfg.c helper.c stub.c

endif

check_PROGRAMS = $(TESTS)

EXTRA_DIST = \
	ecpriv.key \
	eccert.pem \
	private.pem \
	public.pem \
	certificate.pem \
	open-redirect-payload-list.txt

clean-local:
	rm -f *.gcno

${TESTS:%=%.valgrind}: ${TESTS}
	CK_FORK=no valgrind --error-exitcode=1 --show-leak-kinds=definite --read-inline-info=yes --keep-debuginfo=yes ./$$(basename $@ .valgrind)

valgrind: ${TESTS:%=%.valgrind}

CODE_COVERAGE_LCOV_SHOPTS = --ignore-errors inconsistent --ignore-errors unused

@CODE_COVERAGE_RULES@
