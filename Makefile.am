ACLOCAL_AMFLAGS=-I m4

noinst_LTLIBRARIES = libauth_openidc.la

libauth_openidc_la_SOURCES = \
	src/mod_auth_openidc.c \
	src/cache/file.c \
	src/cache/shm.c \
	src/cache/common.c \
	src/oauth.c \
	src/proto.c \
	src/config.c \
	src/util.c \
	src/authz.c \
	src/session.c \
	src/metadata.c \
	src/jose.c \
	src/parse.c \
	src/pcre_subst.c

AM_CFLAGS = -DNAMEVER="@NAMEVER@" -I$(top_srcdir)/src @APACHE_CFLAGS@ @OPENSSL_CFLAGS@ @CURL_CFLAGS@ @JANSSON_CFLAGS@ @CJOSE_CFLAGS@ @PCRE_CFLAGS@
AM_CPPFLAGS = @APACHE_CPPFLAGS@
AM_LDFLAGS = @APACHE_LDFLAGS@
LIBADD = @APACHE_LIBS@ @OPENSSL_LIBS@ @CURL_LIBS@ @JANSSON_LIBS@ @CJOSE_LIBS@ @PCRE_LIBS@

if HAVE_LIBHIREDIS
libauth_openidc_la_SOURCES += \
	src/cache/redis.c
AM_CFLAGS += -DUSE_LIBHIREDIS @HIREDIS_CFLAGS@
LIBADD += @HIREDIS_LIBS@
endif

if HAVE_MEMCACHE
AM_CFLAGS += -DUSE_MEMCACHE
libauth_openidc_la_SOURCES += \
	src/cache/memcache.c
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
	src/mod_auth_openidc.h \
	src/const.h \
	src/jose.h \
	src/parse.h \
	src/cache/cache.h \
	src/pcre_subst.h

if HAVE_LIBHIREDIS
noinst_HEADERS += \
	src/cache/redis.h
endif

EXTRA_DIST = \
	README.md \
	ChangeLog \
	INSTALL \
	AUTHORS \
	LICENSE.txt \
	auth_openidc.conf \
	test/ecpriv.key \
	test/eccert.pem \
	test/private.pem \
	test/public.pem \
	test/certificate.pem \
	test/open-redirect-payload-list.txt

noinst_DATA = mod_auth_openidc.la

mod_auth_openidc.la: libauth_openidc.la
	${APXS} -c -o $@ libauth_openidc.la ${AM_CFLAGS} ${LIBADD}

install-exec-local:
	${INSTALL} -d $(DESTDIR)@APACHE_MODULEDIR@
	${INSTALL} -p -m 755 .libs/mod_auth_openidc.so $(DESTDIR)@APACHE_MODULEDIR@/mod_auth_openidc.so

uninstall-local:
	rm -f $(DESTDIR)@APACHE_MODULEDIR@/mod_auth_openidc.so mod_auth_openidc.la

LDADD = libauth_openidc.la ${LIBADD}

noinst_PROGRAMS = test/test-cmd
test_test_cmd_SOURCES = test/test-cmd.c test/stub.c
test_test_cmd_CFLAGS = ${AM_CFLAGS} -fPIC

TESTS = test/test

check_PROGRAMS = test/test
test_test_SOURCES = test/test.c test/stub.c
test_test_CFLAGS = ${AM_CFLAGS} -fPIC
