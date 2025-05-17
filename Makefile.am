ACLOCAL_AMFLAGS=-I m4

noinst_LTLIBRARIES = libauth_openidc.la

libauth_openidc_la_SOURCES = \
	src/mod_auth_openidc.c \
	src/state.c \
	src/cfg/cfg.c \
	src/cfg/cache.c \
	src/cfg/provider.c \
	src/cfg/oauth.c \
	src/cfg/dir.c \
	src/cfg/parse.c \
	src/cfg/cmds.c \
	src/cache/file.c \
	src/cache/shm.c \
	src/cache/common.c \
	src/handle/authz.c \
	src/handle/content.c \
	src/handle/discovery.c \
	src/handle/dpop.c \
	src/handle/info.c \
	src/handle/jwks.c \
	src/handle/logout.c \
	src/handle/refresh.c	\
	src/handle/request_uri.c \
	src/handle/request.c \
	src/handle/response.c \
	src/handle/revoke.c \
	src/handle/session_management.c \
	src/handle/userinfo.c \
	src/proto/auth.c \
	src/proto/discovery.c \
	src/proto/dpop.c \
	src/proto/id_token.c \
	src/proto/jwks.c \
	src/proto/jwt.c \
	src/proto/pkce.c \
	src/proto/profile.c \
	src/proto/proto.c \
	src/proto/request.c \
	src/proto/response.c \
	src/proto/state.c \
	src/proto/token.c \
	src/proto/userinfo.c \
	src/util/base64.c \
	src/util/expr.c \
	src/util/html.c \
	src/util/jq.c \
	src/util/json.c \
	src/util/jwt.c \
	src/util/key.c \
	src/util/pcre_subst.c \
	src/util/random.c \
	src/util/url.c \
	src/util/util.c \
	src/metrics.c \
	src/oauth.c \
	src/http.c \
	src/session.c \
	src/metadata.c \
	src/jose.c

AM_CFLAGS = -DNAMEVER="@NAMEVER@" -I${top_srcdir}/src @APACHE_CFLAGS@ @OPENSSL_CFLAGS@ @CURL_CFLAGS@ @JANSSON_CFLAGS@ @CJOSE_CFLAGS@ @PCRE_CFLAGS@
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
	src/cfg/cfg.h \
	src/cfg/cfg_int.h \
	src/cfg/cache.h \
	src/cfg/provider.h \
	src/cfg/oauth.h \
	src/cfg/dir.h \
	src/cfg/parse.h \
	src/mod_auth_openidc.h \
	src/state.h \
	src/handle/handle.h \
	src/proto/proto.h \
	src/cache/cache.h \
	src/util/util.h \
	src/util/pcre_subst.h \
	src/oauth.h \
	src/metadata.h \
	src/session.h \
	src/jose.h \
	src/http.h \
	src/metrics.h \
	src/const.h

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

clean-local:
	rm -f mod_auth_openidc.la

LDADD = libauth_openidc.la ${LIBADD}

noinst_PROGRAMS = test/test-cmd
test_test_cmd_SOURCES = test/test-cmd.c test/stub.c
test_test_cmd_CFLAGS = ${AM_CFLAGS} -fPIC

TESTS = test/test

check_PROGRAMS = test/test
test_test_SOURCES = test/test.c test/stub.c
test_test_CFLAGS = ${AM_CFLAGS} -fPIC

clang-format:
	clang-format -style=file -i $$(find . -name *.[ch] -maxdepth 3)
