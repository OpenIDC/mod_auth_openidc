AM_CFLAGS = $(CODE_COVERAGE_CFLAGS) -DNAMEVER="@NAMEVER@" @APACHE_CFLAGS@ @OPENSSL_CFLAGS@ @CURL_CFLAGS@ @JANSSON_CFLAGS@ @CJOSE_CFLAGS@ @PCRE_CFLAGS@
AM_CPPFLAGS = $(CODE_COVERAGE_CPPFLAGS)  @APACHE_CPPFLAGS@
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

noinst_LTLIBRARIES = libauth_openidc.la

libauth_openidc_la_SOURCES = \
	mod_auth_openidc.c \
	state.c \
	cfg/cfg.c \
	cfg/cache.c \
	cfg/provider.c \
	cfg/oauth.c \
	cfg/dir.c \
	cfg/parse.c \
	cfg/cmds.c \
	cache/file.c \
	cache/shm.c \
	cache/common.c \
	handle/authz.c \
	handle/content.c \
	handle/discovery.c \
	handle/dpop.c \
	handle/info.c \
	handle/jwks.c \
	handle/logout.c \
	handle/refresh.c	\
	handle/request_uri.c \
	handle/request.c \
	handle/response.c \
	handle/revoke.c \
	handle/session_management.c \
	handle/userinfo.c \
	proto/auth.c \
	proto/discovery.c \
	proto/dpop.c \
	proto/id_token.c \
	proto/jwks.c \
	proto/jwt.c \
	proto/pkce.c \
	proto/profile.c \
	proto/proto.c \
	proto/request.c \
	proto/response.c \
	proto/state.c \
	proto/token.c \
	proto/userinfo.c \
	util/appinfo.c \
	util/base64.c \
	util/expr.c \
	util/file.c \
	util/html.c \
	util/jq.c \
	util/json.c \
	util/jwt.c \
	util/key.c \
	util/pcre_subst.c \
	util/random.c \
	util/url.c \
	util/util.c \
	metrics.c \
	oauth.c \
	http.c \
	session.c \
	metadata.c \
	jose.c

if HAVE_LIBHIREDIS
libauth_openidc_la_SOURCES += \
	cache/redis.c
endif

if HAVE_MEMCACHE
libauth_openidc_la_SOURCES += \
	cache/memcache.c
endif

noinst_HEADERS = \
	cfg/cfg.h \
	cfg/cfg_int.h \
	cfg/cache.h \
	cfg/provider.h \
	cfg/oauth.h \
	cfg/dir.h \
	cfg/parse.h \
	mod_auth_openidc.h \
	state.h \
	handle/handle.h \
	proto/proto.h \
	cache/cache.h \
	util/util.h \
	util/pcre_subst.h \
	oauth.h \
	metadata.h \
	session.h \
	jose.h \
	http.h \
	metrics.h \
	const.h

if HAVE_LIBHIREDIS
noinst_HEADERS += \
	cache/redis.h
endif

noinst_DATA = mod_auth_openidc.la

mod_auth_openidc.la: libauth_openidc.la
	${APXS} -c -o $@ libauth_openidc.la ${AM_CFLAGS} ${LIBADD}

install-exec-local:
	${INSTALL} -d $(DESTDIR)@APACHE_MODULEDIR@
	${INSTALL} -p -m 755 .libs/mod_auth_openidc.so $(DESTDIR)@APACHE_MODULEDIR@/mod_auth_openidc.so

uninstall-local:
	rm -f $(DESTDIR)@APACHE_MODULEDIR@/mod_auth_openidc.so mod_auth_openidc.la

clean-local:
	rm -f mod_auth_openidc.la *.gcno */*.gcno
