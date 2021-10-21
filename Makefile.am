ACLOCAL_AMFLAGS=-I m4

noinst_LTLIBRARIES = mod_auth_openidc.la

mod_auth_openidc_la_SOURCES = \
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

mod_auth_openidc_la_CFLAGS = -DNAMEVER=\"@NAMEVER@\" -I$(top_srcdir)/src @APACHE_CFLAGS@ @OPENSSL_CFLAGS@ @CURL_CFLAGS@ @JANSSON_CFLAGS@ @CJOSE_CFLAGS@ @PCRE_CFLAGS@
mod_auth_openidc_la_CPPFLAGS = @APACHE_CPPFLAGS@
# -rpath is needed to create shared libraries whilst specifying noinst_LTLIBRARIES
mod_auth_openidc_la_LDFLAGS = -avoid-version -module -rpath @APACHE_MODULEDIR@ @APACHE_LDFLAGS@
mod_auth_openidc_la_LIBADD = @APACHE_LIBS@ @OPENSSL_LIBS@ @CURL_LIBS@ @JANSSON_LIBS@ @CJOSE_LIBS@ @PCRE_LIBS@

if HAVE_LIBHIREDIS
mod_auth_openidc_la_SOURCES += \
	src/cache/redis.c
mod_auth_openidc_la_CFLAGS += -DUSE_LIBHIREDIS @HIREDIS_CFLAGS@
mod_auth_openidc_la_LIBADD += @HIREDIS_LIBS@
endif

if HAVE_MEMCACHE
mod_auth_openidc_la_CFLAGS += -DUSE_MEMCACHE
mod_auth_openidc_la_SOURCES += \
	src/cache/memcache.c
endif

if HAVE_LIBJQ
mod_auth_openidc_la_CFLAGS += -DUSE_LIBJQ @JQ_CFLAGS@
mod_auth_openidc_la_LIBADD += @JQ_LIBS@
endif

noinst_HEADERS = \
	src/mod_auth_openidc.h \
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
	test/public.pem \
	test/certificate.pem

noinst_PROGRAMS = test/test-cmd

check_PROGRAMS = test/test
TESTS = test/test

test_test_SOURCES = test/test.c test/stub.c
test_test_CFLAGS = ${mod_auth_openidc_la_CFLAGS}
test_test_LDFLAGS = @APACHE_LDFLAGS@
test_test_LDADD = mod_auth_openidc.la ${mod_auth_openidc_la_LIBADD}

test_test_cmd_SOURCES = test/test-cmd.c test/stub.c
test_test_cmd_CFLAGS = ${mod_auth_openidc_la_CFLAGS}
test_test_cmd_LDFLAGS = @APACHE_LDFLAGS@
test_test_cmd_LDADD = mod_auth_openidc.la ${mod_auth_openidc_la_LIBADD}

install-exec-local: ${noinst_LTLIBRARIES}
	@APXS@ -i -n mod_auth_openidc mod_auth_openidc.la
#	${INSTALL} -p -m 755 -D .libs/mod_auth_openidc.so @APACHE_MODULEDIR@/mod_auth_openidc.so

docker: docker-build docker-run

docker-build:
	docker build -t mod_auth_openidc .

docker-run:
	docker run -p 80:80 -p 443:443 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it mod_auth_openidc /bin/bash -c "/root/run.sh"
