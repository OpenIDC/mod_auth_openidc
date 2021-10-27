AC_INIT([mod_auth_openidc],[2.4.9.5rc7],[hans.zandbelt@zmartzone.eu])

AC_SUBST(NAMEVER, AC_PACKAGE_TARNAME()-AC_PACKAGE_VERSION())

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AM_PROG_AR
LT_INIT([dlopen])

# Checks for apxs.
AC_ARG_WITH([apxs],
            [--with-apxs=PATH],
            [APXS_PATH="$withval"],
            [APXS_PATH="/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/opt/local/bin:/usr/local/apache2/bin"])

AC_PATH_PROG(APXS, apxs, no, ${APXS_PATH})

AS_IF([test "x${APXS}" = "xno" ],
      [AC_MSG_ERROR([apxs not found])],
      [test "x${APXS}" = "x"],
      [AC_MSG_ERROR([apxs not found])])

APXS_CFLAGS=`${APXS} -q CFLAGS 2> /dev/null`
APXS_CPPFLAGS=`${APXS} -q CPPFLAGS 2> /dev/null`
APXS_LDFLAGS=`${APXS} -q LDFLAGS 2> /dev/null`
APXS_LIBS=`${APXS} -q LIBS 2> /dev/null`
APXS_LIBEXECDIR=`${APXS} -q LIBEXECDIR 2> /dev/null`
APXS_INCLUDEDIR=`${APXS} -q INCLUDEDIR 2> /dev/null`
APXS_INCLUDES="-I${APXS_INCLUDEDIR}"

PKG_CHECK_MODULES(APR, [apr-1, apr-util-1])

# Apache libraries.
APACHE_MODULEDIR="${APXS_LIBEXECDIR}"
APACHE_INCLUDES="${APXS_INCLUDES} ${APR_INCLUDES}"
APACHE_CFLAGS="${APXS_CFLAGS} ${APR_CFLAGS} ${APACHE_INCLUDES}"
APACHE_CPPFLAGS="${APXS_CPPFLAGS} ${APR_CPPFLAGS} ${APACHE_INCLUDES}"
APACHE_LDFLAGS="${APXS_LDFLAGS} ${APR_LDFLAGS}"
APACHE_LIBS="${APXS_LIBS} ${APR_LIBS}"

AC_SUBST(APACHE_MODULEDIR)
AC_SUBST(APACHE_INCLUDES)
AC_SUBST(APACHE_CFLAGS)
AC_SUBST(APACHE_CPPFLAGS)
AC_SUBST(APACHE_LDFLAGS)
AC_SUBST(APACHE_LIBS)

# We need the curl library for HTTP callouts.
PKG_CHECK_MODULES(CURL, libcurl)
AC_SUBST(CURL_CFLAGS)
AC_SUBST(CURL_LIBS)

# We need OpenSSL for crypto and HTTPS callouts.
PKG_CHECK_MODULES(OPENSSL, openssl)
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

# older versions of libapr may not have memcache support
old_CPPFLAGS=$CPPFLAGS
CPPFLAGS="${APACHE_CPPFLAGS} ${APACHE_CFLAGS} $CPPFLAGS"
AC_CHECK_HEADER([apr_memcache.h], [HAVE_MEMCACHE=1], [HAVE_MEMCACHE=0])
AM_CONDITIONAL(HAVE_MEMCACHE,[test x"$HAVE_MEMCACHE" = "x1"])
CPPFLAGS=$old_CPPFLAGS

# We need Jansson for JSON parsing.
PKG_CHECK_MODULES(JANSSON, jansson)
AC_SUBST(JANSSON_CFLAGS)
AC_SUBST(JANSSON_LIBS)

# cjose
PKG_CHECK_MODULES(CJOSE, cjose)
AC_SUBST(CJOSE_CFLAGS)
AC_SUBST(CJOSE_LIBS)

# PCRE
PKG_CHECK_MODULES(PCRE, libpcre)
AC_SUBST(PCRE_CFLAGS)
AC_SUBST(PCRE_LIBS)

# Redis
AC_ARG_WITH([hiredis],
  [AS_HELP_STRING([--with-hiredis],
    [support Redis @<:@default=check@:>@])],
  [],
  [with_hiredis=yes])
AS_CASE(["$with_hiredis"],
  [yes], [
  	if test "$HIREDIS_LIBS" == ""; then PKG_CHECK_MODULES([HIREDIS], [hiredis], [HAVE_LIBHIREDIS=1], [HAVE_LIBHIREDIS=0]) ; else [HAVE_LIBHIREDIS=1] ; fi
  ],
  [no], [HAVE_LIBHIREDIS=0],
  [PKG_CHECK_MODULES([HIREDIS], [hiredis], [HAVE_LIBHIREDIS=1], [HAVE_LIBHIREDIS=0])])
AM_CONDITIONAL(HAVE_LIBHIREDIS, [test x"$HAVE_LIBHIREDIS" = "x1"])
AC_SUBST(HIREDIS_CFLAGS)
AC_SUBST(HIREDIS_LIBS)

# JQ
HAVE_LIBJQ=0

AC_ARG_WITH([jq],
	AS_HELP_STRING([--with-jq=PATH], [location of your libjq installation])])

if test -n "$with_jq"
then
    JQ_CFLAGS="-I$with_jq/include"
    JQ_LIBS="-L$with_jq/lib -ljq"

	CPPFLAGS="$JQ_CFLAGS $CPPFLAGS"
	AC_CHECK_HEADER([jq.h], [HAVE_LIBJQ=1], [HAVE_LIBJQ=0])

	LDFLAGS="$JQ_LIBS $LDFLAGS"
	AC_CHECK_LIB([jq], [jq_init], [HAVE_LIBJQ=1], [HAVE_LIBJQ=0])
	if test "x$have_jq" = "x0" ; then
  		AC_MSG_WARN("cannot find library for -ljq.")
	fi
fi

AM_CONDITIONAL(HAVE_LIBJQ, [test x"$HAVE_LIBJQ" = "x1"])
AC_SUBST(JQ_CFLAGS)
AC_SUBST(JQ_LIBS)

# Create Makefile from Makefile.in
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
