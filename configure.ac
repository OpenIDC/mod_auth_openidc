AC_INIT([mod_auth_openidc],[2.1.1rc0],[hzandbelt@pingidentity.com])

AC_SUBST(NAMEVER, AC_PACKAGE_TARNAME()-AC_PACKAGE_VERSION())

# This section defines the --with-apxs2 option.
AC_ARG_WITH(
	[apxs2],
	[  --with-apxs2=PATH       Full path to the apxs2 executable.],
	[
		APXS2=${withval}
	],)


if test "x$APXS2" = "x"; then
   # The user didn't specify the --with-apxs2-option.

   # Search for apxs2 in the specified directories
   AC_PATH_PROG(APXS2, apxs2,,
		/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin)

   if test "x$APXS2" = "x"; then
      # Didn't find apxs2 in any of the specified directories.
      # Search for apxs instead.
      AC_PATH_PROG(APXS2, apxs,,
		   /usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin)
   fi

fi

# Test if $APXS2 exists and is an executable.
if test ! -x "$APXS2"; then
   # $APXS2 isn't a executable file.
   AC_MSG_ERROR([
Could not find apxs2. Please specify the path to apxs2
using the --with-apxs2=/full/path/to/apxs2 option.
The executable may also be named 'apxs'.
])
fi

# Replace any occurrences of @APXS2@ with the value of $APXS2 in the Makefile.
AC_SUBST(APXS2)

# Use environment varilable APXS2_OPTS to pass params to APXS2 command
AC_ARG_VAR(APXS2_OPTS, [Additional command line options to pass to apxs2.])

# We need the curl library for HTTP callouts.
PKG_CHECK_MODULES(CURL, libcurl)
AC_SUBST(CURL_CFLAGS)
AC_SUBST(CURL_LIBS)

# We need OpenSSL for crypto and HTTPS callouts.
PKG_CHECK_MODULES(OPENSSL, openssl)
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

PKG_CHECK_MODULES(APR, [apr-1, apr-util-1])
AC_SUBST(APR_CFLAGS)
AC_SUBST(APR_LIBS)

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
  [yes], [if test "$HIREDIS_LIBS" == ""; then PKG_CHECK_MODULES([HIREDIS], [hiredis], [HAVE_LIBHIREDIS=1], [HAVE_LIBHIREDIS=0]) ; else [HAVE_LIBHIREDIS=1] ; fi],
  [no], [HAVE_LIBHIREDIS=0],
  [PKG_CHECK_MODULES([HIREDIS], [hiredis], [HAVE_LIBHIREDIS=1], [HAVE_LIBHIREDIS=0])])
AC_SUBST(HAVE_LIBHIREDIS)
AC_SUBST(HIREDIS_CFLAGS)
AC_SUBST(HIREDIS_LIBS)

# Create Makefile from Makefile.in
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
