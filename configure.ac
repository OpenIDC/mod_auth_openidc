AC_INIT([mod_auth_openidc],[3.0.0-dev],[hans.zandbelt@zmartzone.eu])

AM_INIT_AUTOMAKE([foreign no-define subdir-objects])
AC_CONFIG_MACRO_DIRS([m4])

LT_INIT([dlopen])
AC_PROG_CC

AX_CODE_COVERAGE


AC_ARG_WITH([apxs2], AS_HELP_STRING([--with-apxs2=PATH], [full path to the apxs2 executable]), [ APXS2=${withval} ],)
if test "x$APXS2" = "x"; then
	AC_PATH_PROG(APXS2, apxs2,, /usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin)
	if test "x$APXS2" = "x"; then
		AC_PATH_PROG(APXS2, apxs,, /usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin)
	fi
fi
if test ! -x "$APXS2"; then
   AC_MSG_ERROR([
Could not find apxs2. Please specify the path to apxs2
using the --with-apxs2=/full/path/to/apxs2 option.
The executable may also be named 'apxs'.
])
fi

AC_SUBST(APXS2)
AC_ARG_VAR(APXS2_OPTS, [additional command line options to pass to apxs2])


PKG_CHECK_MODULES(APR, [apr-1, apr-util-1])
AC_SUBST(APR_CFLAGS)
AC_SUBST(APR_LIBS)

PKG_CHECK_MODULES(OAUTH2, [liboauth2 >= 1.4.0])
AC_SUBST(OAUTH2_CFLAGS)
AC_SUBST(OAUTH2_LIBS)

PKG_CHECK_MODULES(OAUTH2_APACHE, [liboauth2_apache >= 1.4.0])
AC_SUBST(OAUTH2_APACHE_CFLAGS)
AC_SUBST(OAUTH2_APACHE_LIBS)

# Create Makefile from Makefile.in
AC_CONFIG_FILES([
	Makefile
])
AC_OUTPUT
