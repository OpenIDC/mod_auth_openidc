AC_INIT([mod_oauth2],[3.2.2],[hans.zandbelt@zmartzone.eu])

AM_INIT_AUTOMAKE([foreign no-define subdir-objects])
AC_CONFIG_MACRO_DIRS([m4])

LT_INIT([dlopen])
AC_PROG_CC

AX_CODE_COVERAGE

AC_ARG_WITH([apache], AS_HELP_STRING([--with-apache], [build with Apache support [default=autodetect]]),)
AC_ARG_WITH([apxs],
    [AS_HELP_STRING([--with-apxs=PATH/NAME],[path to the apxs binary for Apache [[apxs]]])],
    [AC_SUBST(APXS, $with_apxs)],
    [AC_PATH_PROGS(APXS, [apxs2 apxs])])
if test "x$with_apache" != "xno"; then
	PKG_CHECK_MODULES([APR], [apr-1, apr-util-1], [have_apache="yes"], [have_apache="no"])

	AS_IF([test "x${APXS}" != "x" -a -x "${APXS}"],
	      [AC_MSG_NOTICE([apxs found at $APXS])],
	      [AC_MSG_FAILURE(["apxs not found. Use --with-apxs"])])

	APACHE_CFLAGS="`${APXS} -q CFLAGS` `${APXS} -q EXTRA_CPPFLAGS` -I`${APXS} -q INCLUDEDIR` ${APR_CFLAGS}"
fi
AM_CONDITIONAL(HAVE_APACHE, [test x"$have_apache" = "xyes"])
AC_SUBST(APR_LIBS)
AC_SUBST(APACHE_CFLAGS)
AC_ARG_VAR(APXS_OPTS, [additional command line options to pass to apxs])

PKG_CHECK_MODULES(OAUTH2, [liboauth2 >= 1.4.2.1])
AC_SUBST(OAUTH2_CFLAGS)
AC_SUBST(OAUTH2_LIBS)

PKG_CHECK_MODULES(OAUTH2_APACHE, [liboauth2_apache >= 1.4.2.1])
AC_SUBST(OAUTH2_APACHE_CFLAGS)
AC_SUBST(OAUTH2_APACHE_LIBS)

# Create Makefile from Makefile.in
AC_CONFIG_FILES([
	Makefile
])
AC_OUTPUT
