ACLOCAL_AMFLAGS=-I m4

SUBDIRS = src test

EXTRA_DIST = \
	README.md \
	ChangeLog \
	INSTALL \
	AUTHORS \
	LICENSE.txt \
	auth_openidc.conf

clang-format:
	clang-format -style=file -i $$(find . -maxdepth 3 -name \*\.[ch])

valgrind: check
	${MAKE} -C test $@

# NB: deliberately no "check" prerequisite here, unlike the valgrind target above: the
# AX_CODE_COVERAGE recipe in test/ runs the suite itself ("-make -k check"), so depending
# on check as well ran every test twice per coverage job. Depending on "all" instead is
# enough to have src/libauth_openidc.la in place for the test link.
# NB: test/coverage-check, not test/check-code-coverage: the latter is AX_CODE_COVERAGE's own
# recipe, which ignores a failing suite. See the comment on that target in test/Makefile.am.
check-code-coverage: all
	${MAKE} -C test coverage-check
