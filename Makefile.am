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
	@# Drop coverage data left behind for sources that are no longer in this tree. Switching the
	@# checkout between branches whose file lists differ -- enterprise carries src/license.c,
	@# master does not -- strands a .gcda/.gcno pair whose source is gone, and lcov aborts the
	@# whole capture on it ("unable to open .../src/license.c: No such file or directory") rather
	@# than skipping the one file. Pruning beats --ignore-errors source: the stale data is wrong
	@# rather than merely unreadable, and keeping it would fold another branch's runs into this
	@# branch's numbers.
	@# libtool puts the objects under <dir>/.libs/, a plain build leaves them in <dir>, so the
	@# source of <dir>/.libs/x.gcda is <dir>/x.c while the source of <dir>/x.gcno is <dir>/x.c
	@# too: only prune when NEITHER candidate exists, or the .gcno of every non-libtool object
	@# gets deleted along with the genuinely orphaned ones.
	@find src \( -name '*.gcda' -o -name '*.gcno' \) -print | while read -r f ; do \
		b=`basename $${f%.*}`.c ; d=`dirname $$f` ; \
		if [ ! -f "$$d/$$b" ] && [ ! -f "`dirname $$d`/$$b" ] ; then \
			echo "pruning orphaned coverage data: $$f (no source for $$b)" ; \
			rm -f "$$f" ; \
		fi ; \
	done
	${MAKE} -C test coverage-check
