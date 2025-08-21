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
	clang-format -style=file -i $$(find . -maxdepth 3 -name *.[ch])

valgrind check-code-coverage: check
	${MAKE} -C test $@
