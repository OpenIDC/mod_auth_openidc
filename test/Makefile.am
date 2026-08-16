AM_CFLAGS = -I${top_srcdir}/src @APACHE_CFLAGS@ @OPENSSL_CFLAGS@ @CURL_CFLAGS@ @JANSSON_CFLAGS@ @CJOSE_CFLAGS@ @PCRE_CFLAGS@
# -I$(srcdir) lets the fuzz targets under fuzz/ include the test fixture "util.h"
AM_CPPFLAGS = @APACHE_CPPFLAGS@ -I$(srcdir)
AM_LDFLAGS = @APACHE_LDFLAGS@
if CODE_COVERAGE_ENABLED
AM_LDFLAGS += --coverage
endif
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

noinst_HEADERS = \
	util.h \
	check_util.h \
	http_server.h \
	fuzz/fuzz.h


noinst_PROGRAMS = test-cmd

test_cmd_SOURCES = \
	test-cmd.c \
	util.c \
	stub.c

if HAVE_CHECK

noinst_LTLIBRARIES = libtest.la libteststub.la

libtest_la_CFLAGS = ${AM_CFLAGS} -fPIC

libtest_la_SOURCES = \
	util.c \
	check_util.c \
	http_server.c

# the Apache stubs live apart from the fixture above: the fixture calls into the module, the stubs
# call nothing, and keeping them in one archive makes the test link cyclic (see LDADD below)
libteststub_la_CFLAGS = ${AM_CFLAGS} -fPIC
libteststub_la_SOURCES = stub.c

AM_CFLAGS += @CHECK_CFLAGS@

# Ordered so that every dependency points forward and one left-to-right scan suffices: the fixture
# (util.c) calls into the module, the module needs the Apache stubs, and the stubs need nothing.
# Holding the stubs in libtest.la instead made the two archives mutually dependent, which no single
# ordering can satisfy.
#
# That link used to succeed by accident: util/util.h pulled in cfg/cfg.h, so even util/base64.o
# referenced auth_openidc_module, and that spurious edge dragged the module out of
# libauth_openidc.a before libtest.a was reached. Dropping that coupling reverses the pull order
# and breaks the link; this ordering does not depend on it either way.
LDADD = libtest.la ${top_builddir}/src/libauth_openidc.la libteststub.la ${LIBADD} @CHECK_LIBS@

oidc_unit_tests = \
	test_cfg \
	test_config \
	test_util \
	test_jose \
	test_http \
	test_cache \
	test_proto \
	test_handle \
	test_state \
	test_session \
	test_oauth \
	test_metadata \
	test_metrics

# fuzz targets: each pairs a libFuzzer entry point (fuzz/fuzz_*.c) with the
# standalone corpus-replay driver (fuzz/standalone.c) so it builds with the
# ordinary toolchain. They are built here but not listed in TESTS directly --
# they need corpus paths as arguments, so fuzz/run-fuzzers.sh drives them.
# Real fuzzing is a separate clang/libFuzzer build; see fuzz/build.sh.
oidc_fuzz_targets = \
	fuzz_base64 \
	fuzz_url \
	fuzz_jwt \
	fuzz_json \
	fuzz_cookie \
	fuzz_response_header \
	fuzz_form_params \
	fuzz_metadata \
	fuzz_state_cookie

fuzz_base64_SOURCES = fuzz/fuzz_base64.c fuzz/standalone.c
fuzz_url_SOURCES = fuzz/fuzz_url.c fuzz/standalone.c
fuzz_jwt_SOURCES = fuzz/fuzz_jwt.c fuzz/standalone.c
fuzz_json_SOURCES = fuzz/fuzz_json.c fuzz/standalone.c
fuzz_cookie_SOURCES = fuzz/fuzz_cookie.c fuzz/standalone.c
fuzz_response_header_SOURCES = fuzz/fuzz_response_header.c fuzz/standalone.c
fuzz_form_params_SOURCES = fuzz/fuzz_form_params.c fuzz/standalone.c
fuzz_metadata_SOURCES = fuzz/fuzz_metadata.c fuzz/standalone.c
fuzz_state_cookie_SOURCES = fuzz/fuzz_state_cookie.c fuzz/standalone.c

check_PROGRAMS = $(oidc_unit_tests) $(oidc_fuzz_targets)

# the libcheck binaries plus four source guards: check_registration.sh (every
# START_TEST body is wired into a suite), check_directives.sh (every
# oidc_dir_cfg_t member is initialized and merged), check_conf_reference.sh
# (auth_openidc.conf still matches the directives and metrics classes the code
# defines) and fuzz/run-fuzzers.sh (the fuzz targets survive their seed
# corpora). The fuzz binaries themselves are driven by that script, not run
# directly.
TESTS = $(oidc_unit_tests) check_registration.sh check_directives.sh check_conf_reference.sh fuzz/run-fuzzers.sh


else

# without libcheck only test-cmd is built, and it compiles stub.c into itself
LDADD = ${top_builddir}/src/libauth_openidc.la ${LIBADD}

endif

# TEST_EXTENSIONS is read at automake time and so must be unconditional; the
# .sh handler drives the script-based tests, the non-programs in TESTS.
TEST_EXTENSIONS = .sh
SH_LOG_COMPILER = $(SHELL)

# libcheck aborts a test that outruns its per-test timeout, which defaults to 4 seconds. That is
# ample on an idle machine and not ample at all inside a distro package build: the SUSE spec runs
# "make check %{?_smp_mflags}", so suites run concurrently on a builder that is already compiling,
# and the PBKDF2 derivation in test_util_jwt_passphrase_rotation outran it on sles12 during the
# 2.4.20.2 release matrix. It surfaced as "(after this point) Test timeout expired" -- a red build
# from a slow machine, not from a wrong result, and it took the other nine licensed targets of
# that flavour down with it because make stops scheduling after a failure.
#
# Raise the default so a loaded builder does not manufacture failures, while keeping a ceiling low
# enough to still catch a genuine hang. CK_DEFAULT_TIMEOUT is honoured by every libcheck the
# supported distros ship, including the 0.9.x on el7 and sles12, and it applies only in fork mode,
# so the CK_FORK=no valgrind runs are unaffected. A value already in the environment wins, so CI
# or a developer can still tighten it for a single run.
# NB: the "export" is load-bearing. am__check_pre ends with $(AM_TESTS_ENVIRONMENT) followed by
# the log driver, so a bare "VAR=value;" is a shell assignment the test binary never inherits.
AM_TESTS_ENVIRONMENT = CK_DEFAULT_TIMEOUT=$${CK_DEFAULT_TIMEOUT:-60}; export CK_DEFAULT_TIMEOUT;
dist_check_SCRIPTS = check_registration.sh check_directives.sh check_conf_reference.sh fuzz/run-fuzzers.sh

EXTRA_DIST = \
	ecpriv.key \
	eccert.pem \
	private.pem \
	public.pem \
	certificate.pem \
	open-redirect-payload-list.txt \
	post_preserve.template \
	post_restore.template \
	fuzz/corpus \
	fuzz/dict \
	fuzz/build.sh \
	fuzz/oss-fuzz-build.sh \
	fuzz/README.md

clean-local:
	rm -f *.gcno

${oidc_unit_tests:%=%.valgrind}: ${oidc_unit_tests}
	CK_FORK=no valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=definite --errors-for-leak-kinds=definite --read-inline-info=yes --keep-debuginfo=yes ./$$(basename $@ .valgrind)

valgrind: ${oidc_unit_tests:%=%.valgrind}

# branch coverage on top of line coverage: a line that ran still hides the leg of its
# condition that never did, and those are exactly the cases unit tests miss. NB: the
# AX_CODE_COVERAGE default derives the branch flags from CODE_COVERAGE_BRANCH_COVERAGE
# into these two variables, so setting that alone would have no effect here -- both are
# overridden below and have to carry the --rc themselves. "branch_coverage" is the lcov 2
# spelling; the older "lcov_branch_coverage"/"genhtml_branch_coverage" still work but warn.
CODE_COVERAGE_BRANCH_COVERAGE = 1
# NB: genhtml needs the same "inconsistent" tolerance as lcov above, and needs it more: it
# treats what lcov reports as a warning ("line is hit but no branches on line have been
# evaluated", which the -flto fat objects produce for a handful of lines) as a fatal error
# and refuses to write the report at all.
CODE_COVERAGE_LCOV_SHOPTS = --ignore-errors inconsistent --ignore-errors unused --rc branch_coverage=1
CODE_COVERAGE_GENHTML_OPTIONS = --ignore-errors inconsistent --rc branch_coverage=1

# the live redis/memcache integration tcases (test_cache.c) register only when
# these are set, so the default "make check" leaves them off. The coverage and
# valgrind runs turn them on so the real cache/redis.c + cache/memcache.c ops --
# which the mock-based tests bypass -- get exercised (and leak-checked under
# valgrind). Defaults assume servers on the loopback (e.g. the CI service
# containers); override via the environment to point elsewhere.
check-code-coverage: export OIDC_TEST_REDIS_SERVER ?= localhost:6379
check-code-coverage: export OIDC_TEST_MEMCACHE_SERVER ?= localhost:11211
coverage-check: export OIDC_TEST_REDIS_SERVER ?= localhost:6379
coverage-check: export OIDC_TEST_MEMCACHE_SERVER ?= localhost:11211
valgrind: export OIDC_TEST_REDIS_SERVER ?= localhost:6379
valgrind: export OIDC_TEST_MEMCACHE_SERVER ?= localhost:11211

# AX_CODE_COVERAGE's own check-code-coverage recipe runs the suite as "-$(MAKE) -k check": the
# leading "-" tells make to ignore its exit status, so a failing suite produces no error anywhere
# and surfaces only as lower coverage. That is how a transient failure of the live redis/memcache
# tests silently cost ~95 lines of coverage and published an understated figure.
#
# Run the suite strictly here and capture only if it passed. The two targets below are the same
# two steps AX_CODE_COVERAGE performs, minus the "-"; the exports above are repeated for this
# target because they are target-specific, and without them the live-backend tests would be
# skipped rather than run -- which would understate coverage by the same lines for the opposite
# reason.
.PHONY: coverage-check
coverage-check:
	$(MAKE) $(AM_MAKEFLAGS) check
	$(MAKE) $(AM_MAKEFLAGS) code-coverage-capture

@CODE_COVERAGE_RULES@
