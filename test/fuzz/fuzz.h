/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Copyright (C) 2017-2026 ZmartZone Holding BV - hans.zandbelt@openidc.com
 *
 * fuzz.h -- shared declarations for the fuzz targets under test/fuzz/.
 *
 * Each target implements the libFuzzer entry point below. The same object
 * builds two ways:
 *   - linked with standalone.c + plain cc  -> a corpus-replay binary run by
 *     test/fuzz/run-fuzzers.sh as part of `make check` (regression guard);
 *   - compiled with `clang -fsanitize=fuzzer` -> a real libFuzzer binary
 *     (libFuzzer provides main); see test/fuzz/build.sh.
 */

#ifndef _MOD_AUTH_OPENIDC_TEST_FUZZ_H_
#define _MOD_AUTH_OPENIDC_TEST_FUZZ_H_

#include <stddef.h>
#include <stdint.h>

/* the one entry point every fuzz target implements */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/*
 * One-time fixture setup (oidc_test_setup), implemented by every target.
 * libFuzzer and honggfuzz call this once at startup; AFL++'s driver calls it
 * *before* spawning its deferred forkserver, and that ordering is the point:
 * the full post-config fixture init must run once in the forkserver parent,
 * not inside every forked child's first LLVMFuzzerTestOneInput call, where
 * afl-fuzz's per-exec timeout (5s in the OSS-Fuzz build check) counts it.
 * afl-fuzz also injects LSAN_OPTIONS containing fast_unwind_on_malloc=0 into
 * the target environment, which makes ASan DWARF-unwind every allocation the
 * init makes and inflates that first exec from ~0.2s to seconds -- the cause
 * of the "All test cases time out" OSS-Fuzz build-check failures on the afl
 * engine. Targets keep a lazy fallback in LLVMFuzzerTestOneInput for runners
 * that do not call this (the standalone corpus-replay main).
 */
int LLVMFuzzerInitialize(int *argc, char ***argv);

#endif /* _MOD_AUTH_OPENIDC_TEST_FUZZ_H_ */
