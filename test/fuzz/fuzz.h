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

#endif /* _MOD_AUTH_OPENIDC_TEST_FUZZ_H_ */
