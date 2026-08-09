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
 * standalone.c -- a minimal main() that replays a seed corpus through a fuzz
 * target, used when the target is NOT linked against libFuzzer. This is what
 * lets the fuzz targets build with the ordinary toolchain and run under
 * `make check` as deterministic regression tests. When a target is compiled
 * with `clang -fsanitize=fuzzer`, libFuzzer supplies main() and this file is
 * left out of the link.
 *
 * Usage:
 *   ./fuzz_xxx file1 file2 ...     each file is fed as one input
 *   ./fuzz_xxx --lines file        each line of the file is fed as one input
 *                                  (for newline-separated payload lists)
 *
 * Exits non-zero when an input could not be read, or when the run fed the
 * target nothing at all: a corpus that moved, or a glob the shell left
 * unexpanded because it matched no file, must not be reported as a pass.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* getline() */
#endif
#include "fuzz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* returns the number of inputs fed to the target, or -1 if the file was unreadable */
static long run_file(const char *path) {
	FILE *f = fopen(path, "rb");
	if (f == NULL) {
		fprintf(stderr, "fuzz: cannot open %s\n", path);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	if (sz < 0)
		sz = 0;
	fseek(f, 0, SEEK_SET);
	unsigned char *buf = (unsigned char *)malloc((size_t)sz + 1);
	size_t n = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	LLVMFuzzerTestOneInput(buf, n);
	free(buf);
	return 1;
}

/* returns the number of lines fed to the target, or -1 if the file was unreadable */
static long run_lines(const char *path) {
	FILE *f = fopen(path, "rb");
	if (f == NULL) {
		fprintf(stderr, "fuzz: cannot open %s\n", path);
		return -1;
	}
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;
	long fed = 0;
	while ((len = getline(&line, &cap, f)) != -1) {
		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
			len--;
		LLVMFuzzerTestOneInput((const unsigned char *)line, (size_t)len);
		fed++;
	}
	free(line);
	fclose(f);
	return fed;
}

int main(int argc, char **argv) {
	int i = 1;
	int lines = 0;
	int unreadable = 0;
	long fed = 0;

	if (argc > 1 && strcmp(argv[1], "--lines") == 0) {
		lines = 1;
		i = 2;
	}
	for (; i < argc; i++) {
		long n = lines ? run_lines(argv[i]) : run_file(argv[i]);
		if (n < 0)
			unreadable = 1;
		else
			fed += n;
	}

	/* the "cannot open" reason has already been reported per path */
	if (unreadable)
		return 1;

	if (fed == 0) {
		fprintf(stderr, "fuzz: no input was replayed -- corpus missing, empty, or no arguments given\n");
		return 1;
	}

	return 0;
}
