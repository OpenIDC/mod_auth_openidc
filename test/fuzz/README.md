# Fuzz targets

Coverage-guided fuzz targets for the parsers that handle untrusted input in
`mod_auth_openidc`. Each target is a single `LLVMFuzzerTestOneInput` over one
parser, reusing the libcheck test fixture (`test/util.c`) for a ready
`request_rec` + `oidc_cfg_t` and linking the static convenience library
`libauth_openidc.la` directly.

| target        | function under test                | what it stresses                                  |
|---------------|------------------------------------|---------------------------------------------------|
| `fuzz_base64` | `oidc_util_base64url_decode`       | base64url decoding (cookies, state, JWT segments) |
| `fuzz_url`    | `oidc_validate_redirect_url`       | the open-redirect guard (return-to / logout URLs) |
| `fuzz_jwt`    | `oidc_jwt_parse`                   | compact JWT/JWS/JWE structural parse              |
| `fuzz_json`   | `oidc_json_decode_object`          | JSON decode (token / userinfo / metadata)         |
| `fuzz_cookie` | `oidc_http_get_cookie`             | raw `Cookie` request header tokenizing            |
| `fuzz_response_header` | `oidc_http_response_header` | raw OP response header line parsing (curl callback) |
| `fuzz_form_params` | `oidc_util_read_form_encoded_params` | authz response / back-channel logout param parsing |

## Three build modes

Every target builds three ways from the same `fuzz_*.c`:

1. **Regression (part of `make check`)** — the target is linked with
   `standalone.c` and the ordinary compiler. `run-fuzzers.sh` replays each
   target's seed corpus (and, for `fuzz_url`, the 800+ curated payloads in
   `../open-redirect-payload-list.txt`). Any crash fails the build. This keeps
   the targets compiling and proves the parsers survive the known-nasty inputs
   on every CI run — no clang required.

2. **Fuzzing (clang + libFuzzer)** — `./build.sh` compiles each target with
   `clang -fsanitize=fuzzer,address,undefined`; libFuzzer supplies `main()` and
   `standalone.c` is left out. See the script header for prerequisites and the
   `FUZZ_CFLAGS` / `FUZZ_LIBS` / `CC` overrides.

   ```sh
   cd test/fuzz && ./build.sh
   ./build/fuzz_url -max_len=1024 corpus/url
   ```

3. **OSS-Fuzz** — `oss-fuzz-build.sh` builds the same targets inside an OSS-Fuzz
   `base-builder` container, against `$CC`/`$CFLAGS`/`$LIB_FUZZING_ENGINE`, and
   ships each target's seeds as `$OUT/<target>_seed_corpus.zip` (`fuzz_url` also
   gets the open-redirect payload list, one input per file). It lives here rather
   than in `google/oss-fuzz` so that adding a target, a corpus or a dictionary is
   a change in this tree and nowhere else; the project's build script there is one
   line calling this one.

   Three things it has to work around are documented inline, because none are
   obvious and all three fail late: cjose commits autotools output from a newer
   automake than the base image has (so always `autoreconf -fi`), `apxs` supplies
   `-flto` flags that discard the sanitizer-coverage constructors (so `-fno-lto`),
   and the runner image lacks the builder's distro libraries (so they are copied
   to `$OUT/lib` behind an `$ORIGIN` rpath).

   Verified locally with `infra/helper.py build_fuzzers` + `check_build`.

## Reproducing a crash

The standalone binaries (built by `make check`) take input files directly, so a
libFuzzer crash file replays under a debugger without clang:

```sh
cd test && ./fuzz_url crash-file          # one input per file
./fuzz_url --lines open-redirect-payload-list.txt   # one input per line
```

## Adding a target

1. Write `fuzz_<name>.c` implementing `LLVMFuzzerTestOneInput`; create a
   per-input subpool from `oidc_test_pool_get()` and free it each call (free any
   non-pooled results — `json_decref`, `oidc_jwt_destroy`, ...).
2. Add `fuzz_<name>` to `oidc_fuzz_targets` and a `fuzz_<name>_SOURCES` line in
   `test/Makefile.am`, and a `replay` line in `run-fuzzers.sh`.
3. Drop a few seed inputs in `corpus/<name>/`.
