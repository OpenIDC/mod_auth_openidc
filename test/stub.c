#include <apr_global_mutex.h>
#include <apr_lib.h>
#include <apr_strings.h>

// clang-format off

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>

// clang-format on

/* NB: deliberately not "util.h": including it here pulls in <http_request.h>, whose AP_DECLARE_HOOK
 * declarations collide with the hand-rolled ap_hook_* shims below. These mirror the declarations in
 * util.h instead; the two must stay in step. */
typedef int (*oidc_test_hook_post_config_fn)(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2, server_rec *s);
typedef void (*oidc_test_hook_child_init_fn)(apr_pool_t *p, server_rec *s);
typedef void (*oidc_test_hook_insert_filter_fn)(request_rec *r);
typedef apr_status_t (*oidc_test_input_filter_fn)(ap_filter_t *f, apr_bucket_brigade *b, ap_input_mode_t mode,
						  apr_read_type_e block, apr_off_t nbytes);

static oidc_test_hook_insert_filter_fn _oidc_test_hook_insert_filter = NULL;
static oidc_test_input_filter_fn _oidc_test_input_filter = NULL;
static const char *_oidc_test_added_input_filter = NULL;
static const char *_oidc_test_brigade_body = NULL;
static apr_status_t _oidc_test_brigade_rc = APR_SUCCESS;

#define ap_HOOK_check_user_id_t void

AP_DECLARE(void)
ap_hook_check_authn(ap_HOOK_check_user_id_t *pf, const char *const *aszPre, const char *const *aszSucc, int nOrder,
		    int type) {
	// comment explaining why the method is empty
}

/* the first authz provider the module registers, so its parse_require_line can be driven */
static const void *_oidc_test_authz_provider = NULL;

const void *oidc_test_authz_provider_get(void) {
	return _oidc_test_authz_provider;
}

AP_DECLARE(apr_status_t)
ap_register_auth_provider(apr_pool_t *pool, const char *provider_group, const char *provider_name,
			  const char *provider_version, const void *provider, int type) {
	if (_oidc_test_authz_provider == NULL)
		_oidc_test_authz_provider = provider;
	return 0;
}

AP_DECLARE(apr_status_t) ap_unixd_set_global_mutex_perms(apr_global_mutex_t *gmutex) {
	return 0;
}

/* the AuthType reported to the module; default openid-connect, overridable per
 * test via oidc_test_set_auth_type() so the OAuth / mixed dispatch paths can be
 * exercised */
static const char *stub_auth_type = "openid-connect";

void oidc_test_set_auth_type(const char *auth_type) {
	stub_auth_type = (auth_type != NULL) ? auth_type : "openid-connect";
}

AP_DECLARE(const char *) ap_auth_type(request_rec *r) {
	return stub_auth_type;
}

AP_DECLARE(const char *) ap_auth_name(request_rec *r) {
	return NULL;
}

AP_DECLARE(long) ap_get_client_block(request_rec *r, char *buffer, apr_size_t bufsiz) {
	/* tests stash the POST body in r->args (and r->remaining tracks bytes left); copy
	 * from there into the caller's buffer so oidc_util_read can drive the form parser */
	if (r->args == NULL || r->remaining == 0)
		return 0;
	/* r->remaining is signed (apr_off_t) and is only ever positive here, but compare and
	 * assign in one type so the narrowing is explicit rather than a signedness surprise */
	apr_size_t remaining = (apr_size_t)r->remaining;
	apr_size_t off = strlen(r->args) - remaining;
	apr_size_t n = (bufsiz < remaining) ? bufsiz : remaining;
	memcpy(buffer, r->args + off, n);
	r->remaining -= n;
	return (long)n;
}

AP_DECLARE(char *) ap_getword(apr_pool_t *atrans, const char **line, char stop) {
	const char *pos = *line;
	int len;
	char *res;

	while ((*pos != stop) && *pos) {
		++pos;
	}

	len = (int)(pos - *line);
	res = apr_pstrmemdup(atrans, *line, len);

	if (stop) {
		while (*pos == stop) {
			++pos;
		}
	}
	*line = pos;

	return res;
}

static char *substring_conf(apr_pool_t *p, const char *start, int len, char quote) {
	char *result = apr_palloc(p, len + 1);
	char *resp = result;
	int i;

	for (i = 0; i < len; ++i) {
		if (start[i] == '\\' && (start[i + 1] == '\\' || (quote && start[i + 1] == quote)))
			*resp++ = start[++i];
		else
			*resp++ = start[i];
	}

	*resp++ = '\0';
#if RESOLVE_ENV_PER_TOKEN
	return (char *)ap_resolve_env(p, result);
#else
	return result;
#endif
}

AP_DECLARE(char *) ap_getword_conf(apr_pool_t *p, const char **line) {
	const char *str = *line, *strend;
	char *res;
	char quote;

	while (apr_isspace(*str))
		++str;

	if (!*str) {
		*line = str;
		return "";
	}

	if ((quote = *str) == '"' || quote == '\'') {
		strend = str + 1;
		while (*strend && *strend != quote) {
			if (*strend == '\\' && strend[1] && (strend[1] == quote || strend[1] == '\\')) {
				strend += 2;
			} else {
				++strend;
			}
		}
		res = substring_conf(p, str + 1, (int)(strend - str - 1), quote);

		if (*strend == quote)
			++strend;
	} else {
		strend = str;
		while (*strend && !apr_isspace(*strend))
			++strend;

		res = substring_conf(p, str, (int)(strend - str), 0);
	}

	while (apr_isspace(*strend))
		++strend;
	*line = strend;
	return res;
}

AP_DECLARE(char *) ap_getword_nulls(apr_pool_t *p, const char **line, char stop) {
	/* match Apache semantics: return the word before `stop`, advance *line past
	 * the separator (or to '\0' if `stop` is not present). The previous stub
	 * silently returned "" and left *line untouched, which masked any callers
	 * that relied on the advance — e.g. oidc_oauth_token_from_basic. */
	const char *pos = *line;
	while (*pos && (*pos != stop))
		++pos;
	char *res = apr_pstrmemdup(p, *line, pos - *line);
	*line = (*pos == stop) ? pos + 1 : pos;
	return res;
}

AP_DECLARE(char *) ap_getword_white(apr_pool_t *atrans, const char **line) {
	const char *pos = *line;
	int len;
	char *res;

	while (!apr_isspace(*pos) && *pos) {
		++pos;
	}

	len = (int)(pos - *line);
	res = apr_pstrmemdup(atrans, *line, len);

	while (apr_isspace(*pos)) {
		++pos;
	}

	*line = pos;

	return res;
}

AP_DECLARE(int) ap_hook_check_user_id(request_rec *r) {
	return 0;
}

AP_DECLARE(int) ap_hook_auth_checker(request_rec *r) {
	return 0;
}

AP_DECLARE(void)
ap_hook_fixups(int (*handler)(request_rec *r), const char *const *aszPre, const char *const *aszSucc, int nOrder) {
	// comment explaining why the method is empty
}

AP_DECLARE(void)
ap_hook_insert_filter(void (*insert_filter)(request_rec *r), const char *const *aszPre, const char *const *aszSucc,
		      int nOrder) {
	_oidc_test_hook_insert_filter = insert_filter;
}

/*
 * the hooks the module registers are recorded rather than discarded, so a test can drive the
 * server-lifetime entry points (post_config, child_init) the way httpd would; see test_config.c
 */
static oidc_test_hook_post_config_fn _oidc_test_hook_post_config = NULL;
static oidc_test_hook_child_init_fn _oidc_test_hook_child_init = NULL;

oidc_test_hook_post_config_fn oidc_test_hook_post_config_get(void) {
	return _oidc_test_hook_post_config;
}

oidc_test_hook_child_init_fn oidc_test_hook_child_init_get(void) {
	return _oidc_test_hook_child_init;
}

AP_DECLARE(void)
ap_hook_post_config(int (*post_config)(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2, server_rec *s),
		    const char *const *aszPre, const char *const *aszSucc, int nOrder) {
	_oidc_test_hook_post_config = post_config;
}

AP_DECLARE(void)
ap_hook_child_init(void (*child_init)(apr_pool_t *p, server_rec *s), const char *const *aszPre,
		   const char *const *aszSucc, int nOrder) {
	_oidc_test_hook_child_init = child_init;
}

AP_DECLARE(void)
ap_hook_handler(int (*handler)(request_rec *r), const char *const *aszPre, const char *const *aszSucc, int nOrder) {
	// comment explaining why the method is empty
}

AP_DECLARE(int) ap_is_initial_req(request_rec *r) {
	/* match Apache semantics: a request is "initial" when it is neither a
	 * sub-request (r->main NULL) nor an internal-redirect carryover
	 * (r->prev NULL). The previous stub hard-returned 0 which forced every
	 * caller through the sub-request branch and hid initial-request paths
	 * from coverage (e.g. oidc_oauth_check_userid_redirect_uri). */
	return (r->main == NULL) && (r->prev == NULL);
}

AP_DECLARE(ap_expr_info_t *)
ap_expr_parse_cmd_mi(const cmd_parms *cmd, const char *expr, unsigned int flags, const char **err,
		     ap_expr_lookup_fn_t *lookup_fn, int module_index) {
	if (strcmp(expr, "#") == 0) {
		*err = "error";
		return NULL;
	}
	ap_expr_info_t *rv = apr_pcalloc(cmd->pool, sizeof(ap_expr_info_t));
	/* echo the expression through ap_expr_str_exec below so string-valued
	 * expression directives behave like literal strings in the tests */
	rv->filename = apr_pstrdup(cmd->pool, expr);
	rv->root_node = NULL;
	return rv;
}

AP_DECLARE(const char *) ap_expr_str_exec(request_rec *r, const ap_expr_info_t *expr, const char **err) {
	if (err)
		*err = NULL;
	return expr->filename;
}

AP_DECLARE(char *) ap_get_exec_line(apr_pool_t *p, const char *cmd, const char *const *argv) {
	return NULL;
}

AP_DECLARE(void)
ap_log_error_(const char *file, int line, int module_index, int level, apr_status_t status, const server_rec *s,
	      const char *fmt, ...) {
	if (level < APLOG_DEBUG) {
		fprintf(stderr, "%s:%d [%d] [%d] ", file, line, level, status);
		va_list ap;
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
	}
}

AP_DECLARE(void)
ap_log_rerror_(const char *file, int line, int module_index, int level, apr_status_t status, const request_rec *r,
	       const char *fmt, ...) {
	if (level < APLOG_DEBUG) {
		fprintf(stderr, "%s:%d [%d] [%d] ", file, line, level, status);
		va_list ap;
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
	}
}

AP_DECLARE(void) ap_note_auth_failure(request_rec *r) {
	// comment explaining why the method is empty
}

/* capture the response body passed down the output filter chain in the request
 * state under "sent_body" so tests can assert on generated content; the test
 * fixture wires request->output_filters->r for this (see test/util.c) */
extern void oidc_request_state_set(request_rec *r, const char *key, const char *value);

AP_DECLARE(apr_status_t) ap_pass_brigade(ap_filter_t *filter, apr_bucket_brigade *bucket) {
	char *buf = NULL;
	apr_size_t len = 0;
	if ((filter != NULL) && (filter->r != NULL) &&
	    (apr_brigade_pflatten(bucket, &buf, &len, filter->r->pool) == APR_SUCCESS) && (len > 0))
		oidc_request_state_set(filter->r, "sent_body", apr_pstrmemdup(filter->r->pool, buf, len));
	return APR_SUCCESS;
}

AP_DECLARE(const apr_array_header_t *) ap_requires(request_rec *r) {
	return NULL;
}

const char *ap_run_http_scheme(const request_rec *r) {
	char *rv;
	apr_pool_userdata_get((void **)&rv, "scheme", r->pool);
	return (const char *)rv;
}

AP_DECLARE(void) ap_set_content_type(request_rec *r, const char *ct) {
	// comment explaining why the method is empty
}

AP_DECLARE_NONSTD(const char *) ap_set_flag_slot(cmd_parms *cmd, void *struct_ptr, int arg) {
	return "";
}

AP_DECLARE_NONSTD(const char *) ap_set_string_slot(cmd_parms *cmd, void *struct_ptr, const char *arg) {
	return "";
}

AP_DECLARE_NONSTD(const char *) ap_set_int_slot(cmd_parms *cmd, void *struct_ptr, const char *arg) {
	return "";
}

AP_DECLARE(int) ap_setup_client_block(request_rec *r, int read_policy) {
	return 0;
}

AP_DECLARE(int) ap_should_client_block(request_rec *r) {
	return 1;
}

AP_DECLARE(int) ap_unescape_url(char *url) {
	return 0;
}

AP_DECLARE(apr_status_t) unixd_set_global_mutex_perms(apr_global_mutex_t *gmutex) {
	return APR_SUCCESS;
}

AP_DECLARE(const char *) ap_get_server_name(request_rec *r) {
	return "www.example.com";
}

AP_DECLARE(char *) ap_server_root_relative(apr_pool_t *p, const char *file) {
	/* Apache's real implementation prepends ServerRoot to relative paths; in tests
	 * we treat the path as already-absolute (or relative-to-cwd) and return it verbatim */
	if (file == NULL)
		return NULL;
	return apr_pstrdup(p, file);
}

AP_DECLARE(ap_filter_t *) ap_add_input_filter(const char *name, void *ctx, request_rec *r, conn_rec *c) {
	_oidc_test_added_input_filter = name;
	return NULL;
}

const char *oidc_test_added_input_filter_get(void) {
	return _oidc_test_added_input_filter;
}

void oidc_test_added_input_filter_reset(void) {
	_oidc_test_added_input_filter = NULL;
}

AP_DECLARE(apr_status_t)
ap_get_brigade(ap_filter_t *filter, apr_bucket_brigade *bucket, ap_input_mode_t mode, apr_read_type_e block,
	       apr_off_t readbytes) {
	/* feed the caller the request body the next call is primed with, followed by EOS; an unprimed
	 * call yields an empty brigade, as before. The input filter under test only appends its
	 * captured POST parameters once it sees the EOS bucket, so a stub that produced nothing at all
	 * left that half of it unreachable. */
	if (_oidc_test_brigade_body != NULL) {
		apr_bucket_alloc_t *ba = bucket->bucket_alloc;
		APR_BRIGADE_INSERT_TAIL(
		    bucket, apr_bucket_heap_create(_oidc_test_brigade_body, strlen(_oidc_test_brigade_body), NULL, ba));
		APR_BRIGADE_INSERT_TAIL(bucket, apr_bucket_eos_create(ba));
		_oidc_test_brigade_body = NULL;
	}
	return _oidc_test_brigade_rc;
}

void oidc_test_brigade_prime(const char *body, apr_status_t rc) {
	_oidc_test_brigade_body = body;
	_oidc_test_brigade_rc = rc;
}

AP_DECLARE(ap_filter_rec_t *)
ap_register_input_filter(const char *name, ap_in_filter_func filter_func, ap_init_filter_func filter_init,
			 ap_filter_type ftype) {
	_oidc_test_input_filter = filter_func;
	return NULL;
}

oidc_test_input_filter_fn oidc_test_input_filter_get(void) {
	return _oidc_test_input_filter;
}

oidc_test_hook_insert_filter_fn oidc_test_hook_insert_filter_get(void) {
	return _oidc_test_hook_insert_filter;
}

AP_DECLARE(char *) ap_make_dirstr_parent(apr_pool_t *p, const char *s) {
	return NULL;
}

AP_DECLARE(apr_status_t) ap_mpm_query(int query_code, int *result) {
	*result = 1;
	return APR_SUCCESS;
}

#if AP_MODULE_MAGIC_AT_LEAST(20080920, 2)
AP_DECLARE(apr_status_t)
ap_timeout_parameter_parse(const char *timeout_parameter, apr_interval_time_t *timeout, const char *default_time_unit) {
	char *endp;
	const char *time_str;
	apr_int64_t tout;

	tout = apr_strtoi64(timeout_parameter, &endp, 10);
	if (!endp || !*endp) {
		time_str = default_time_unit;
	} else {
		time_str = endp;
	}

	switch (*time_str) {
		/* Time is in seconds */
	case 's':
		*timeout = (apr_interval_time_t)apr_time_from_sec(tout);
		break;
	case 'h':
		/* Time is in hours */
		*timeout = (apr_interval_time_t)apr_time_from_sec(tout * 3600);
		break;
	case 'm':
		switch (*(++time_str)) {
		/* Time is in milliseconds */
		case 's':
			*timeout = (apr_interval_time_t)tout * 1000;
			break;
		/* Time is in minutes */
		case 'i':
			*timeout = (apr_interval_time_t)apr_time_from_sec(tout * 60);
			break;
		default:
			return APR_EGENERAL;
		}
		break;
	default:
		return APR_EGENERAL;
	}
	return APR_SUCCESS;
}
#endif

AP_DECLARE(int) ap_expr_exec(request_rec *r, const ap_expr_info_t *expr, const char **err) {
	*err = "error";
	return 1;
}
