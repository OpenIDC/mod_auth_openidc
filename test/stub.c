#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <apr_global_mutex.h>
#include <apr_strings.h>
#include <apr_lib.h>
#include <http_log.h>

#define ap_HOOK_check_user_id_t void

AP_DECLARE(void) ap_hook_check_authn(ap_HOOK_check_user_id_t *pf,
		const char * const *aszPre, const char * const *aszSucc, int nOrder,
		int type) {
}

AP_DECLARE(apr_status_t) ap_register_auth_provider(apr_pool_t *pool,
		const char *provider_group, const char *provider_name,
		const char *provider_version, const void *provider, int type) {
	return 0;
}

AP_DECLARE(apr_status_t) ap_unixd_set_global_mutex_perms(
		apr_global_mutex_t *gmutex) {
	return 0;
}

AP_DECLARE(const char *) ap_auth_type(request_rec *r) {
	return "openid-connect";
}

AP_DECLARE(const char *) ap_auth_name(request_rec *r) {
	return NULL;
}

AP_DECLARE(long) ap_get_client_block(request_rec * r, char * buffer,
		apr_size_t bufsiz) {
	return 0;
}

AP_DECLARE(char *) ap_get_exec_line(apr_pool_t *p, const char *cmd,
		const char * const *argv) {
	return NULL;
}

AP_DECLARE(char *) ap_getword(apr_pool_t *atrans, const char **line, char stop) {
	const char *pos = *line;
	int len;
	char *res;

	while ((*pos != stop) && *pos) {
		++pos;
	}

	len = pos - *line;
	res = apr_pstrmemdup(atrans, *line, len);

	if (stop) {
		while (*pos == stop) {
			++pos;
		}
	}
	*line = pos;

	return res;
}

static char *substring_conf(apr_pool_t *p, const char *start, int len,
		char quote) {
	char *result = apr_palloc(p, len + 1);
	char *resp = result;
	int i;

	for (i = 0; i < len; ++i) {
		if (start[i] == '\\'
				&& (start[i + 1] == '\\' || (quote && start[i + 1] == quote)))
			*resp++ = start[++i];
		else
			*resp++ = start[i];
	}

	*resp++ = '\0';
#if RESOLVE_ENV_PER_TOKEN
	return (char *)ap_resolve_env(p,result);
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
			if (*strend == '\\' && strend[1] &&
					(strend[1] == quote || strend[1] == '\\')) {
				strend += 2;
			}
			else {
				++strend;
			}
		}
		res = substring_conf(p, str + 1, strend - str - 1, quote);

		if (*strend == quote)
			++strend;
	}
	else {
		strend = str;
		while (*strend && !apr_isspace(*strend))
			++strend;

		res = substring_conf(p, str, strend - str, 0);
	}

	while (apr_isspace(*strend))
		++strend;
	*line = strend;
	return res;
}

AP_DECLARE(char *) ap_getword_nulls(apr_pool_t *p, const char **line, char stop) {
	return "";
}

AP_DECLARE(char *) ap_getword_white(apr_pool_t *p, const char **line) {
	return 0;
}

AP_DECLARE(int) ap_hook_check_user_id(request_rec *r) {
	return 0;
}

AP_DECLARE(int) ap_hook_auth_checker(request_rec *r) {
	return 0;
}

AP_DECLARE(int) ap_hook_fixups(request_rec *r) {
	return 0;
}

AP_DECLARE(int) ap_hook_insert_filter(request_rec *r) {
	return 0;
}

AP_DECLARE(void) ap_hook_post_config(
		int (*post_config)(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2,
				server_rec *s), const char * const *aszPre,
				const char * const *aszSucc, int nOrder) {
}

AP_DECLARE(void) ap_hook_child_init(
		void (*child_init)(apr_pool_t *p, server_rec *s),
		const char * const *aszPre, const char * const *aszSucc, int nOrder) {
}

AP_DECLARE(void) ap_hook_handler(int (*handler)(request_rec *r),
		const char * const *aszPre, const char * const *aszSucc, int nOrder) {
}

AP_DECLARE(int) ap_is_initial_req(request_rec *r) {
	return 0;
}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
AP_DECLARE(ap_expr_info_t *) ap_expr_parse_cmd_mi(const cmd_parms *cmd, const char *expr,
		unsigned int flags, const char **err, ap_expr_lookup_fn_t *lookup_fn,
		int module_index) {
	return NULL;
}

AP_DECLARE(const char *) ap_expr_str_exec(request_rec *r, const ap_expr_info_t *expr,
		const char **err) {
	err = NULL;
	return expr->filename;
}

AP_DECLARE(void) ap_log_error_(const char *file, int line, int module_index,
		int level, apr_status_t status, const server_rec *s, const char *fmt,
		...) {
#else
	AP_DECLARE(void) ap_log_error(const char *file, int line, int level,
			apr_status_t status, const server_rec *s, const char *fmt, ...) {
#endif
		if (level < APLOG_DEBUG) {
			fprintf(stderr, "%s:%d [%d] [%d] ", file, line, level, status);
			va_list ap;
			va_start(ap, fmt);
			vfprintf(stderr, fmt, ap);
			va_end(ap);
			fprintf(stderr, "\n");
		}
	}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	AP_DECLARE(void) ap_log_rerror_(const char *file, int line, int module_index,
			int level, apr_status_t status, const request_rec *r, const char *fmt,
			...) {
#else
		AP_DECLARE(void) ap_log_rerror(const char *file, int line, int level,
				apr_status_t status, const request_rec *r, const char *fmt, ...) {
#endif
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
		}

		AP_DECLARE(apr_status_t) ap_pass_brigade(ap_filter_t *filter,
				apr_bucket_brigade *bucket) {
			return APR_SUCCESS;
		}

		AP_DECLARE(const apr_array_header_t *) ap_requires(request_rec *r) {
			return NULL;
		}

		const char *ap_run_http_scheme(const request_rec *r) {
			char *rv;
			apr_pool_userdata_get((void **) &rv, "scheme", r->pool);
			return (const char *) rv;
		}

		AP_DECLARE(void) ap_set_content_type(request_rec *r, const char *ct) {
		}

		AP_DECLARE_NONSTD(const char *) ap_set_flag_slot(cmd_parms *cmd,
				void *struct_ptr,
				int arg) {
			return "";
		}

		AP_DECLARE_NONSTD(const char *) ap_set_string_slot(cmd_parms *cmd,
				void *struct_ptr,
				const char *arg) {

			return "";
		}

		AP_DECLARE_NONSTD(const char *) ap_set_int_slot(cmd_parms *cmd,
				void *struct_ptr,
				const char *arg) {
			return "";
		}

		AP_DECLARE(int) ap_setup_client_block(request_rec *r, int read_policy) {
			return 0;
		}

		AP_DECLARE(int) ap_should_client_block(request_rec *r) {
			return 0;
		}

		AP_DECLARE(int) ap_unescape_url(char *url) {
			return 0;
		}

		AP_DECLARE(apr_status_t) unixd_set_global_mutex_perms(
				apr_global_mutex_t *gmutex) {
			return APR_SUCCESS;
		}

		AP_DECLARE(const char *) ap_get_server_name(request_rec *r) {
			return "www.example.com";
		}

		AP_DECLARE(char *) ap_server_root_relative(apr_pool_t *p, const char *file) {
			return "";
		}

		AP_DECLARE(ap_filter_t *) ap_add_input_filter(const char *name, void *ctx,
				request_rec *r, conn_rec *c) {
			return NULL;
		}

		AP_DECLARE(apr_status_t) ap_get_brigade(ap_filter_t *filter,
				apr_bucket_brigade *bucket, ap_input_mode_t mode, apr_read_type_e block,
				apr_off_t readbytes) {
			return APR_SUCCESS;
		}

		AP_DECLARE(ap_filter_rec_t *) ap_register_input_filter(const char *name,
				ap_in_filter_func filter_func,
				ap_init_filter_func filter_init,
				ap_filter_type ftype) {
			return NULL;
		}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
		AP_DECLARE(int) ap_expr_exec(request_rec *r, const ap_expr_info_t *expr,
				const char **err) {
			return 0;
		}
#endif
