#include <stdio.h>
#include <string.h>

#include <apr_file_io.h>
#include <apr_base64.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <cjose/header.h>
#include <cjose/jws.h>

#include <mod_auth_openidc.h>

int usage(int argc, char **argv, const char *msg) {
	fprintf(stderr, "Usage: %s %s\n", argv[0],
			msg ? msg : "[ sign | verify | jwk2cert | cert2jwk | enckey ] <options>");
	return -1;
}

int file_read(apr_pool_t *pool, const char *path, char **rbuf) {
	apr_file_t *fd = NULL;
	char s_err[128];
	int rc;
	apr_size_t bytes_read = 0;
	apr_finfo_t finfo;
	apr_size_t len;

	rc = apr_file_open(&fd, path, APR_FOPEN_READ | APR_FOPEN_BUFFERED,
	APR_OS_DEFAULT, pool);
	if (rc != APR_SUCCESS) {
		fprintf(stderr, "could not open file %s: %s", path,
				apr_strerror(rc, s_err, sizeof(s_err)));
		return -1;
	}

	apr_file_info_get(&finfo, APR_FINFO_NORM, fd);
	len = (apr_size_t) finfo.size;
	*rbuf = apr_pcalloc(pool, len + 1);

	rc = apr_file_read_full(fd, *rbuf, len, &bytes_read);
	if (rc != APR_SUCCESS) {
		fprintf(stderr, "could not read file %s: %s", path,
				apr_strerror(rc, s_err, sizeof(s_err)));
		return -1;
	}

	(*rbuf)[bytes_read] = '\0';

	apr_file_close(fd);

	return 0;
}

int sign(int argc, char **argv, apr_pool_t *pool) {

	if (argc <= 4)
		return usage(argc, argv, "sign <algo> <jwt-file> <jwk-file>");

	char *s_jwt = NULL, *s_jwk = NULL;
	const char *cser = NULL;

	if (file_read(pool, argv[3], &s_jwt) != 0)
		return -1;
	if (file_read(pool, argv[4], &s_jwk) != 0)
		return -1;

	cjose_err cjose_err;

	cjose_header_t *hdr = cjose_header_new(&cjose_err);
	cjose_header_set(hdr, "alg", argv[2], &cjose_err);

	cjose_jwk_t *jwk = cjose_jwk_import(s_jwk, strlen(s_jwk), &cjose_err);
	if (jwk == NULL) {
		fprintf(stderr,
				"could not import JWK: %s [file: %s, function: %s, line: %ld]\n",
				cjose_err.message, cjose_err.file, cjose_err.function,
				cjose_err.line);
		return -1;
	}

	cjose_jws_t *jws = cjose_jws_sign(jwk, hdr, (const uint8_t *) s_jwt,
			strlen(s_jwt), &cjose_err);
	if (jws == NULL) {
		fprintf(stderr,
				"could not sign JWS: %s [file: %s, function: %s, line: %ld]\n",
				cjose_err.message, cjose_err.file, cjose_err.function,
				cjose_err.line);
		return -1;
	}

	if (cjose_jws_export(jws, &cser, &cjose_err) == FALSE) {
		fprintf(stderr,
				"could not serialize JWS: %s [file: %s, function: %s, line: %ld]\n",
				cjose_err.message, cjose_err.file, cjose_err.function,
				cjose_err.line);
		return -1;
	}

	fprintf(stdout, "%s", cser);

	cjose_jws_release(jws);
	cjose_jwk_release(jwk);

	return 0;
}

int verify(int argc, char **argv, apr_pool_t *pool) {

	if (argc <= 3)
		return usage(argc, argv, "verify <serialized-jwt-file> <jwk-file>");

	char *s_jwt = NULL, *s_jwk = NULL;

	if (file_read(pool, argv[2], &s_jwt) != 0)
		return -1;
	if (file_read(pool, argv[3], &s_jwk) != 0)
		return -1;

	cjose_err cjose_err;

	cjose_jws_t *jws = cjose_jws_import(s_jwt, strlen(s_jwt), &cjose_err);
	if (jws == NULL) {
		fprintf(stderr,
				"could not import JWS: %s [file: %s, function: %s, line: %ld]\n",
				cjose_err.message, cjose_err.file, cjose_err.function,
				cjose_err.line);
		return -1;
	}

	cjose_jwk_t *jwk = cjose_jwk_import(s_jwk, strlen(s_jwk), &cjose_err);
	if (jwk == NULL) {
		fprintf(stderr,
				"could not import JWK: %s [file: %s, function: %s, line: %ld]\n",
				cjose_err.message, cjose_err.file, cjose_err.function,
				cjose_err.line);
		return -1;
	}

	if (cjose_jws_verify(jws, jwk, &cjose_err) == FALSE) {
		fprintf(stderr,
				"could not verify JWS: %s [file: %s, function: %s, line: %ld]\n",
				cjose_err.message, cjose_err.file, cjose_err.function,
				cjose_err.line);
		return -1;
	}

	uint8_t *plaintext = NULL;
	size_t plaintext_len = 0;
	if (cjose_jws_get_plaintext(jws, &plaintext, &plaintext_len,
			&cjose_err) == FALSE) {
		fprintf(stderr,
				"could not get plaintext: %s [file: %s, function: %s, line: %ld]\n",
				cjose_err.message, cjose_err.file, cjose_err.function,
				cjose_err.line);
		return -1;
	}

	fprintf(stdout, "%s", plaintext);

	cjose_jws_release(jws);
	cjose_jwk_release(jwk);

	return 0;
}

int mkcert(RSA *rsa, X509 **x509p, EVP_PKEY **pkeyp, int serial, int days) {
	X509 *x;
	EVP_PKEY *pk;
	X509_NAME *name = NULL;

	if ((pkeyp == NULL) || (*pkeyp == NULL)) {
		if ((pk = EVP_PKEY_new()) == NULL)
			return -1;
	} else
		pk = *pkeyp;

	if ((x509p == NULL) || (*x509p == NULL)) {
		if ((x = X509_new()) == NULL)
			return -1;
	} else
		x = *x509p;

	if (!EVP_PKEY_assign_RSA(pk, rsa))
		return -1;

	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), (long) 60 * 60 * 24 * days);
	X509_set_pubkey(x, pk);

	name = X509_get_subject_name(x);

	X509_NAME_add_entry_by_txt(name, "C",
	MBSTRING_ASC, (const unsigned char *) "NL", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN",
	MBSTRING_ASC, (const unsigned char *) "Ping Identity", -1, -1, 0);

	X509_set_issuer_name(x, name);

	if (!X509_sign(x, pk, EVP_md5()))
		return -1;

	*x509p = x;
	*pkeyp = pk;

	return 0;
}

int jwk2cert(int argc, char **argv, apr_pool_t *pool) {

	if (argc <= 2)
		return usage(argc, argv, "jwk2cert <jwk-file>");

	char *s_jwk = NULL;

	if (file_read(pool, argv[2], &s_jwk) != 0)
		return -1;

	cjose_err cjose_err;

	cjose_jwk_t *jwk = cjose_jwk_import(s_jwk, strlen(s_jwk), &cjose_err);
	if (jwk == NULL) {
		fprintf(stderr,
				"could not import JWK: %s [file: %s, function: %s, line: %ld]\n",
				cjose_err.message, cjose_err.file, cjose_err.function,
				cjose_err.line);
		return -1;
	}

	if (cjose_jwk_get_kty(jwk, &cjose_err) != CJOSE_JWK_KTY_RSA) {
		fprintf(stderr, "wrong key type");
		return -1;
	}

	RSA *rsa = cjose_jwk_get_keydata(jwk, &cjose_err);
	//PEM_write_RSAPublicKey(stdout, rsa);
	PEM_write_RSA_PUBKEY(stdout, rsa);

	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;

	if (mkcert(rsa, &x509, &pkey, 0, 365) != 0)
		return -1;

	//RSA_print_fp(stdout,pkey->pkey.rsa,0);
	//X509_print_fp(stdout,x509);

	//PEM_write_PrivateKey(stdout,pkey,NULL,NULL,0,NULL, NULL);
	PEM_write_X509(stdout, x509);

	X509_free(x509);
	EVP_PKEY_free(pkey);

	return 0;
}

int cert2jwk(int argc, char **argv, apr_pool_t *pool) {

	if (argc <= 2)
		return usage(argc, argv, "cert2jwk <pem-file>");

	oidc_jwk_t *jwk = NULL;
	oidc_jose_error_t err;
	if (oidc_jwk_parse_rsa_public_key(pool, NULL, argv[2], &jwk, &err) == FALSE) {
		fprintf(stderr, "oidc_jwk_parse_rsa_public_key failed: %s", oidc_jose_e2s(pool, err));
		return -1;
	}

	char *s_json = NULL;
	if (oidc_jwk_to_json(pool, jwk, &s_json, &err) == FALSE) {
		fprintf(stderr, "oidc_jwk_to_json failed: %s", oidc_jose_e2s(pool, err));
		return -1;
	}

	fprintf(stdout, "%s", s_json);

	oidc_jwk_destroy(jwk);

	return 0;
}

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

typedef struct oidc_dir_cfg oidc_dir_cfg;

static request_rec * request_setup(apr_pool_t *pool) {
	const unsigned int kIdx = 0;
	const unsigned int kEls = kIdx + 1;
	request_rec *request = (request_rec *) apr_pcalloc(pool,
			sizeof(request_rec));

	request->pool = pool;

	request->headers_in = apr_table_make(request->pool, 0);
	request->headers_out = apr_table_make(request->pool, 0);
	request->err_headers_out = apr_table_make(request->pool, 0);

	apr_table_set(request->headers_in, "Host", "www.example.com");
	apr_table_set(request->headers_in, "OIDC_foo", "some-value");
	apr_table_set(request->headers_in, "Cookie", "foo=bar; "
			"mod_auth_openidc_session" "=0123456789abcdef; baz=zot");

	request->server = apr_pcalloc(request->pool, sizeof(struct server_rec));
	request->server->process = apr_pcalloc(request->pool,
			sizeof(struct process_rec));
	request->server->process->pool = request->pool;
	request->connection = apr_pcalloc(request->pool, sizeof(struct conn_rec));
	request->connection->local_addr = apr_pcalloc(request->pool,
			sizeof(apr_sockaddr_t));

	apr_pool_userdata_set("https", "scheme", NULL, request->pool);
	request->server->server_hostname = "www.example.com";
	request->connection->local_addr->port = 443;
	request->unparsed_uri = "/bla?foo=bar&param1=value1";
	request->args = "foo=bar&param1=value1";
	apr_uri_parse(request->pool,
			"https://www.example.com/bla?foo=bar&param1=value1",
			&request->parsed_uri);

	auth_openidc_module.module_index = kIdx;
	oidc_cfg *cfg = oidc_create_server_config(request->pool, request->server);
	cfg->provider.issuer = "https://idp.example.com";
	cfg->provider.authorization_endpoint_url =
			"https://idp.example.com/authorize";
	cfg->provider.scope = "openid";
	cfg->provider.client_id = "client_id";
	cfg->redirect_uri = "https://www.example.com/protected/";

	oidc_dir_cfg *d_cfg = oidc_create_dir_config(request->pool, NULL);

	request->server->module_config = apr_pcalloc(request->pool,
			sizeof(ap_conf_vector_t *) * kEls);
	request->per_dir_config = apr_pcalloc(request->pool,
			sizeof(ap_conf_vector_t *) * kEls);
	ap_set_module_config(request->server->module_config, &auth_openidc_module,
			cfg);
	ap_set_module_config(request->per_dir_config, &auth_openidc_module, d_cfg);

	cfg->cache = &oidc_cache_shm;
	cfg->cache_cfg = NULL;
	cfg->cache_shm_size_max = 500;
	cfg->cache_shm_entry_size_max = 16384 + 255 + 17;
	if (cfg->cache->post_config(request->server) != OK) {
		printf("cfg->cache->post_config failed!\n");
		exit(-1);
	}

	return request;
}

int enckey(int argc, char **argv, apr_pool_t *pool) {

	if (argc <= 2)
		return usage(argc, argv, "enckey <secret> [hash] [key-length]");

	request_rec *r = request_setup(pool);

	oidc_jwk_t *jwk = NULL;
	if (oidc_util_create_symmetric_key(r, argv[2], argc > 4 ? atoi(argv[4]) : 0, argc > 3 ? argv[3] : NULL, FALSE, &jwk) == FALSE) {
		fprintf(stderr, "oidc_util_create_symmetric_key failed");
		return -1;
	}

	oidc_jose_error_t err;
	char *s_json = NULL;
	if (oidc_jwk_to_json(pool, jwk, &s_json, &err) == FALSE) {
		fprintf(stderr, "oidc_jwk_to_json failed");
		return -1;
	}

	cjose_err cjose_err;
	int src_len = cjose_jwk_get_keysize(jwk->cjose_jwk, &cjose_err) / 8;
	int enc_len = apr_base64_encode_len(src_len);
	char *b64 = apr_palloc(r->pool, enc_len);
	apr_base64_encode(b64, (const char *) cjose_jwk_get_keydata(jwk->cjose_jwk, &cjose_err), src_len);

	fprintf(stdout, "\nJWK:\n%s\n\nbase64:\n%s\n\n", s_json, b64);

	return 0;
}

int main(int argc, char **argv, char **env) {

	if (argc <= 1)
		return usage(argc, argv, NULL);

	if (apr_app_initialize(&argc, (const char * const **) argv,
			(const char * const **) env) != APR_SUCCESS) {
		printf("apr_app_initialize failed\n");
		return -1;
	}

	OpenSSL_add_all_algorithms();

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, NULL);

	if (strcmp(argv[1], "sign") == 0)
		return sign(argc, argv, pool);

	if (strcmp(argv[1], "verify") == 0)
		return verify(argc, argv, pool);

	if (strcmp(argv[1], "jwk2cert") == 0)
		return jwk2cert(argc, argv, pool);

	if (strcmp(argv[1], "cert2jwk") == 0)
		return cert2jwk(argc, argv, pool);

	if (strcmp(argv[1], "enckey") == 0)
		return enckey(argc, argv, pool);

	apr_pool_destroy(pool);
	apr_terminate();

	return usage(argc, argv, NULL);
}
