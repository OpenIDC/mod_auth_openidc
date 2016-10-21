/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/***************************************************************************
 * Copyright (C) 2013-2016 Ping Identity Corporation
 * All rights reserved.
 *
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
 *
 * DISCLAIMER OF WARRANTIES:
 *
 * THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
 * ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
 * WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
 * WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
 * USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
 * YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
 * WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * caching using a file storage backend
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <apr_hash.h>
#include <apr_time.h>
#include <apr_strings.h>
#include <apr_pools.h>

#include <httpd.h>
#include <http_log.h>

#include "../mod_auth_openidc.h"

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

/*
 * header structure that holds the metadata info for a cache file entry
 */
typedef struct {
	/* length of the cached data */
	apr_size_t len;
	/* cache expiry timestamp */
	apr_time_t expire;
} oidc_cache_file_info_t;

/*
 * prefix that distinguishes mod_auth_openidc cache files from other files in the same directory (/tmp)
 */
#define OIDC_CACHE_FILE_PREFIX "mod-auth-connect-"

/* post config routine */
int oidc_cache_file_post_config(server_rec *s) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(s->module_config,
			&auth_openidc_module);
	if (cfg->cache_file_dir == NULL) {
		/* by default we'll use the OS specified /tmp dir for cache files */
		apr_temp_dir_get((const char **) &cfg->cache_file_dir,
				s->process->pool);
	}
	return OK;
}

/*
 * return the cache file name for a specified key
 */
static const char *oidc_cache_file_name(request_rec *r, const char *section,
		const char *key) {
	return apr_psprintf(r->pool, "%s%s-%s", OIDC_CACHE_FILE_PREFIX, section,
			key);
}

/*
 * return the fully qualified path name to a cache file for a specified key
 */
static const char *oidc_cache_file_path(request_rec *r, const char *section,
		const char *key) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	return apr_psprintf(r->pool, "%s/%s", cfg->cache_file_dir,
			oidc_cache_file_name(r, section, key));
}

/*
 * read a specified number of bytes from a cache file in to a preallocated buffer
 */
static apr_status_t oidc_cache_file_read(request_rec *r, const char *path,
		apr_file_t *fd, void *buf, const apr_size_t len) {

	apr_status_t rc = APR_SUCCESS;
	apr_size_t bytes_read = 0;
	char s_err[128];

	/* (blocking) read the requested number of bytes */
	rc = apr_file_read_full(fd, buf, len, &bytes_read);

	/* test for system errors */
	if (rc != APR_SUCCESS) {
		oidc_error(r, "could not read from: %s (%s)", path,
				apr_strerror(rc, s_err, sizeof(s_err)));
	}

	/* ensure that we've got the requested number of bytes */
	if (bytes_read != len) {
		oidc_error(r,
				"could not read enough bytes from: \"%s\", bytes_read (%" APR_SIZE_T_FMT ") != len (%" APR_SIZE_T_FMT ")",
				path, bytes_read, len);
		rc = APR_EGENERAL;
	}

	return rc;
}

/*
 * write a specified number of bytes from a buffer to a cache file
 */
static apr_status_t oidc_cache_file_write(request_rec *r, const char *path,
		apr_file_t *fd, void *buf, const apr_size_t len) {

	apr_status_t rc = APR_SUCCESS;
	apr_size_t bytes_written = 0;
	char s_err[128];

	/* (blocking) write the number of bytes in the buffer */
	rc = apr_file_write_full(fd, buf, len, &bytes_written);

	/* check for a system error */
	if (rc != APR_SUCCESS) {
		oidc_error(r, "could not write to: \"%s\" (%s)", path,
				apr_strerror(rc, s_err, sizeof(s_err)));
		return rc;
	}

	/* check that all bytes from the header were written */
	if (bytes_written != len) {
		oidc_error(r,
				"could not write enough bytes to: \"%s\", bytes_written (%" APR_SIZE_T_FMT ") != len (%" APR_SIZE_T_FMT ")",
				path, bytes_written, len);
		return APR_EGENERAL;
	}

	return rc;
}

/*
 * get a value for the specified key from the cache
 */
static apr_byte_t oidc_cache_file_get(request_rec *r, const char *section,
		const char *key, const char **value) {
	apr_file_t *fd = NULL;
	apr_status_t rc = APR_SUCCESS;
	char s_err[128];

	/* get the fully qualified path to the cache file based on the key name */
	const char *path = oidc_cache_file_path(r, section, key);

	/* open the cache file if it exists, otherwise we just have a "regular" cache miss */
	if (apr_file_open(&fd, path, APR_FOPEN_READ | APR_FOPEN_BUFFERED,
	APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
		oidc_debug(r, "cache miss for key \"%s\"", key);
		return TRUE;
	}

	/* the file exists, now lock it */
	apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);

	/* move the read pointer to the very start of the cache file */
	apr_off_t begin = 0;
	apr_file_seek(fd, APR_SET, &begin);

	/* read a header with metadata */
	oidc_cache_file_info_t info;
	if ((rc = oidc_cache_file_read(r, path, fd, &info,
			sizeof(oidc_cache_file_info_t))) != APR_SUCCESS)
		goto error_close;

	/* check if this cache entry has already expired */
	if (apr_time_now() >= info.expire) {

		/* yep, expired: unlock and close before deleting the cache file */
		apr_file_unlock(fd);
		apr_file_close(fd);

		/* log this event */
		oidc_debug(r, "cache entry \"%s\" expired, removing file \"%s\"", key,
				path);

		/* and kill it */
		if ((rc = apr_file_remove(path, r->pool)) != APR_SUCCESS) {
			oidc_error(r, "could not delete cache file \"%s\" (%s)", path,
					apr_strerror(rc, s_err, sizeof(s_err)));
		}

		/* nothing strange happened really */
		return TRUE;
	}

	/* allocate space for the actual value based on the data size info in the header (+1 for \0 termination) */
	*value = apr_palloc(r->pool, info.len);

	/* (blocking) read the requested data in to the buffer */
	rc = oidc_cache_file_read(r, path, fd, (void *) *value, info.len);

	/* barf on failure */
	if (rc != APR_SUCCESS) {
		oidc_error(r, "could not read cache value from \"%s\"", path);
		goto error_close;
	}

	/* we're done, unlock and close the file */
	apr_file_unlock(fd);
	apr_file_close(fd);

	/* log a successful cache hit */
	oidc_debug(r,
			"cache hit for key \"%s\" (%" APR_SIZE_T_FMT " bytes, expiring in: %" APR_TIME_T_FMT ")",
			key, info.len, apr_time_sec(info.expire - apr_time_now()));

	return TRUE;

error_close:

	apr_file_unlock(fd);
	apr_file_close(fd);

	oidc_error(r, "return error status %d (%s)", rc,
			apr_strerror(rc, s_err, sizeof(s_err)));

	return FALSE;
}

// TODO: make these configurable?
#define OIDC_CACHE_FILE_LAST_CLEANED "last-cleaned"

/*
 * delete all expired entries from the cache directory
 */
static apr_status_t oidc_cache_file_clean(request_rec *r) {
	apr_status_t rc = APR_SUCCESS;
	apr_dir_t *dir = NULL;
	apr_file_t *fd = NULL;
	apr_status_t i;
	apr_finfo_t fi;
	oidc_cache_file_info_t info;
	char s_err[128];

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	/* get the path to the metadata file that holds "last cleaned" metadata info */
	const char *metadata_path = oidc_cache_file_path(r, "cache-file",
			OIDC_CACHE_FILE_LAST_CLEANED);

	/* open the metadata file if it exists */
	if ((rc = apr_stat(&fi, metadata_path, APR_FINFO_MTIME, r->pool))
			== APR_SUCCESS) {

		/* really only clean once per so much time, check that we haven not recently run */
		if (apr_time_now() < fi.mtime + apr_time_from_sec(cfg->cache_file_clean_interval)) {
			oidc_debug(r,
					"last cleanup call was less than %d seconds ago (next one as early as in %" APR_TIME_T_FMT " secs)",
					cfg->cache_file_clean_interval,
					apr_time_sec( fi.mtime + apr_time_from_sec(cfg->cache_file_clean_interval) - apr_time_now()));
			return APR_SUCCESS;
		}

		/* time to clean, reset the modification time of the metadata file to reflect the timestamp of this cleaning cycle */
		apr_file_mtime_set(metadata_path, apr_time_now(), r->pool);

	} else {

		/* no metadata file exists yet, create one (and open it) */
		if ((rc = apr_file_open(&fd, metadata_path,
				(APR_FOPEN_WRITE | APR_FOPEN_CREATE), APR_OS_DEFAULT, r->pool))
				!= APR_SUCCESS) {
			oidc_error(r, "error creating cache timestamp file '%s' (%s)",
					metadata_path, apr_strerror(rc, s_err, sizeof(s_err)));
			return rc;
		}

		/* and cleanup... */
		if ((rc = apr_file_close(fd)) != APR_SUCCESS) {
			oidc_error(r, "error closing cache timestamp file '%s' (%s)",
					metadata_path, apr_strerror(rc, s_err, sizeof(s_err)));
		}
	}

	/* time to clean, open the cache directory */
	if ((rc = apr_dir_open(&dir, cfg->cache_file_dir, r->pool)) != APR_SUCCESS) {
		oidc_error(r, "error opening cache directory '%s' for cleaning (%s)",
				cfg->cache_file_dir, apr_strerror(rc, s_err, sizeof(s_err)));
		return rc;
	}

	/* loop trough the cache file entries */
	do {

		/* read the next entry from the directory */
		i = apr_dir_read(&fi, APR_FINFO_NAME, dir);

		if (i == APR_SUCCESS) {

			/* skip non-cache entries, cq. the ".", ".." and the metadata file */
			if ((fi.name[0] == '.')
					|| (strstr(fi.name, OIDC_CACHE_FILE_PREFIX) != fi.name)
					|| ((apr_strnatcmp(fi.name,
							oidc_cache_file_name(r, "cache-file",
									OIDC_CACHE_FILE_LAST_CLEANED)) == 0)))
				continue;

			/* get the fully qualified path to the cache file and open it */
			const char *path = apr_psprintf(r->pool, "%s/%s",
					cfg->cache_file_dir, fi.name);
			if ((rc = apr_file_open(&fd, path, APR_FOPEN_READ, APR_OS_DEFAULT,
					r->pool)) != APR_SUCCESS) {
				oidc_error(r, "unable to open cache entry \"%s\" (%s)", path,
						apr_strerror(rc, s_err, sizeof(s_err)));
				continue;
			}

			/* read the header with cache metadata info */
			rc = oidc_cache_file_read(r, path, fd, &info,
					sizeof(oidc_cache_file_info_t));
			apr_file_close(fd);

			if (rc == APR_SUCCESS) {

				/* check if this entry expired, if not just continue to the next entry */
				if (apr_time_now() < info.expire)
					continue;

				/* the cache entry expired, we're going to remove it so log that event */
				oidc_debug(r, "cache entry (%s) expired, removing file \"%s\")",
						fi.name, path);

			} else {

				/* file open returned an error, log that */
				oidc_error(r,
						"cache entry (%s) corrupted (%s), removing file \"%s\"",
						fi.name, apr_strerror(rc, s_err, sizeof(s_err)), path);

			}

			/* delete the cache file */
			if ((rc = apr_file_remove(path, r->pool)) != APR_SUCCESS) {

				/* hrm, this will most probably happen again on the next run... */
				oidc_error(r, "could not delete cache file \"%s\" (%s)", path,
						apr_strerror(rc, s_err, sizeof(s_err)));
			}

		}

	} while (i == APR_SUCCESS);

	apr_dir_close(dir);

	return APR_SUCCESS;
}

/*
 * write a value for the specified key to the cache
 */
static apr_byte_t oidc_cache_file_set(request_rec *r, const char *section,
		const char *key, const char *value, apr_time_t expiry) {
	apr_file_t *fd = NULL;
	apr_status_t rc = APR_SUCCESS;
	char s_err[128];

	/* get the fully qualified path to the cache file based on the key name */
	const char *path = oidc_cache_file_path(r, section, key);

	/* only on writes (not on reads) we clean the cache first (if not done recently) */
	oidc_cache_file_clean(r);

	/* just remove cache file if value is NULL */
	if (value == NULL) {
		if ((rc = apr_file_remove(path, r->pool)) != APR_SUCCESS) {
			oidc_error(r, "could not delete cache file \"%s\" (%s)", path,
					apr_strerror(rc, s_err, sizeof(s_err)));
		}
		return TRUE;
	}

	/* try to open the cache file for writing, creating it if it does not exist */
	if ((rc = apr_file_open(&fd, path, (APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE),
			APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) {
		oidc_error(r, "cache file \"%s\" could not be opened (%s)", path,
				apr_strerror(rc, s_err, sizeof(s_err)));
		return FALSE;
	}

	/* lock the file and move the write pointer to the start of it */
	apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);
	apr_off_t begin = 0;
	apr_file_seek(fd, APR_SET, &begin);

	/* construct the metadata for this cache entry in the header info */
	oidc_cache_file_info_t info;
	info.expire = expiry;
	info.len = strlen(value) + 1;

	/* write the header */
	if ((rc = oidc_cache_file_write(r, path, fd, &info,
			sizeof(oidc_cache_file_info_t))) != APR_SUCCESS)
		return FALSE;

	/* next write the value */
	if ((rc = oidc_cache_file_write(r, path, fd, (void *) value, info.len))
			!= APR_SUCCESS)
		return FALSE;

	/* unlock and close the written file */
	apr_file_unlock(fd);
	apr_file_close(fd);

	/* log our success */
	oidc_debug(r,
			"set entry for key \"%s\" (%" APR_SIZE_T_FMT " bytes, expires in: %" APR_TIME_T_FMT ")",
			key, info.len, apr_time_sec(expiry - apr_time_now()));

	return TRUE;
}

oidc_cache_t oidc_cache_file = {
		1,
		NULL,
		oidc_cache_file_post_config,
		NULL,
		oidc_cache_file_get,
		oidc_cache_file_set,
		NULL
};
