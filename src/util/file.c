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
 * Copyright (C) 2017-2026 ZmartZone Holding BV
 * All rights reserved.
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
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "util/util.h"

/*
 * true if path exists and is a regular file (as opposed to a symlink or other special
 * file); finfo->filetype is always well-defined on return: APR_NOFILE when the path
 * could not be stat-ed at all (typically: missing), the actual (non-regular) type
 * otherwise, letting callers tell "absent" apart from "present but wrong type"
 */
apr_byte_t oidc_util_file_is_regular(apr_pool_t *pool, const char *path, apr_finfo_t *finfo) {
	finfo->filetype = APR_NOFILE;
	if (apr_stat(finfo, path, APR_FINFO_TYPE | APR_FINFO_LINK, pool) != APR_SUCCESS)
		return FALSE;
	return (finfo->filetype == APR_REG) ? TRUE : FALSE;
}

typedef enum {
	OIDC_UTIL_FILE_READ_OK = 0,
	OIDC_UTIL_FILE_READ_NOT_FOUND,	 /* missing, or could not be stat-ed/opened */
	OIDC_UTIL_FILE_READ_NOT_REGULAR, /* exists but is a symlink or other special file */
	OIDC_UTIL_FILE_READ_IO_ERROR,	 /* stat/open succeeded but a later step failed */
} oidc_util_file_read_rc_t;

/*
 * hardened whole-file read shared by the request- and server-scoped wrappers below: rejects
 * symlinks/non-regular files and caps the size of what gets allocated into memory; the caller
 * is responsible for logging, since the request/server logging macros are not interchangeable
 */
static oidc_util_file_read_rc_t oidc_util_file_read_core(apr_pool_t *pool, const char *path, char **result, char *s_err,
							 apr_size_t s_err_len) {
	apr_file_t *fd = NULL;
	apr_status_t rc = APR_SUCCESS;
	apr_finfo_t finfo;

	if (oidc_util_file_is_regular(pool, path, &finfo) == FALSE) {
		if (finfo.filetype == APR_NOFILE) {
			apr_cpystrn(s_err, "no such file", s_err_len);
			return OIDC_UTIL_FILE_READ_NOT_FOUND;
		}
		apr_cpystrn(s_err, "not a regular file", s_err_len);
		return OIDC_UTIL_FILE_READ_NOT_REGULAR;
	}

	/* open the file */
	if ((rc = apr_file_open(&fd, path, APR_FOPEN_READ | APR_FOPEN_BUFFERED, APR_OS_DEFAULT, pool)) != APR_SUCCESS) {
		apr_strerror(rc, s_err, s_err_len);
		return OIDC_UTIL_FILE_READ_NOT_FOUND;
	}

	/* the file exists, now lock it */
	apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);

	/* move the read pointer to the very start of the file */
	apr_off_t begin = 0;
	apr_file_seek(fd, APR_SET, &begin);

	/* get the file info so we know its size */
	if ((rc = apr_file_info_get(&finfo, APR_FINFO_SIZE, fd)) != APR_SUCCESS) {
		apr_strerror(rc, s_err, s_err_len);
		goto error_close;
	}

	/* refuse untrusted on-disk sizes before allocating memory for the contents */
	if ((finfo.size < 0) || (finfo.size > (apr_off_t)OIDC_UTIL_FILE_SIZE_MAX)) {
		apr_snprintf(s_err, s_err_len, "file too large (%" APR_OFF_T_FMT " bytes)", finfo.size);
		goto error_close;
	}

	/* now that we have the size of the file, allocate a buffer that can contain its contents */
	*result = apr_palloc(pool, finfo.size + 1);

	/* read the file in to the buffer */
	apr_size_t bytes_read = 0;
	if ((rc = apr_file_read_full(fd, *result, finfo.size, &bytes_read)) != APR_SUCCESS) {
		apr_strerror(rc, s_err, s_err_len);
		goto error_close;
	}

	/* just to be sure, we set a \0 (we allocated space for it anyway) */
	(*result)[bytes_read] = '\0';

	/* check that we've got all of it */
	if ((apr_off_t)bytes_read != finfo.size) {
		apr_snprintf(s_err, s_err_len, "read %" APR_SIZE_T_FMT " bytes, expected %" APR_OFF_T_FMT, bytes_read,
			     finfo.size);
		goto error_close;
	}

	/* we're done, unlock and close the file */
	apr_file_unlock(fd);
	apr_file_close(fd);

	return OIDC_UTIL_FILE_READ_OK;

error_close:

	apr_file_unlock(fd);
	apr_file_close(fd);

	return OIDC_UTIL_FILE_READ_IO_ERROR;
}

/*
 * read a file from a path on disk, for use at request time
 */
apr_byte_t oidc_util_file_read(request_rec *r, const char *path, apr_pool_t *pool, char **result) {
	char s_err[128];
	oidc_util_file_read_rc_t rc = oidc_util_file_read_core(pool, path, result, s_err, sizeof(s_err));

	switch (rc) {
	case OIDC_UTIL_FILE_READ_OK:
		oidc_debug(r, "file read successfully \"%s\"", path);
		return TRUE;
	case OIDC_UTIL_FILE_READ_NOT_FOUND:
		oidc_warn(r, "no file found at: \"%s\" (%s)", path, s_err);
		return FALSE;
	case OIDC_UTIL_FILE_READ_NOT_REGULAR:
		oidc_warn(r, "refusing to read non-regular file: \"%s\"", path);
		return FALSE;
	default:
		oidc_error(r, "reading \"%s\" failed: %s", path, s_err);
		return FALSE;
	}
}

/*
 * read a file from a path on disk, for use at server startup (e.g. config/license checks)
 * where there is no request_rec to log against or allocate from
 */
apr_byte_t oidc_util_file_read_server(server_rec *s, const char *path, apr_pool_t *pool, char **result) {
	char s_err[128];
	oidc_util_file_read_rc_t rc = oidc_util_file_read_core(pool, path, result, s_err, sizeof(s_err));

	switch (rc) {
	case OIDC_UTIL_FILE_READ_OK:
		oidc_sdebug(s, "file read successfully \"%s\"", path);
		return TRUE;
	case OIDC_UTIL_FILE_READ_NOT_FOUND:
		oidc_swarn(s, "no file found at: \"%s\" (%s)", path, s_err);
		return FALSE;
	case OIDC_UTIL_FILE_READ_NOT_REGULAR:
		oidc_swarn(s, "refusing to read non-regular file: \"%s\"", path);
		return FALSE;
	default:
		oidc_serror(s, "reading \"%s\" failed: %s", path, s_err);
		return FALSE;
	}
}

/*
 * write data to a file
 */
apr_byte_t oidc_util_file_write(request_rec *r, const char *path, const char *data) {

	apr_file_t *fd = NULL;
	apr_status_t rc = APR_SUCCESS;
	apr_size_t bytes_written = 0;
	char s_err[128];
	char *rnd = NULL;
	const char *tmp_path = NULL;

	if (oidc_util_rand_str(r, &rnd, 12) == FALSE)
		return FALSE;
	tmp_path = apr_psprintf(r->pool, "%s.%s.tmp", path, rnd);

	/* try to open the metadata file for writing, creating it if it does not exist; some of
	 * these files hold secrets (e.g. a dynamically registered client_secret), so restrict
	 * the permissions to the owner only rather than falling back to the process umask */
	if ((rc = apr_file_open(&fd, tmp_path, (APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_EXCL),
				(APR_FPROT_UREAD | APR_FPROT_UWRITE), r->pool)) != APR_SUCCESS) {
		oidc_error(r, "file \"%s\" could not be opened for atomic update (%s)", tmp_path,
			   apr_strerror(rc, s_err, sizeof(s_err)));
		return FALSE;
	}

	/* lock the file and move the write pointer to the start of it */
	apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);
	apr_off_t begin = 0;
	apr_file_seek(fd, APR_SET, &begin);

	/* calculate the length of the data, which is a string length */
	apr_size_t len = _oidc_strlen(data);

	/* (blocking) write the number of bytes in the buffer */
	rc = apr_file_write_full(fd, data, len, &bytes_written);

	/* check for a system error */
	if (rc != APR_SUCCESS) {
		oidc_error(r, "could not write to: \"%s\" (%s)", path, apr_strerror(rc, s_err, sizeof(s_err)));
		apr_file_unlock(fd);
		apr_file_close(fd);
		apr_file_remove(tmp_path, r->pool);
		return FALSE;
	}

	/* check that all bytes from the header were written */
	if (bytes_written != len) {
		oidc_error(r,
			   "could not write enough bytes to: \"%s\", bytes_written (%" APR_SIZE_T_FMT
			   ") != len (%" APR_SIZE_T_FMT ")",
			   path, bytes_written, len);
		apr_file_unlock(fd);
		apr_file_close(fd);
		apr_file_remove(tmp_path, r->pool);
		return FALSE;
	}

	/* unlock and close the written file */
	apr_file_unlock(fd);
	apr_file_close(fd);
	if ((rc = apr_file_rename(tmp_path, path, r->pool)) != APR_SUCCESS) {
		oidc_error(r, "file \"%s\" could not be atomically renamed to \"%s\" (%s)", tmp_path, path,
			   apr_strerror(rc, s_err, sizeof(s_err)));
		apr_file_remove(tmp_path, r->pool);
		return FALSE;
	}

	oidc_debug(r, "file \"%s\" written; number of bytes (%" APR_SIZE_T_FMT ")", path, len);

	return TRUE;
}
