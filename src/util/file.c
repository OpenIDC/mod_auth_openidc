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
 * Copyright (C) 2017-2025 ZmartZone Holding BV
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
 * read a file from a path on disk
 */
apr_byte_t oidc_util_file_read(request_rec *r, const char *path, apr_pool_t *pool, char **result) {
	apr_file_t *fd = NULL;
	apr_status_t rc = APR_SUCCESS;
	char s_err[128];
	apr_finfo_t finfo;

	/* open the file if it exists */
	if ((rc = apr_file_open(&fd, path, APR_FOPEN_READ | APR_FOPEN_BUFFERED, APR_OS_DEFAULT, r->pool)) !=
	    APR_SUCCESS) {
		oidc_warn(r, "no file found at: \"%s\" (%s)", path, apr_strerror(rc, s_err, sizeof(s_err)));
		return FALSE;
	}

	/* the file exists, now lock it */
	apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);

	/* move the read pointer to the very start of the cache file */
	apr_off_t begin = 0;
	apr_file_seek(fd, APR_SET, &begin);

	/* get the file info so we know its size */
	if ((rc = apr_file_info_get(&finfo, APR_FINFO_SIZE, fd)) != APR_SUCCESS) {
		oidc_error(r, "error calling apr_file_info_get on file: \"%s\" (%s)", path,
			   apr_strerror(rc, s_err, sizeof(s_err)));
		goto error_close;
	}

	/* now that we have the size of the file, allocate a buffer that can contain its contents */
	*result = apr_palloc(pool, finfo.size + 1);

	/* read the file in to the buffer */
	apr_size_t bytes_read = 0;
	if ((rc = apr_file_read_full(fd, *result, finfo.size, &bytes_read)) != APR_SUCCESS) {
		oidc_error(r, "apr_file_read_full on (%s) returned an error: %s", path,
			   apr_strerror(rc, s_err, sizeof(s_err)));
		goto error_close;
	}

	/* just to be sure, we set a \0 (we allocated space for it anyway) */
	(*result)[bytes_read] = '\0';

	/* check that we've got all of it */
	if (bytes_read != finfo.size) {
		oidc_error(r,
			   "apr_file_read_full on (%s) returned less bytes (%" APR_SIZE_T_FMT
			   ") than expected: (%" APR_OFF_T_FMT ")",
			   path, bytes_read, finfo.size);
		goto error_close;
	}

	/* we're done, unlock and close the file */
	apr_file_unlock(fd);
	apr_file_close(fd);

	/* log successful content retrieval */
	oidc_debug(r, "file read successfully \"%s\"", path);

	return TRUE;

error_close:

	apr_file_unlock(fd);
	apr_file_close(fd);

	oidc_error(r, "return error");

	return FALSE;
}

/*
 * write data to a file
 */
apr_byte_t oidc_util_file_write(request_rec *r, const char *path, const char *data) {

	apr_file_t *fd = NULL;
	apr_status_t rc = APR_SUCCESS;
	apr_size_t bytes_written = 0;
	char s_err[128];

	/* try to open the metadata file for writing, creating it if it does not exist */
	if ((rc = apr_file_open(&fd, path, (APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE), APR_OS_DEFAULT,
				r->pool)) != APR_SUCCESS) {
		oidc_error(r, "file \"%s\" could not be opened (%s)", path, apr_strerror(rc, s_err, sizeof(s_err)));
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
		return FALSE;
	}

	/* check that all bytes from the header were written */
	if (bytes_written != len) {
		oidc_error(r,
			   "could not write enough bytes to: \"%s\", bytes_written (%" APR_SIZE_T_FMT
			   ") != len (%" APR_SIZE_T_FMT ")",
			   path, bytes_written, len);
		return FALSE;
	}

	/* unlock and close the written file */
	apr_file_unlock(fd);
	apr_file_close(fd);

	oidc_debug(r, "file \"%s\" written; number of bytes (%" APR_SIZE_T_FMT ")", path, len);

	return TRUE;
}
