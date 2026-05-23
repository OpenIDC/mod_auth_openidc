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
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/

#include "check_util.h"
#include "metrics.h"
#include "mod_auth_openidc.h"
#include "util.h"
#include "util/util.h"

/*
 * Tests for oidc_metrics_is_valid_classname — pure validation against the
 * static class-name table; no subsystem init required.
 */

START_TEST(test_metrics_is_valid_classname_known) {
	apr_pool_t *pool = oidc_test_pool_get();
	char *valid_names = NULL;
	/* class names come from the static OM_CLASS_* table; "provider" covers both timings and counters */
	ck_assert_int_eq(oidc_metrics_is_valid_classname(pool, "provider", &valid_names), TRUE);
	ck_assert_ptr_nonnull(valid_names);
	valid_names = NULL;
	ck_assert_int_eq(oidc_metrics_is_valid_classname(pool, "session", &valid_names), TRUE);
	valid_names = NULL;
	ck_assert_int_eq(oidc_metrics_is_valid_classname(pool, "authtype", &valid_names), TRUE);
	valid_names = NULL;
	ck_assert_int_eq(oidc_metrics_is_valid_classname(pool, "authn", &valid_names), TRUE);
}
END_TEST

START_TEST(test_metrics_is_valid_classname_claim_wildcard) {
	apr_pool_t *pool = oidc_test_pool_get();
	char *valid_names = NULL;
	/* the "claim" namespace is matched as a substring rather than a hash hit */
	ck_assert_int_eq(oidc_metrics_is_valid_classname(pool, "claim.id_token.email", &valid_names), TRUE);
	valid_names = NULL;
	ck_assert_int_eq(oidc_metrics_is_valid_classname(pool, "claim.userinfo.sub", &valid_names), TRUE);
}
END_TEST

START_TEST(test_metrics_is_valid_classname_unknown) {
	apr_pool_t *pool = oidc_test_pool_get();
	char *valid_names = NULL;
	ck_assert_int_eq(oidc_metrics_is_valid_classname(pool, "totally_bogus", &valid_names), FALSE);
	/* on failure the helper still populates the human-readable list of allowed classnames */
	ck_assert_ptr_nonnull(valid_names);
	ck_assert_msg(_oidc_strstr(valid_names, "session") != NULL, "valid_names list should mention 'session'");
}
END_TEST

/*
 * Lifecycle tests for the metrics subsystem: bring it up via
 * oidc_metrics_post_config, push a counter + timing sample through the
 * macro-style API, drive oidc_metrics_handle_request through each output
 * format, and tear the subsystem down via oidc_metrics_cleanup. The
 * subsystem holds process-wide state so each lifecycle test owns the full
 * setup/teardown.
 */

/* enable metrics on the cfg by registering one counter and one timing class */
static void enable_metrics_hook_data(request_rec *r) {
	cmd_parms *cmd = oidc_test_cmd_get("OIDCMetricsData");
	ck_assert_ptr_null(oidc_cmd_metrics_hook_data_set(cmd, NULL, "session"));
	cmd = oidc_test_cmd_get("OIDCMetricsData");
	ck_assert_ptr_null(oidc_cmd_metrics_hook_data_set(cmd, NULL, "provider"));
}

static void metrics_subsystem_setup(request_rec *r) {
	enable_metrics_hook_data(r);
	ck_assert_int_eq(oidc_metrics_post_config(r->server->process->pconf, r->server), TRUE);
	ck_assert_int_eq(oidc_metrics_child_init(r->server->process->pconf, r->server), APR_SUCCESS);
}

static void metrics_subsystem_teardown(request_rec *r) {
	ck_assert_int_eq(oidc_metrics_cleanup(r->server), APR_SUCCESS);
}

START_TEST(test_metrics_handle_request_no_format_default_prometheus) {
	request_rec *r = oidc_test_request_get();
	metrics_subsystem_setup(r);

	r->args = "";
	int rc = oidc_metrics_handle_request(r);
	ck_assert_int_eq(rc, OK);

	metrics_subsystem_teardown(r);
}
END_TEST

START_TEST(test_metrics_handle_request_format_json) {
	request_rec *r = oidc_test_request_get();
	metrics_subsystem_setup(r);

	r->args = "format=json";
	int rc = oidc_metrics_handle_request(r);
	ck_assert_int_eq(rc, OK);

	metrics_subsystem_teardown(r);
}
END_TEST

START_TEST(test_metrics_handle_request_format_internal) {
	request_rec *r = oidc_test_request_get();
	metrics_subsystem_setup(r);

	/* the "internal" handler returns NOT_FOUND when the shm has nothing in it
	 * (we haven't waited long enough for the background flush thread to fire) */
	r->args = "format=internal";
	int rc = oidc_metrics_handle_request(r);
	ck_assert_int_eq(rc, HTTP_NOT_FOUND);

	metrics_subsystem_teardown(r);
}
END_TEST

START_TEST(test_metrics_handle_request_format_status) {
	request_rec *r = oidc_test_request_get();
	metrics_subsystem_setup(r);

	r->args = "format=status";
	int rc = oidc_metrics_handle_request(r);
	ck_assert_int_eq(rc, OK);

	metrics_subsystem_teardown(r);
}
END_TEST

START_TEST(test_metrics_handle_request_format_unknown) {
	request_rec *r = oidc_test_request_get();
	metrics_subsystem_setup(r);

	r->args = "format=totally_bogus";
	int rc = oidc_metrics_handle_request(r);
	ck_assert_int_eq(rc, HTTP_NOT_FOUND);

	metrics_subsystem_teardown(r);
}
END_TEST

START_TEST(test_metrics_handle_request_with_samples) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	metrics_subsystem_setup(r);

	/* push one counter sample for each AUTHN_REQUEST counter class via the macro
	 * and one timing sample for the PROVIDER_TOKEN class — these exercise the
	 * counter_inc / timing_add storage paths that handle_request later reads */
	OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHN_REQUEST_ERROR_URL);
	OIDC_METRICS_COUNTER_INC_VALUE(r, c, OM_PROVIDER_HTTP_RESPONSE_CODE, "200");

	OIDC_METRICS_TIMING_START(r, c);
	apr_sleep(apr_time_from_msec(1));
	OIDC_METRICS_TIMING_ADD(r, c, OM_PROVIDER_TOKEN);

	r->args = "format=json&reset=true";
	int rc = oidc_metrics_handle_request(r);
	ck_assert_int_eq(rc, OK);

	metrics_subsystem_teardown(r);
}
END_TEST

int main(void) {
	TCase *classname = tcase_create("classname");
	tcase_add_checked_fixture(classname, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(classname, test_metrics_is_valid_classname_known);
	tcase_add_test(classname, test_metrics_is_valid_classname_claim_wildcard);
	tcase_add_test(classname, test_metrics_is_valid_classname_unknown);

	TCase *lifecycle = tcase_create("lifecycle");
	tcase_add_checked_fixture(lifecycle, oidc_test_setup, oidc_test_teardown);
	tcase_set_timeout(lifecycle, 30);
	tcase_add_test(lifecycle, test_metrics_handle_request_no_format_default_prometheus);
	tcase_add_test(lifecycle, test_metrics_handle_request_format_json);
	tcase_add_test(lifecycle, test_metrics_handle_request_format_internal);
	tcase_add_test(lifecycle, test_metrics_handle_request_format_status);
	tcase_add_test(lifecycle, test_metrics_handle_request_format_unknown);
	tcase_add_test(lifecycle, test_metrics_handle_request_with_samples);

	Suite *s = suite_create("metrics");
	suite_add_tcase(s, classname);
	suite_add_tcase(s, lifecycle);

	return oidc_test_suite_run(s);
}
