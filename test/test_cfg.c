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
 *
 **************************************************************************/

#include "cfg/provider.h"
#include "helper.h"

// provider

START_TEST(test_cmd_provider_token_endpoint_auth_set) {
	void *ptr = NULL;
	const char *arg = NULL;
	const char *rv = NULL;
	cmd_parms *cmd = oidc_test_cmd_get(OIDCProviderTokenEndpointAuth);

	arg = "private_key_jwt";
	rv = oidc_cmd_provider_token_endpoint_auth_set(cmd, ptr, arg);
	ck_assert_msg(rv == NULL, "failed: %s", rv);

	arg = "private_key_jws";
	rv = oidc_cmd_provider_token_endpoint_auth_set(cmd, ptr, arg);
	ck_assert_msg(rv != NULL, "should have failed");

	arg = "private_key_jwt:RS256";
	rv = oidc_cmd_provider_token_endpoint_auth_set(cmd, ptr, arg);
	ck_assert_msg(rv == NULL, "failed: %s", rv);

	arg = "private_key_jwt:RA256";
	rv = oidc_cmd_provider_token_endpoint_auth_set(cmd, ptr, arg);
	ck_assert_msg(rv != NULL, "should have failed");
}
END_TEST

int main(void) {
	TCase *core = tcase_create("core");
	tcase_add_checked_fixture(core, oidc_test_setup, oidc_test_teardown);

	tcase_add_test(core, test_cmd_provider_token_endpoint_auth_set);

	Suite *s = suite_create("cfg");
	suite_add_tcase(s, core);

	return oidc_test_suite_run(s);
}
