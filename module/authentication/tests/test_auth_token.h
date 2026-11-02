/**************************************************************************/
/*  test_auth_token.h                                                   */
/**************************************************************************/
/*                         This file is part of:                          */
/*                             GOBU ENGINE                               */
/*                        https://gobuengine.org                         */
/**************************************************************************/
/* Copyright (c) 2014-present Gobu Engine contributors (see AUTHORS.md). */
/* Copyright (c) 2007-2014 Juan Linietsky, Ariel Manzur.                  */
/*                                                                        */
/* Permission is hereby granted, free of charge, to any person obtaining  */
/* a copy of this software and associated documentation files (the        */
/* "Software"), to deal in the Software without restriction, including    */
/* without limitation the rights to use, copy, modify, merge, publish,    */
/* distribute, sublicense, and/or sell copies of the Software, and to     */
/* permit persons to whom the Software is furnished to do so, subject to  */
/* the following conditions:                                              */
/*                                                                        */
/* The above copyright notice and this permission notice shall be         */
/* included in all copies or substantial portions of the Software.        */
/*                                                                        */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,        */
/* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF     */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. */
/* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY   */
/* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,   */
/* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE      */
/* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                 */
/**************************************************************************/

#pragma once

#include "../authentication.h"
#include "Modules/online/online.h"
#include "core/plugin/plugin_manager.h"
#include "../auth_token.h"
#include "core/config/project_settings.h"

#include "Tests/test_macros.h"

namespace TestAuthToken {

// The plugin, as a project that enabled it (its class, its singleton, its settings).
static void _enable_plugin() {
	if (!GobuPlugins::is_loaded(Authentication::PLUGIN_ID)) {
		GobuPlugins::load(Authentication::PLUGIN_ID);
	}
}

// Signed with openssl (an RSA 2048 key, kid "rsa-1"; a P-256 key, "ec-1"; HS256 with "super-secret"), as a
// login service signs them. Valid until 2100; EXPIRED in 2001.
static const char *JWKS = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"rsa-1\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"tNJHgpQHV5XTl1N3wiDpRxFnj0PwHwvB5GeGHNYpJmY99PGaWtA2hOp-XbWxiNB-Of7ZNsY3N_GsBA_pEiyxI5PSUOSneedxqSNO6OmCwvURqvDXERjtEmKTXRxtVH5x8_dKBzToYbwKBUJnEv8dT3ggUpaacS1Qp-fBOEPxYZnGS9pUDmEZEJsC_8LlWWDebaZaziADbMLRctcaP7rkvOipeOcu63O-kXDSlJjqGQGN8H_lPNJMUu_IEcurGVr--QT8-0YunxLwxkW7HZ-Pr6rOrOp8Zq3dQyqKz94ai2VLRn61WVmECBuoVAzoBhZ0y5pSWQw4bKxMeOTtOrk-Bw\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":\"ec-1\",\"use\":\"sig\",\"alg\":\"ES256\",\"crv\":\"P-256\",\"x\":\"tinUEHNrteMkJ6thGrOpLtlKmBoqb9Lwt7qw5ol34Uk\",\"y\":\"IdUDT9ujuLYZ3Eygtop_2fHr5efgO22YrjfU7EKnBAc\"}]}";
static const char *RS256_VALID = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYS0xIn0.eyJzdWIiOiJ1c2VyLTEiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuc3VwYWJhc2UuY28vYXV0aC92MSIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJleHAiOjQxMDI0NDQ4MDB9.cSNoiYnBgo0WxeDrfys3yDbZB-MIVm5OmbyY-e0-bTEh40Scsld8SqZmDDvSqwcnM20zQAWIrcFC6iT6YzWmeetQD50XAWvuAwJVTtTxxibqs26q-lVo9TF6dzJiLYOV58f8ZM1mE-F-pQSsQkUpcuHlwfT836eZjQf7SREC05W-AQSmTsZ34Q-gv3DoBCFODAou4n-vLJM9_C-wXHitUoIXyv9562a9iBNuFps1aG0SP3R-QqkExpEBumav6D6zXvoiTTUinfRM41hW-NCYm3yGOqPzcZJHdV0YJHqf5Ca-AupzDexJFPYJmBwVxELeiHZPNMwdVaHVHUGqRx8ktw";
static const char *ES256_VALID = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImVjLTEifQ.eyJzdWIiOiJ1c2VyLTIiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuc3VwYWJhc2UuY28vYXV0aC92MSIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJleHAiOjQxMDI0NDQ4MDB9.PrlQp6MEFHGyoGPERLmn1z_YLyOYEFiBEQ4A_iWCcZJ0n7dQLE1GlNnlUK8PJQHbJKE736mAvaVY6vEtJOBdYA";
static const char *HS256_VALID = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTMiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuc3VwYWJhc2UuY28vYXV0aC92MSIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJleHAiOjQxMDI0NDQ4MDB9.0KJtSd_YFWbckbrb19VwgHkbco5HQxnMdCY7-uzKrSg";
static const char *EXPIRED = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYS0xIn0.eyJzdWIiOiJ1c2VyLTEiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuc3VwYWJhc2UuY28vYXV0aC92MSIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJleHAiOjEwMDAwMDAwMDB9.fHMKY-pSIaZr_rd92SD36Is8cxEYEYZTefX_9q-8XMJ864ujnTxTSoX-hjoWbym9iuz29tmlPyzEGo23UVT3UNreZjlcfRL-NjYxF7y4ZnJDU3oqhz5-p0ogfWtb38KUt-2EWp6C9mQNVwRA_0FXI6c-Z7j67czNz0UvS1iFISRKmzkspebFMpogMq1s_cAXcUReb9bivsxoNCiDoAOJEp_qEQKz_rKi4HmGXzqxjtmbrwFdid6cOfnjaLv3MvxjJvwkvoa6Ngeq4GnW7Te5KYvWFK0mlTH7cX1LkibL4k_8Bb1XHiAuxCr-sZxMFEhBnizCkjbCPdImeqoddhkaRA";
static const char *NOT_YET = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImVjLTEifQ.eyJzdWIiOiJ1c2VyLTEiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuc3VwYWJhc2UuY28vYXV0aC92MSIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJleHAiOjQxMDI0NDQ4MDAsIm5iZiI6NDEwMjQ0NDc5MH0.RQUV2CFgYQCQaz_utnGH7oAFQ4m8LosXJQZgrNHI05CPf3tkfoqeLRJkQAgkMjtlX4aaeCa1CsOMRACL1_7AAw";
static const char *WRONG_ISSUER = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYS0xIn0.eyJzdWIiOiJ1c2VyLTEiLCJpc3MiOiJodHRwczovL290aGVyLmV4YW1wbGUvYXV0aCIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJleHAiOjQxMDI0NDQ4MDB9.bHsO2N19zX0tU4MF6f9qUNjY0XH0vvQQ1Rqwk2_znWSE1_3qoAfrjT5b8wNuUXje8OwL349nZT7-oYtyipU3DYKo8U3fWKAMj2IGJbTZLDcO-gbNyRxMor4tuQVrjVDy2yWjDj52nLsqBBndFkncFRZHtqgV8Hl2cGIZnpU228vFE1UpMwg8yCKuSeawSstUVodZSF9lPSMm_XuUUhfoMDiNB_MvFYqkKiHnKyENt1iX_NaYdH1m1QNNITURQM9WMZ_y7rGKCX6Fmtvmswxj1egMEwxFSbGKChm2dq7ThPsq_TAHdnhlDRGjuvrHjV5o7SxNfqtNYSV6zgCuPj2bUw";
static const char *AUDIENCE_LIST = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYS0xIn0.eyJzdWIiOiJ1c2VyLTEiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuc3VwYWJhc2UuY28vYXV0aC92MSIsImF1ZCI6WyJvdGhlciIsImF1dGhlbnRpY2F0ZWQiXSwiZXhwIjo0MTAyNDQ0ODAwfQ.dwJjZ3tmumhFH-TRZ3jGl9wuEipwGkiRiwJ8oJIuXCMuLeYNEcvsUZogaQ8TDjl2pl2mmVqTQZAzmxKRW0WPHcHhBguofExbucDjh7bPWHNsJMz55ITifv4GrSVLVeTKYgP9SiVz9djfjRFVT6w-JaqhPD-USaypsulS5r1HFJ9BWCcC3bW22Y0SzV-3bMCKdvPqT61xtF-gL6syLtF7sSKK5q9B7uMhGVnlBvZzB5tdVa39oYUJtZN_8A9R1sU5WPd20t5lsrFOqfq-hqwrwrNf4UwQd2_5gSK0GYpppnS1iSeb1cmI8hAKU3eyzusB9tFcaUCnzf_MgEqvXTTzzA";
static const char *UNKNOWN_KID = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYS0yIn0.eyJzdWIiOiJ1c2VyLTEiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuc3VwYWJhc2UuY28vYXV0aC92MSIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJleHAiOjQxMDI0NDQ4MDB9.rPtK4TMFnZtQhraWztGn_CFesgbb0R3A59LIuXwmr114LB26hi87TRcGH6yBUniHC66mZKQ7rv_1PgFNt_5G66pM6SoVZ4VAuRxpTlnuXLn8ITdP4bjks8fWYG1OiANFC-kb9fptVK-GhaP4eyVaHb2YoFW80q5d5EGy0jMW-NcGewstnq97-N0YQTYtWKQQZDOb177ZnXJQs-UL4nePl0diE2hmkazZq1oXtj12HVaXbzUvd4-WtY6zgKf2RP2av4bQiPpZGlvhQes-s-R9Pfed3IU_QPhC2JGW9VST9RFQymVZYqJ37TROZRXqPcaaIcIYzV4-1229wlaNo87iOg";
static const char *WRONG_KEY_TYPE = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYS0xIn0.eyJzdWIiOiJ1c2VyLTEiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuc3VwYWJhc2UuY28vYXV0aC92MSIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJleHAiOjQxMDI0NDQ4MDB9.7x8wxvuJ5Yd34GHO9bLGAjMPOGCodDLKxtFbZ-vuEvNLAg1o5kwU-k9ziGv--z7u650Ebq86Rb0uq-gL8paX4w";
static const char *NUMERIC_ACCOUNT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImVjLTEifQ.eyJzdWIiOjQyLCJpc3MiOiJodHRwczovL2V4YW1wbGUuc3VwYWJhc2UuY28vYXV0aC92MSIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJleHAiOjQxMDI0NDQ4MDB9.zoXM0p_isZz4bVzG6nNg4xwWcP83jXiQtmj5GencHw20MGhqKbRlKFzaPupn68r43cg40YirX0xVxpCZwVjL1A";
static const char *NO_ACCOUNT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYS0xIn0.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuc3VwYWJhc2UuY28vYXV0aC92MSIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJleHAiOjQxMDI0NDQ4MDB9.A8yT3Tn4qqyj5ZatKjKwZc7MwIbQVAeGT6EQzMC1_n9VbJJbcIvhd65oLLyfjlF65sbck0NGNry5oSHfLLehv9fFzqyi-VnUvs3t15Zn1B7fUQ4U3fBcmVrqiYt4sgudlRiE5_pS0RHVluUaAWFqzO3jCIgD1Nx8IDlw4aBszJaipi6YjSqqqq_xMqyyeSzilpSyS9MbMzi8gHwy25oLpJBKQeHKYSnNxWrrILDE_0HCYwnttVLjgrzkzu3M7tFQxeGlPf_-26x601DmPDSxZHwQNmqM8hkexJzU8SCRp-7nKjiPSQse2TDGyQaSEdB0AGgN686WjOJo0LLAz649tw";
static const char *NONE = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyLTEiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuc3VwYWJhc2UuY28vYXV0aC92MSIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJleHAiOjQxMDI0NDQ4MDB9.";
static const char *TAMPERED = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYS0xIn0.eyJzdWIiOiJhZG1pbiIsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5zdXBhYmFzZS5jby9hdXRoL3YxIiwiYXVkIjoiYXV0aGVudGljYXRlZCIsImV4cCI6NDEwMjQ0NDgwMH0.cSNoiYnBgo0WxeDrfys3yDbZB-MIVm5OmbyY-e0-bTEh40Scsld8SqZmDDvSqwcnM20zQAWIrcFC6iT6YzWmeetQD50XAWvuAwJVTtTxxibqs26q-lVo9TF6dzJiLYOV58f8ZM1mE-F-pQSsQkUpcuHlwfT836eZjQf7SREC05W-AQSmTsZ34Q-gv3DoBCFODAou4n-vLJM9_C-wXHitUoIXyv9562a9iBNuFps1aG0SP3R-QqkExpEBumav6D6zXvoiTTUinfRM41hW-NCYm3yGOqPzcZJHdV0YJHqf5Ca-AupzDexJFPYJmBwVxELeiHZPNMwdVaHVHUGqRx8ktw";

static const char *GOOGLE_VALID = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYS0xIn0.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiJnYW1lLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTEwMjQ4NDk1OTIxMjM4OTg2NDIwIiwiZXhwIjo0MTAyNDQ0ODAwfQ.SlRGQg27DYdesyie4KyZJn9uQkXQZ06yIkzV7X25GWH0_jhUBWwW4WH9XxnDdrLrzzBAM-_J1d0xUen7Kp-2i0XXJI0VUA_NnImXw_bx0jJzRTvOZjYJDEsZ83cl7Fi_KPaVWu9443xLBP0FtQX1SVMPlUBNUSrR7RXqW-JjxihrGcVV_bitZihJpQD8MylM6m3gQSdNhYaTkGALPP8GnyPO6vfXFaX3MaLdrCPT9CEv_lcLcue_gPeKvNNBST7Xd4AD7PyNSQoO7KxNfExLhve0UjvoHWjFVYu6q60VYy2bE95lTJ8i9L4hbba5i6d1SqbWtJASXh2mNCK9J0kXQQ";

static const int64_t NOW = 1800000000; // 2027.

static AuthToken _checker() {
	AuthToken checker;
	CHECK(checker.set_keys(JWKS) == OK);
	return checker;
}

TEST_CASE("[Modules][Authentication] A login service's keys (JWKS)") {
	_enable_plugin();
	AuthToken checker;
	CHECK_FALSE(checker.has_keys());
	CHECK(checker.set_keys(JWKS) == OK);
	CHECK(checker.get_key_count() == 2);
	CHECK(checker.has_keys());
	// Nothing it can use: the keys it had stay.
	ERR_PRINT_OFF;
	CHECK(checker.set_keys("not json") == ERR_PARSE_ERROR);
	CHECK(checker.set_keys("{\"keys\":[{\"kty\":\"oct\",\"k\":\"c2VjcmV0\"}]}") == ERR_INVALID_DATA);
	CHECK(checker.set_keys("{\"keys\":[{\"kty\":\"RSA\",\"use\":\"enc\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}") == ERR_INVALID_DATA);
	ERR_PRINT_ON;
	CHECK(checker.get_key_count() == 2);
}

TEST_CASE("[Modules][Authentication] A login token signed by the service names its account") {
	_enable_plugin();
	AuthToken checker = _checker();
	String account;
	CHECK(checker.check(RS256_VALID, NOW, account) == AuthToken::VALID);
	CHECK(account == "user-1");
	CHECK(checker.check(ES256_VALID, NOW, account) == AuthToken::VALID);
	CHECK(account == "user-2");
	// HS256 with the secret only the server has.
	CHECK(checker.check(HS256_VALID, NOW, account) == AuthToken::UNKNOWN_KEY);
	checker.secret = String("super-secret").to_utf8_buffer();
	CHECK(checker.check(HS256_VALID, NOW, account) == AuthToken::VALID);
	CHECK(account == "user-3");
	checker.secret = String("another-secret").to_utf8_buffer();
	CHECK(checker.check(HS256_VALID, NOW, account) == AuthToken::BAD_SIGNATURE);
	// Another claim as the account; a number is an account without ".0".
	checker.account_claim = "iss";
	CHECK(checker.check(RS256_VALID, NOW, account) == AuthToken::VALID);
	CHECK(account == "https://example.supabase.co/auth/v1");
	checker.account_claim = "sub";
	CHECK(checker.check(NUMERIC_ACCOUNT, NOW, account) == AuthToken::VALID);
	CHECK(account == "42");
	CHECK(checker.check(NO_ACCOUNT, NOW, account) == AuthToken::NO_ACCOUNT);
	// Unchecked: a host's own.
	CHECK(AuthToken::read_claim(ES256_VALID, "sub") == "user-2");
	CHECK(AuthToken::read_claim("nothing", "sub").is_empty());
}

TEST_CASE("[Modules][Authentication] A login token that is not valid") {
	_enable_plugin();
	AuthToken checker = _checker();
	String account;
	CHECK(checker.check("", NOW, account) == AuthToken::MALFORMED);
	CHECK(checker.check("a.b.c", NOW, account) == AuthToken::MALFORMED);
	CHECK(checker.check(TAMPERED, NOW, account) == AuthToken::BAD_SIGNATURE);
	CHECK(checker.check(NONE, NOW, account) == AuthToken::UNSUPPORTED);
	CHECK(checker.check(UNKNOWN_KID, NOW, account) == AuthToken::UNKNOWN_KEY);
	CHECK(checker.check(WRONG_KEY_TYPE, NOW, account) == AuthToken::BAD_SIGNATURE);
	CHECK(checker.check(EXPIRED, NOW, account) == AuthToken::EXPIRED);
	CHECK(checker.check(NOT_YET, NOW, account) == AuthToken::NOT_YET_VALID);
	CHECK(checker.check(NOT_YET, 4102444800, account) == AuthToken::VALID);
	// A minute of clock difference.
	CHECK(checker.check(EXPIRED, 1000000000 + 59, account) == AuthToken::VALID);
	CHECK(checker.check(EXPIRED, 1000000000 + 61, account) == AuthToken::EXPIRED);
	CHECK_FALSE(AuthToken::describe(AuthToken::EXPIRED).is_empty());
	CHECK(AuthToken::describe(AuthToken::VALID).is_empty());
}

TEST_CASE("[Modules][Authentication] A login token from another service or for another game") {
	_enable_plugin();
	AuthToken checker = _checker();
	String account;
	checker.issuers.push_back("https://example.supabase.co/auth/v1");
	CHECK(checker.check(RS256_VALID, NOW, account) == AuthToken::VALID);
	CHECK(checker.check(WRONG_ISSUER, NOW, account) == AuthToken::WRONG_ISSUER);
	checker.issuers.clear();
	CHECK(checker.check(WRONG_ISSUER, NOW, account) == AuthToken::VALID);
	checker.audiences.push_back("authenticated");
	CHECK(checker.check(RS256_VALID, NOW, account) == AuthToken::VALID);
	CHECK(checker.check(AUDIENCE_LIST, NOW, account) == AuthToken::VALID);
	checker.audiences = PackedStringArray({ "another-game" });
	CHECK(checker.check(RS256_VALID, NOW, account) == AuthToken::WRONG_AUDIENCE);
	CHECK(checker.check(AUDIENCE_LIST, NOW, account) == AuthToken::WRONG_AUDIENCE);
}

TEST_CASE("[Modules][Authentication] A login token for any platform's client of the game") {
	_enable_plugin();
	AuthToken checker = _checker();
	String account;
	checker.audiences = PackedStringArray({ "desktop-client", "authenticated" });
	CHECK(checker.check(RS256_VALID, NOW, account) == AuthToken::VALID);
	CHECK(checker.check(AUDIENCE_LIST, NOW, account) == AuthToken::VALID);
	checker.audiences = PackedStringArray({ "desktop-client", "web-client" });
	CHECK(checker.check(RS256_VALID, NOW, account) == AuthToken::WRONG_AUDIENCE);
}

TEST_CASE("[Modules][Authentication] An ES256 signature as mbedTLS reads it") {
	_enable_plugin();
	PackedByteArray raw;
	raw.resize(64);
	for (int i = 0; i < 64; i++) {
		raw.write[i] = i < 32 ? 0x80 + i : i; // r with its high bit: a zero before it.
	}
	const PackedByteArray der = AuthToken::ecdsa_signature_der(raw);
	REQUIRE(der.size() == 2 + (2 + 33) + (2 + 32));
	CHECK(der[0] == 0x30);
	CHECK(der[2] == 0x02);
	CHECK(der[3] == 33);
	CHECK(der[4] == 0x00);
	CHECK(der[5] == 0x80);
	CHECK(AuthToken::ecdsa_signature_der(PackedByteArray()).is_empty());
	CHECK(AuthToken::base64url_decode("AQAB") == PackedByteArray({ 1, 0, 1 }));
	CHECK(AuthToken::base64url_decode("-_8").size() == 2);
}

static void _clear_services() {
	const char *settings[] = { "authentication/google/desktop/client_id", "authentication/google/web/client_id", "authentication/google/ios/client_id", "authentication/supabase/url", "authentication/firebase/project_id", "authentication/auth0/domain", "authentication/auth0/desktop/client_id", "authentication/auth0/web/client_id", "authentication/custom/keys_url", "authentication/custom/issuer", "authentication/custom/audience" };
	for (const char *setting : settings) {
		ProjectSettings::get_singleton()->set_setting(setting, "");
	}
}

TEST_CASE("[Modules][Authentication] Each login service from its section of the settings") {
	_enable_plugin();
	_clear_services();
	CHECK(AuthToken::services_from_settings(false).is_empty());
	ProjectSettings::get_singleton()->set_setting("authentication/google/desktop/client_id", "game.apps.googleusercontent.com");
	ProjectSettings::get_singleton()->set_setting("authentication/google/web/client_id", "game-web.apps.googleusercontent.com");
	ProjectSettings::get_singleton()->set_setting("authentication/supabase/url", "https://example.supabase.co/");
	ProjectSettings::get_singleton()->set_setting("authentication/firebase/project_id", "my-game");
	ProjectSettings::get_singleton()->set_setting("authentication/auth0/domain", "https://tenant.auth0.com/");
	ProjectSettings::get_singleton()->set_setting("authentication/auth0/desktop/client_id", "auth0-client");
	ProjectSettings::get_singleton()->set_setting("authentication/auth0/web/client_id", "auth0-spa");
	ProjectSettings::get_singleton()->set_setting("authentication/custom/keys_url", "https://mine.example/jwks.json");
	ProjectSettings::get_singleton()->set_setting("authentication/custom/audience", "mine-desktop, mine-web");
	const Vector<AuthToken::Service> services = AuthToken::services_from_settings(false);
	REQUIRE(services.size() == 5);
	CHECK(services[0].name == "google");
	CHECK(services[0].keys_url == "https://www.googleapis.com/oauth2/v3/certs");
	CHECK(services[0].issuers.has("accounts.google.com"));
	// Each platform's client: a token for any of them is for this game.
	CHECK(services[0].audiences == PackedStringArray({ "game.apps.googleusercontent.com", "game-web.apps.googleusercontent.com" }));
	CHECK(services[1].name == "supabase");
	CHECK(services[1].keys_url == "https://example.supabase.co/auth/v1/.well-known/jwks.json");
	CHECK(services[1].issuers[0] == "https://example.supabase.co/auth/v1");
	CHECK(services[1].audiences == PackedStringArray({ "authenticated" }));
	CHECK(services[2].issuers[0] == "https://securetoken.google.com/my-game");
	CHECK(services[2].audiences == PackedStringArray({ "my-game" }));
	CHECK(services[3].keys_url == "https://tenant.auth0.com/.well-known/jwks.json");
	CHECK(services[3].issuers[0] == "https://tenant.auth0.com/");
	CHECK(services[3].audiences == PackedStringArray({ "auth0-client", "auth0-spa" }));
	CHECK(services[4].name == "custom");
	CHECK(services[4].issuers.is_empty());
	CHECK(services[4].audiences == PackedStringArray({ "mine-desktop", "mine-web" }));

	// A token goes to the service of its issuer; Custom without an issuer takes the others.
	CHECK(AuthToken::service_for(services, "https://accounts.google.com") == 0);
	CHECK(AuthToken::service_for(services, "https://example.supabase.co/auth/v1") == 1);
	CHECK(AuthToken::service_for(services, "https://elsewhere.example") == 4);
	ProjectSettings::get_singleton()->set_setting("authentication/custom/issuer", "https://mine.example");
	CHECK(AuthToken::service_for(AuthToken::services_from_settings(false), "https://elsewhere.example") == -1);
	CHECK(AuthToken::service_for(AuthToken::services_from_settings(false), "https://mine.example") == 4);

	// A secret only (HS256 of a service of its own): Custom takes it.
	_clear_services();
	const Vector<AuthToken::Service> secret_only = AuthToken::services_from_settings(true);
	REQUIRE(secret_only.size() == 1);
	CHECK(secret_only[0].name == "custom");
	CHECK(AuthToken::service_for(secret_only, "anything") == 0);
}

TEST_CASE("[Modules][Authentication] Offline, a game that logged in is its account, with its service") {
	_enable_plugin();
	Online *online = Online::get_singleton();
	REQUIRE(online);
	_clear_services();
	ProjectSettings::get_singleton()->set_setting("online/login/check", Online::LOGIN_TOKEN);
	ProjectSettings::get_singleton()->set_setting("authentication/supabase/url", "https://example.supabase.co");
	ProjectSettings::get_singleton()->set_setting("authentication/google/desktop/client_id", "game.apps.googleusercontent.com");
	online->login(RS256_VALID);
	CHECK(online->get_account(0) == "supabase:user-1");
	online->login(GOOGLE_VALID);
	CHECK(online->get_account(0) == "google:110248495921238986420");
	// A service the settings do not name: no account.
	ProjectSettings::get_singleton()->set_setting("authentication/supabase/url", "");
	online->login(RS256_VALID);
	CHECK(online->get_account(0).is_empty());
	online->login("");
	CHECK(online->get_account(0).is_empty());
	// Without the login check, a token is no account.
	ProjectSettings::get_singleton()->set_setting("online/login/check", Online::LOGIN_OFF);
	ERR_PRINT_OFF;
	online->login(GOOGLE_VALID);
	ERR_PRINT_ON;
	CHECK(online->get_account(0).is_empty());
	online->login("");
	_clear_services();
}

} // namespace TestAuthToken
