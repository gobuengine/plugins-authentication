/**************************************************************************/
/*  auth_itch.cpp                                                         */
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

#include "authentication.h"

#include <memory>

using gobu::Value;

// itch.io's OAuth (itch.io/docs/api/oauth): the code with PKCE is traded at api.itch.io/oauth/token like any other
// service's (auth_sign_in.cpp); its access token is not a JWT and doesn't expire, so who the player is comes from
// GET api.itch.io/profile with it, on the game (for signed_in) and on a server (for the account).

static constexpr int OK = 0;
static constexpr int HTTP_GET = 0; // HTTPClient.METHOD_GET
static constexpr int RESULT_SUCCESS = 0; // HTTPRequest.RESULT_SUCCESS

static std::string _itch_api() {
	return gobu::has_environment("GOBU_ITCH_API_URL") ? gobu::environment("GOBU_ITCH_API_URL") : std::string("https://api.itch.io");
}

static Value _itch_headers(const std::string &p_token) {
	Value headers = Value::array();
	headers.push_back("Authorization: Bearer " + p_token);
	headers.push_back("Accept: application/json");
	return headers;
}

// The "user" of /profile's answer, or nil.
static Value _itch_user(int p_result, int p_code, const std::string &p_body) {
	if (p_result != RESULT_SUCCESS || p_code != 200) {
		return Value();
	}
	Value json = gobu::instantiate("JSON");
	if (json.call("parse", { p_body }).to_int() != OK) {
		return Value();
	}
	const Value answer = json.call("get_data");
	const Value user = answer.type() == GOBU_TYPE_DICTIONARY ? answer.get("user") : Value();
	return user.type() == GOBU_TYPE_DICTIONARY && !user.get("id", "").str().empty() ? user : Value();
}

static std::string _itch_id(const Value &p_user) {
	// A number in JSON: a float here, and an id 42 is "42", not "42.0".
	const Value id = p_user.get("id");
	return id.type() == GOBU_TYPE_FLOAT || id.type() == GOBU_TYPE_INT ? std::to_string(id.to_int()) : id.str();
}

void Authentication::_itch_sign_in_profile(const std::string &p_token) {
	GobuObject *request = _internal_request(sign_in_profile_request, "AuthSignInProfile", [this, p_token](int p_result, int p_code, const std::string &p_body) {
		if (!signing_in) {
			return;
		}
		const Value user = _itch_user(p_result, p_code, p_body);
		if (user.is_nil()) {
			_sign_in_end(std::string(), Value::dictionary(), p_result != RESULT_SUCCESS ? "Could not reach itch.io for the player's profile (result " + std::to_string(p_result) + ")." : "itch.io did not give the player's profile (HTTP " + std::to_string(p_code) + ").");
			return;
		}
		Value data = Value::dictionary();
		data.set("service", "itch");
		data.set("id", _itch_id(user));
		data.set("username", user.get("username", "").str());
		data.set("display_name", user.get("display_name", "").str());
		data.set("avatar_url", user.get("cover_url", "").str());
		_sign_in_end(ITCH_PREFIX + p_token, data, std::string());
	});
	if (!request || gobu::call(request, "request", { _itch_api() + "/profile", _itch_headers(p_token), HTTP_GET, "" }).to_int() != OK) {
		_sign_in_end(std::string(), Value::dictionary(), "Could not ask itch.io for the player's profile.");
	}
}

void Authentication::_check_itch_token(const std::string &p_token, const Value &p_done) {
	// Only a game that set up its itch.io OAuth application takes them.
	if (AuthToken::client_ids("itch").empty()) {
		p_done.call("call", { std::string(), std::string("The login is from a service this game does not take.") });
		return;
	}
	if (p_token.empty()) {
		p_done.call("call", { std::string(), std::string("The itch.io login has no token.") });
		return;
	}
	// A request of its own for each: several players may log in at once. It goes when it answers.
	std::shared_ptr<GobuObjectId> id = std::make_shared<GobuObjectId>(0);
	static int count = 0;
	GobuObject *request = _internal_request(*id, "AuthItch_" + std::to_string(++count), [id, p_done](int p_result, int p_code, const std::string &p_body) {
		if (GobuObject *own = gobu::object_of(*id)) {
			gobu::call(own, "queue_free");
		}
		const Value user = _itch_user(p_result, p_code, p_body);
		if (!user.is_nil()) {
			p_done.call("call", { "itch:" + _itch_id(user), std::string() });
		} else if (p_result != RESULT_SUCCESS) {
			p_done.call("call", { std::string(), "The server could not reach itch.io to check the login (result " + std::to_string(p_result) + ")." });
		} else {
			p_done.call("call", { std::string(), p_code == 401 || p_code == 403 ? std::string("itch.io did not take the login (a revoked or forged token).") : "itch.io did not check the login (HTTP " + std::to_string(p_code) + ")." });
		}
	});
	if (!request || gobu::call(request, "request", { _itch_api() + "/profile", _itch_headers(p_token), HTTP_GET, "" }).to_int() != OK) {
		if (GobuObject *own = gobu::object_of(*id)) {
			gobu::call(own, "queue_free");
		}
		p_done.call("call", { std::string(), std::string("The server could not ask itch.io to check the login.") });
	}
}
