/**************************************************************************/
/*  auth_poki.cpp                                                         */
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

// Poki's player accounts (developers.poki.com/guide/accounts): PokiSDK.login() (the page loads again when the
// player signs in), getToken() (a JWT for this game that lasts a minute) and getUser() ({username, avatarUrl}).
// A server gives the token to Poki's user-vault with the team's key and gets the player's user_id, the same for
// this game forever.

static constexpr int OK = 0;
static constexpr int ERR_UNAVAILABLE = 2;
static constexpr int HTTP_GET = 0; // HTTPClient.METHOD_GET
static constexpr int RESULT_SUCCESS = 0; // HTTPRequest.RESULT_SUCCESS
static constexpr const char *POKI_VERIFY_URL = "https://user-vault.poki.com/auth/verify-token";

// The page's part: Poki's sign-in, then the token and the player, back to done(token, name, avatar, error).
static const char *POKI_SIGN_IN_SCRIPT = R"(
if (!window.gobuPokiSignIn) {
	window.gobuPokiSignIn = function (done) {
		if (typeof PokiSDK === 'undefined') {
			done('', '', '', 'This page has no Poki SDK: enable the Poki plugin, whose web export puts it in the page.');
			return;
		}
		Promise.resolve().then(function () {
			return PokiSDK.login();
		}).then(function () {
			return Promise.all([PokiSDK.getToken(), PokiSDK.getUser()]);
		}).then(function (both) {
			const user = both[1] || {};
			if (!both[0]) {
				done('', '', '', 'The player is not signed in to Poki.');
				return;
			}
			done(String(both[0]), user.username ? String(user.username) : '', user.avatarUrl ? String(user.avatarUrl) : '', '');
		}, function (error) {
			done('', '', '', error && error.message ? 'Poki: ' + error.message : 'The Poki sign-in was closed.');
		});
	};
}
)";

static void _answer(const Value &p_done, const std::string &p_account, const std::string &p_reason) {
	p_done.call("call", { p_account, p_reason });
}

// Signing in (a web game).

int Authentication::_sign_in_poki() {
	GobuObject *js = gobu::singleton("JavaScriptBridge");
	if (!js || !gobu::has_feature("web")) {
		_later([this]() { _sign_in_failed("Signing in with Poki is for web games on Poki (with the Poki plugin)."); });
		return ERR_UNAVAILABLE;
	}
	gobu::call(js, "eval", { POKI_SIGN_IN_SCRIPT, true });
	const Value window = gobu::call(js, "get_interface", { "window" });
	// create_callback() calls it with an Array of the JavaScript arguments.
	sign_in_web_callback = gobu::call(js, "create_callback", { gobu::callable([this](const gobu::Args &p_args) {
		_on_poki_sign_in(p_args.empty() ? Value::array() : p_args[0]);
	}, self) });
	if (window.object() == nullptr || sign_in_web_callback.object() == nullptr) {
		_later([this]() { _sign_in_failed("This web game can't run JavaScript to sign in."); });
		return ERR_UNAVAILABLE;
	}
	signing_in = true;
	sign_in_exchanging = false;
	sign_in_poki = true;
	sign_in_flow = AuthSignIn::Flow();
	// Poki gives up after 45 seconds; a little more here, so its answer comes first.
	sign_in_deadline = gobu::ticks_msec() + 60000;
	GOBU_VERBOSE("Authentication: signing in with Poki.");
	gobu::call(window.object(), "gobuPokiSignIn", { sign_in_web_callback });
	return OK;
}

void Authentication::_on_poki_sign_in(const Value &p_args) {
	if (!signing_in || !sign_in_poki) {
		return;
	}
	sign_in_poki = false;
	const std::string poki_token = p_args.size() > 0 ? p_args.at(0).str() : std::string();
	const std::string error = p_args.size() > 3 ? p_args.at(3).str() : std::string("The Poki sign-in did not answer.");
	if (poki_token.empty()) {
		_sign_in_end(std::string(), Value::dictionary(), error.empty() ? std::string("The Poki sign-in did not answer.") : error);
		return;
	}
	Value data = Value::dictionary();
	data.set("service", "poki");
	data.set("username", p_args.size() > 1 ? p_args.at(1).str() : std::string());
	data.set("avatar_url", p_args.size() > 2 ? p_args.at(2).str() : std::string());
	_sign_in_end(POKI_PREFIX + poki_token, data, std::string());
}

// Checking a token (a server): Poki answers with the player's user_id, which the account is made of.

void Authentication::_check_poki_token(const std::string &p_token, const Value &p_done) {
	const std::string key = gobu::environment(POKI_KEY_ENVIRONMENT);
	if (key.empty()) {
		static bool told = false;
		if (!told) {
			told = true;
			GOBU_ERROR(std::string("Authentication: a player logs in with Poki, but this server has no Poki team key (the ") + POKI_KEY_ENVIRONMENT + " environment variable, from Poki's account manager): Poki logins are turned away.");
		}
		_answer(p_done, std::string(), "This server takes no Poki logins.");
		return;
	}
	if (p_token.empty()) {
		_answer(p_done, std::string(), "The Poki login has no token.");
		return;
	}
	const std::string url = gobu::has_environment(POKI_VERIFY_ENVIRONMENT) ? gobu::environment(POKI_VERIFY_ENVIRONMENT) : std::string(POKI_VERIFY_URL);
	// A request of its own for each: several players may log in at once. It goes when it answers.
	std::shared_ptr<GobuObjectId> id = std::make_shared<GobuObjectId>(0);
	static int count = 0;
	GobuObject *request = _internal_request(*id, "AuthPoki_" + std::to_string(++count), [id, p_done](int p_result, int p_code, const std::string &p_body) {
		if (GobuObject *own = gobu::object_of(*id)) {
			gobu::call(own, "queue_free");
		}
		if (p_result != RESULT_SUCCESS) {
			_answer(p_done, std::string(), "The server could not reach Poki to check the login (result " + std::to_string(p_result) + ").");
			return;
		}
		if (p_code != 200) {
			_answer(p_done, std::string(), p_code == 401 || p_code == 403 ? std::string("Poki did not take the login (an old or forged token).") : "Poki did not check the login (HTTP " + std::to_string(p_code) + ").");
			return;
		}
		// JSON.parse() and not parse_string(): an answer that isn't JSON prints nothing.
		Value json = gobu::instantiate("JSON");
		const Value answer = json.call("parse", { p_body }).to_int() == OK ? json.call("get_data") : Value();
		const std::string user_id = answer.type() == GOBU_TYPE_DICTIONARY ? answer.get("user_id", "").str() : std::string();
		if (user_id.empty()) {
			_answer(p_done, std::string(), "Poki's answer has no user_id.");
			return;
		}
		_answer(p_done, "poki:" + user_id, std::string());
	});
	Value headers = Value::array();
	headers.push_back("Authorization: Bearer " + p_token);
	headers.push_back("X-Poki-Team-Api-Key: " + key);
	headers.push_back("Accept: application/json");
	if (!request || gobu::call(request, "request", { url, headers, HTTP_GET, "" }).to_int() != OK) {
		if (GobuObject *own = gobu::object_of(*id)) {
			gobu::call(own, "queue_free");
		}
		_answer(p_done, std::string(), "The server could not ask Poki to check the login.");
	}
}
