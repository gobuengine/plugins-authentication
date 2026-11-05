/**************************************************************************/
/*  auth_crazygames.cpp                                                   */
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

using gobu::Value;

// CrazyGames's player accounts (docs.crazygames.com/sdk/user): the player signs in with CrazyGames's prompt
// (showAuthPrompt) when they aren't yet, and getUserToken() gives a JWT for this game (RS256, an hour, "userId" and
// "gameId"), checked with CrazyGames's public keys. The CrazyGames plugin started the SDK.

static constexpr int OK = 0;
static constexpr int ERR_UNAVAILABLE = 2;

// The page's part: the sign-in, then the token and the player, back to done(token, name, avatar, error).
static const char *CRAZYGAMES_SIGN_IN_SCRIPT = R"(
if (!window.gobuCrazyGamesSignIn) {
	window.gobuCrazyGamesSignIn = function (done) {
		const sdk = window.CrazyGames && window.CrazyGames.SDK;
		if (!sdk || !sdk.user) {
			done('', '', '', 'This page has no CrazyGames SDK: enable the CrazyGames plugin, whose web export puts it in the page.');
			return;
		}
		let user = null;
		Promise.resolve().then(function () {
			return sdk.user.getUser();
		}).then(function (signed) {
			return signed || sdk.user.showAuthPrompt();
		}).then(function (signed) {
			user = signed || {};
			return sdk.user.getUserToken({ signingKeyType: 'IN_GAME_AUTH' });
		}).then(function (token) {
			if (!token) {
				done('', '', '', 'The player is not signed in to CrazyGames.');
				return;
			}
			done(String(token), user.username ? String(user.username) : '', user.profilePictureUrl ? String(user.profilePictureUrl) : '', '');
		}, function (error) {
			done('', '', '', error && error.message ? 'CrazyGames: ' + error.message : 'The CrazyGames sign-in was closed.');
		});
	};
}
)";

int Authentication::_sign_in_crazygames() {
	GobuObject *js = gobu::singleton("JavaScriptBridge");
	if (!js || !gobu::has_feature("web")) {
		_later([this]() { _sign_in_failed("Signing in with CrazyGames is for web games on CrazyGames (with the CrazyGames plugin)."); });
		return ERR_UNAVAILABLE;
	}
	gobu::call(js, "eval", { CRAZYGAMES_SIGN_IN_SCRIPT, true });
	const Value window = gobu::call(js, "get_interface", { "window" });
	// create_callback() calls it with an Array of the JavaScript arguments.
	sign_in_web_callback = gobu::call(js, "create_callback", { gobu::callable([this](const gobu::Args &p_args) {
		_on_crazygames_sign_in(p_args.empty() ? Value::array() : p_args[0]);
	}, self) });
	if (window.object() == nullptr || sign_in_web_callback.object() == nullptr) {
		_later([this]() { _sign_in_failed("This web game can't run JavaScript to sign in."); });
		return ERR_UNAVAILABLE;
	}
	signing_in = true;
	sign_in_exchanging = false;
	sign_in_crazygames = true;
	sign_in_flow = AuthSignIn::Flow();
	sign_in_deadline = gobu::ticks_msec() + uint64_t(AuthSignIn::TIMEOUT * 1000.0);
	GOBU_VERBOSE("Authentication: signing in with CrazyGames.");
	gobu::call(window.object(), "gobuCrazyGamesSignIn", { sign_in_web_callback });
	return OK;
}

void Authentication::_on_crazygames_sign_in(const Value &p_args) {
	if (!signing_in || !sign_in_crazygames) {
		return;
	}
	sign_in_crazygames = false;
	const std::string crazy_token = p_args.size() > 0 ? p_args.at(0).str() : std::string();
	const std::string error = p_args.size() > 3 ? p_args.at(3).str() : std::string();
	if (crazy_token.empty()) {
		_sign_in_end(std::string(), Value::dictionary(), error.empty() ? std::string("The CrazyGames sign-in did not answer.") : error);
		return;
	}
	Value data = Value::dictionary();
	data.set("service", "crazygames");
	data.set("username", p_args.size() > 1 ? p_args.at(1).str() : std::string());
	data.set("avatar_url", p_args.size() > 2 ? p_args.at(2).str() : std::string());
	_sign_in_end("crazygames:" + crazy_token, data, std::string());
}
