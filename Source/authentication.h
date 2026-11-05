/**************************************************************************/
/*  authentication.h                                                      */
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

#include "auth_sign_in.h"
#include "auth_token.h"

#include <functional>
#include <string>
#include <vector>

// The Authentication plugin: players sign in with a service (Google, Supabase, Firebase, Auth0 or any other) and
// the game has their token, to call the service's API or to join an online game; a server checks those tokens
// with each service's keys. A library of its own (gobu_plugin.h): Gobu loads it only in a project that enabled it,
// and then there are its class, its singleton and its settings (Project Settings > Authentication).
class Authentication {
public:
	static constexpr const char *CLASS_NAME = "Authentication";
	// The HS256 secret of a service that signs with one, on the server only: never in the project (it goes with
	// the game).
	static constexpr const char *SECRET_ENVIRONMENT = "GOBU_AUTH_SECRET";

	static Authentication *singleton;
	GobuObject *self = nullptr; // Its object: the singleton.

	// The plugin's class: its methods, signals and settings (gobu_plugin_init()).
	static bool register_class();
	// Once a frame (the plugin's process callback).
	void frame();

	// Signs in with a service in the player's browser ("google", "supabase", "auth0", "oauth": the Custom one), on
	// computers and in web games; then signed_in, or sign_in_failed. An Error code.
	int sign_in_with(const std::string &p_provider, const gobu::Value &p_options);
	void cancel_sign_in();
	bool is_signing_in() const { return signing_in; }
	void sign_out();

	std::string get_token() const { return token; }
	gobu::Value get_session() const { return session; }
	// "<service>:<id>": the one this game signed in with, or any token's (unchecked: what it says).
	std::string get_account() const;
	std::string account_of(const std::string &p_token) const;

	// A server: whether a token is one of the services of the settings, for this game; then p_done(account,
	// reason) (the account empty when it is not). It may answer later: the service's keys are read first.
	void check_token(const std::string &p_raw_token, const gobu::Value &p_done);

	explicit Authentication(GobuObject *p_self);
	~Authentication();

private:
	// This game's session: the token it signed in with, and the service's whole answer.
	std::string token;
	gobu::Value session;

	// What waits for the next frame (as call_deferred: never inside the caller).
	std::vector<std::function<void()>> later;
	void _later(std::function<void()> p_function);

	// Checking tokens (a server): the services of the settings, each with its own keys, read when a token needs
	// them (again if one comes with a key it does not have, at most once a minute).
	struct Service {
		AuthToken::Service settings;
		AuthToken checker;
		GobuObjectId keys_request = 0;
		uint64_t keys_read_msec = 0;
		bool keys_reading = false;
	};
	struct Waiting {
		std::string token;
		std::string service;
		gobu::Value done;
	};
	std::vector<Service> services;
	std::vector<Waiting> waiting;
	void _configure_services();
	int _find_service(const std::string &p_name) const;
	void _read_keys(const std::string &p_service);
	void _on_keys_read(int p_result, int p_code, const std::string &p_body, const std::string &p_service);

	// Signing in in the browser (auth_sign_in.cpp): the address of this computer where the browser comes back
	// (or, in a web game, the page that does), what it asked there, and the code traded for the token.
	struct SignInVisit {
		gobu::Value peer; // StreamPeerTCP.
		std::string received;
		uint64_t since = 0;
	};
	bool signing_in = false;
	bool sign_in_exchanging = false;
	AuthSignIn::Flow sign_in_flow;
	std::vector<gobu::Value> sign_in_servers; // TCPServer.
	std::vector<SignInVisit> sign_in_visits;
	std::string sign_in_verifier; // PKCE.
	std::string sign_in_state;
	std::string sign_in_nonce; // A web game's ID token (Google) carries it.
	std::string sign_in_redirect;
	gobu::Value sign_in_web_callback; // A web game: the JavaScript callback its page's answer comes to.
	uint64_t sign_in_deadline = 0;
	GobuObjectId sign_in_page_request = 0; // Following the page itself (AuthSignIn::FOLLOW_ENVIRONMENT).
	GobuObjectId sign_in_token_request = 0;
	// An HTTPRequest of its own in the scene (reused): p_done(result, code, body).
	GobuObject *_internal_request(GobuObjectId &r_id, const std::string &p_name, std::function<void(int, int, const std::string &)> p_done);
	void _sign_in_frame();
	int _sign_in_web(const AuthSignIn::Flow &p_flow);
	void _on_web_sign_in(const gobu::Value &p_args);
	void _sign_in_follow(const std::string &p_address);
	std::string _sign_in_refusal(const gobu::Value &p_params) const;
	void _sign_in_came_back(const gobu::Value &p_params);
	void _on_sign_in_token(int p_result, int p_code, const std::string &p_body);
	void _sign_in_stop();
	void _sign_in_end(const std::string &p_token, const gobu::Value &p_data, const std::string &p_error);
	void _sign_in_failed(const std::string &p_reason);

	// Poki (auth_poki.cpp): a web game on poki.com with the Poki plugin, whose page has Poki's SDK. Its sign-in gives
	// "poki:<Poki's token>" (it lasts a minute), and a server checks it with Poki with the game's team key, in an
	// environment variable of the server (never in the project: it goes with the game).
	static constexpr const char *POKI_PREFIX = "poki:";
	static constexpr const char *POKI_KEY_ENVIRONMENT = "GOBU_POKI_TEAM_KEY";
	static constexpr const char *POKI_VERIFY_ENVIRONMENT = "GOBU_POKI_VERIFY_URL"; // The tests' mock of Poki's.
	bool sign_in_poki = false; // The sign-in going on is Poki's.
	int _sign_in_poki();
	void _on_poki_sign_in(const gobu::Value &p_args);
	void _check_poki_token(const std::string &p_token, const gobu::Value &p_done);

	// CrazyGames (auth_crazygames.cpp): a web game on CrazyGames with the CrazyGames plugin. Its sign-in gives
	// "crazygames:<its token>" (RS256, an hour), checked with CrazyGames's keys for this game's id (Project Settings >
	// Authentication > CrazyGames > Game Id); the account is "crazygames:<userId>".
	bool sign_in_crazygames = false;

	// itch.io (auth_itch.cpp): Authentication.sign_in_with("itch") is the OAuth sign-in of the game's itch.io OAuth
	// application; the token is "itch:<access token>" (it doesn't expire, and doesn't say which game it is for). A
	// server checks it with itch.io's API (its profile); the account is "itch:<user id>".
	static constexpr const char *ITCH_PREFIX = "itch:";
	static constexpr const char *ITCH_API_ENVIRONMENT = "GOBU_ITCH_API_URL"; // The tests' mock of api.itch.io.
	GobuObjectId sign_in_profile_request = 0;
	void _itch_sign_in_profile(const std::string &p_token);
	void _check_itch_token(const std::string &p_token, const gobu::Value &p_done);
	int _sign_in_crazygames();
	void _on_crazygames_sign_in(const gobu::Value &p_args);
	void _emit(const char *p_signal, std::initializer_list<gobu::Value> p_args = {});
};
