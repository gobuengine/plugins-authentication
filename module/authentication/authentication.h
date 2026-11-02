/**************************************************************************/
/*  auth_token.h                                                        */
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

#include "core/io/tcp_server.h"
#include "core/object/object.h"
#include "core/templates/local_vector.h"

class HTTPRequest;

// The Authentication plugin (Project Settings > Plugins: it comes with Gobu, a project adds it): players sign in
// with a service (Google, Supabase, Firebase, Auth0 or any other) and the game has their token, to call the
// service's API or to join an online game; a server checks those tokens with each service's keys. Its class, its
// singleton and its settings (Project Settings > Authentication) exist only in a project that enabled it.
class Authentication : public Object {
	GDCLASS(Authentication, Object);

public:
	static constexpr const char *PLUGIN_ID = "authentication";
	// The HS256 secret of a service that signs with one, on the server only: never in the project (it goes with
	// the game).
	static constexpr const char *SECRET_ENVIRONMENT = "GOBU_AUTH_SECRET";

private:
	static Authentication *singleton;

	// This game's session: the token it signed in with, and the service's whole answer.
	String token;
	Dictionary session;

	// Checking tokens (a server): the services of the settings, each with its own keys, read when a token needs
	// them (again if one comes with a key it does not have, at most once a minute).
	struct Service {
		AuthToken::Service settings;
		AuthToken checker;
		ObjectID keys_request;
		uint64_t keys_read_msec = 0;
		bool keys_reading = false;
	};
	struct Waiting {
		String token;
		String service;
		Callable done;
	};
	LocalVector<Service> services;
	LocalVector<Waiting> waiting;
	void _configure_services();
	int _find_service(const String &p_name) const;
	void _read_keys(const String &p_service);
	void _on_keys_read(int p_result, int p_code, const PackedStringArray &p_headers, const PackedByteArray &p_body, const String &p_service);

	// Signing in in the browser (auth_sign_in.cpp): the address of this computer where the browser comes back
	// (or, in a web game, the page that does), what it asked there, and the code traded for the token.
	struct SignInVisit {
		Ref<StreamPeerTCP> peer;
		PackedByteArray received;
		uint64_t since = 0;
	};
	bool signing_in = false;
	bool sign_in_exchanging = false;
	AuthSignIn::Flow sign_in_flow;
	LocalVector<Ref<TCPServer>> sign_in_servers;
	LocalVector<SignInVisit> sign_in_visits;
	String sign_in_verifier; // PKCE.
	String sign_in_state;
	String sign_in_nonce; // A web game's ID token (Google) carries it.
	String sign_in_redirect;
	Ref<RefCounted> sign_in_web_callback; // A web game: the JavaScript callback its page's answer comes to.
	uint64_t sign_in_deadline = 0;
	ObjectID sign_in_page_request; // Following the page itself (AuthSignIn::FOLLOW_ENVIRONMENT).
	ObjectID sign_in_token_request;
	HTTPRequest *_internal_request(ObjectID &r_id, const String &p_name, const Callable &p_done);
	void _sign_in_frame();
	Error _sign_in_web(const AuthSignIn::Flow &p_flow);
	void _on_web_sign_in(const Array &p_args);
	void _sign_in_follow(const String &p_address);
	String _sign_in_refusal(const Dictionary &p_params) const;
	void _sign_in_came_back(const Dictionary &p_params);
	void _on_sign_in_token(int p_result, int p_code, const PackedStringArray &p_headers, const PackedByteArray &p_body);
	void _on_sign_in_page(int p_result, int p_code, const PackedStringArray &p_headers, const PackedByteArray &p_body);
	void _sign_in_stop();
	void _sign_in_end(const String &p_token, const Dictionary &p_data, const String &p_error);
	void _sign_in_failed(const String &p_reason);

	// For Online (its hooks): a server checks a player's token; a game's own account.
	static void _online_check_token(const String &p_token, const Callable &p_done);
	static String _online_account_of(const String &p_token);

protected:
	static void _bind_methods();

public:
	static Authentication *get_singleton() { return singleton; }

	// Signs in with a service in the player's browser ("google", "supabase", "auth0", "oauth": the Custom one), on
	// computers and in web games; then signed_in, or sign_in_failed.
	Error sign_in_with(const String &p_provider, const Dictionary &p_options = Dictionary());
	void cancel_sign_in();
	bool is_signing_in() const { return signing_in; }
	void sign_out();

	String get_token() const { return token; }
	Dictionary get_session() const { return session; }
	// "<service>:<id>": the one this game signed in with, or any token's (unchecked: what it says).
	String get_account() const;
	String account_of(const String &p_token) const;

	// A server: whether a token is one of the services of the settings, for this game; then p_done(account,
	// reason) (the account empty when it is not). It may answer later: the service's keys are read first.
	void check_token(const String &p_token, const Callable &p_done);

	Authentication();
	~Authentication();
};
