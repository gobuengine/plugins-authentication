/**************************************************************************/
/*  auth_sign_in.h                                                        */
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

#include "gobu.hpp"

#include <string>
#include <vector>

// Signing in with a service in the system's browser, as games and apps on a computer do (OAuth 2.0 for
// installed apps, RFC 8252, with PKCE, RFC 7636): the game opens the service's page, the player signs in
// there (Google, Discord, a Supabase project's providers...), and the browser comes back to an address of
// this computer where the game listens (http://127.0.0.1:<port>); the game then trades the code it got for
// the token. Authentication.sign_in_with() runs it (authentication.cpp); these are its pieces.
struct AuthSignIn {
	// For tests and headless runs: the game opens the sign-in page itself, as a browser that follows its
	// redirects (a service that signs in at once, such as a test one, comes back to it without a player).
	static constexpr const char *FOLLOW_ENVIRONMENT = "GOBU_SIGN_IN_FOLLOW";
	static constexpr double TIMEOUT = 300.0; // Seconds for the player to sign in.

	struct Flow {
		std::string authorize_url;
		std::string token_url;
		std::string client_id;
		std::string client_secret; // Some services ask for it also from installed games (Google's "Desktop app").
		std::string scope;
		gobu::Value params; // More of the sign-in page's parameters (prompt, login_hint...): a Dictionary.
		std::string token_field; // Of the service's answer; empty: id_token when there is one, else access_token.
		int port = 0; // Where the game listens; 0: any free one (services that ask for an exact address: fixed).
		// The return address as the service has it registered ("http://localhost:43210"), exactly; empty:
		// http://127.0.0.1:<port>/. The game listens where it can come: 127.0.0.1, and ::1 for "localhost".
		std::string redirect_uri;
		std::vector<std::string> listen_on;
		// In a web game (a browser keeps no secret): Google's ID token straight back in the page's address
		// (OpenID Connect's implicit flow, with a nonce); the others, a code with PKCE traded by the game.
		bool web = false;
		bool id_token_back = false;
		// Supabase Auth: its own parameters (provider, redirect_to) and code exchange (grant_type=pkce).
		bool supabase = false;
		// itch.io: its token is not a JWT; the player's profile comes from its API after the code is traded.
		bool itch = false;
		std::string supabase_url;
		std::string supabase_key;
		std::string supabase_provider;
	};

	// "google", "supabase", "auth0" or "oauth" (any other service: its addresses), and the options.
	static bool make_flow(const std::string &p_provider, const gobu::Value &p_options, Flow &r_flow, std::string &r_error, bool p_web = false);
	// The options, with what the service's section of Project Settings > Authentication says (the ones given win).
	static gobu::Value options_from_settings(const std::string &p_provider, const gobu::Value &p_options);
	// The sign-in page, with what the game sends: where to come back, and the PKCE challenge and state.
	static std::string authorize_address(const Flow &p_flow, const std::string &p_redirect, const std::string &p_challenge, const std::string &p_state, const std::string &p_nonce = std::string());
	// What came back in the page's address: its query and, in a web game, its fragment (#id_token=...).
	static gobu::Value parse_answer(const std::string &p_address);

	static std::string random_text(int p_bytes); // URL-safe base64 of random bytes.
	static std::string pkce_challenge(const std::string &p_verifier); // S256.
	static std::string query(const gobu::Value &p_params); // a=1&b=2, percent-encoded.
	static gobu::Value parse_query(const std::string &p_query);
	// The page the browser shows once it came back to the game.
	static std::string page(const std::string &p_game, bool p_signed_in, const std::string &p_detail);
};
