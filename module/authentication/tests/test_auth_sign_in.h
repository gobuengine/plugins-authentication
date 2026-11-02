/**************************************************************************/
/*  test_auth_sign_in.h                                                 */
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
#include "../auth_sign_in.h"
#include "core/config/project_settings.h"

#include "Tests/test_macros.h"

namespace TestAuthSignIn {

// The plugin, as a project that enabled it (its class, its singleton, its settings).
static void _enable_plugin() {
	if (!GobuPlugins::is_loaded(Authentication::PLUGIN_ID)) {
		GobuPlugins::load(Authentication::PLUGIN_ID);
	}
}

TEST_CASE("[Modules][Authentication] Signing in: PKCE and the browser's addresses") {
	_enable_plugin();
	// RFC 7636, appendix B.
	CHECK(AuthSignIn::pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
	const String verifier = AuthSignIn::random_text(32);
	CHECK(verifier.length() == 43); // 43 to 128 characters.
	CHECK(AuthSignIn::random_text(32) != verifier);
	CHECK_FALSE(verifier.contains_char('+'));
	CHECK_FALSE(verifier.contains_char('/'));
	CHECK_FALSE(verifier.contains_char('='));

	Dictionary params;
	params["redirect_uri"] = "http://127.0.0.1:4000/";
	params["scope"] = "openid email";
	const String text = AuthSignIn::query(params);
	CHECK(text == "redirect_uri=http%3A%2F%2F127.0.0.1%3A4000%2F&scope=openid%20email");
	const Dictionary back = AuthSignIn::parse_query(text + "&state=a+b&empty");
	CHECK(String(back["redirect_uri"]) == "http://127.0.0.1:4000/");
	CHECK(String(back["scope"]) == "openid email");
	CHECK(String(back["state"]) == "a b");
	CHECK(back.has("empty"));
}

TEST_CASE("[Modules][Authentication] Signing in: the services") {
	_enable_plugin();
	AuthSignIn::Flow flow;
	String error;
	Dictionary options;
	// Google: its addresses, the game's client.
	CHECK(AuthSignIn::make_flow("google", options, flow, error) == ERR_INVALID_PARAMETER);
	CHECK(error.contains("client_id"));
	options["client_id"] = "game.apps.googleusercontent.com";
	options["params"] = Dictionary({ { "prompt", "select_account" } });
	REQUIRE(AuthSignIn::make_flow("Google", options, flow, error) == OK);
	CHECK(flow.token_url == "https://oauth2.googleapis.com/token");
	CHECK(flow.token_field == "id_token");
	const String google = AuthSignIn::authorize_address(flow, "http://127.0.0.1:4000/", "CHALLENGE", "STATE");
	CHECK(google.begins_with("https://accounts.google.com/o/oauth2/v2/auth?"));
	const Dictionary sent = AuthSignIn::parse_query(google.get_slicec('?', 1));
	CHECK(String(sent["response_type"]) == "code");
	CHECK(String(sent["client_id"]) == "game.apps.googleusercontent.com");
	CHECK(String(sent["redirect_uri"]) == "http://127.0.0.1:4000/");
	CHECK(String(sent["scope"]) == "openid email profile");
	CHECK(String(sent["state"]) == "STATE");
	CHECK(String(sent["code_challenge"]) == "CHALLENGE");
	CHECK(String(sent["code_challenge_method"]) == "S256");
	CHECK(String(sent["prompt"]) == "select_account");

	// Supabase: its project's providers, its own parameters.
	Dictionary supabase;
	supabase["url"] = "https://project.supabase.co/";
	supabase["key"] = "anon";
	CHECK(AuthSignIn::make_flow("supabase", supabase, flow, error) == ERR_INVALID_PARAMETER);
	supabase["provider"] = "discord";
	REQUIRE(AuthSignIn::make_flow("supabase", supabase, flow, error) == OK);
	CHECK(flow.token_url == "https://project.supabase.co/auth/v1/token?grant_type=pkce");
	const Dictionary asked = AuthSignIn::parse_query(AuthSignIn::authorize_address(flow, "http://127.0.0.1:4000/", "C", "S").get_slicec('?', 1));
	CHECK(String(asked["provider"]) == "discord");
	CHECK(String(asked["redirect_to"]) == "http://127.0.0.1:4000/");
	CHECK(String(asked["code_challenge_method"]) == "s256");
	CHECK_FALSE(asked.has("state"));

	// Any other service: its addresses.
	Dictionary other;
	other["client_id"] = "123";
	CHECK(AuthSignIn::make_flow("oauth", other, flow, error) == ERR_INVALID_PARAMETER);
	other["authorize_url"] = "https://discord.com/oauth2/authorize";
	other["token_url"] = "https://discord.com/api/oauth2/token";
	other["scope"] = "identify";
	other["port"] = 43210;
	REQUIRE(AuthSignIn::make_flow("oauth", other, flow, error) == OK);
	CHECK(flow.port == 43210);
	CHECK(flow.token_field.is_empty()); // id_token when there is one, else access_token.
	CHECK(AuthSignIn::make_flow("steam", other, flow, error) == ERR_INVALID_PARAMETER);
	other["port"] = 70000;
	CHECK(AuthSignIn::make_flow("oauth", other, flow, error) == ERR_INVALID_PARAMETER);
}

TEST_CASE("[Modules][Authentication] Signing in: Auth0, and each service's section of the settings") {
	_enable_plugin();
	AuthSignIn::Flow flow;
	String error;
	Dictionary auth0;
	auth0["client_id"] = "auth0-client";
	CHECK(AuthSignIn::make_flow("auth0", auth0, flow, error) == ERR_INVALID_PARAMETER);
	auth0["domain"] = "https://tenant.auth0.com/";
	REQUIRE(AuthSignIn::make_flow("auth0", auth0, flow, error) == OK);
	CHECK(flow.authorize_url == "https://tenant.auth0.com/authorize");
	CHECK(flow.token_url == "https://tenant.auth0.com/oauth/token");
	CHECK(flow.token_field == "id_token");

	// This platform's block (the tests run on a computer: Desktop), and what the section shares.
	CHECK(AuthToken::platform() == "desktop");
	ProjectSettings::get_singleton()->set_setting("authentication/google/desktop/client_id", "game.apps.googleusercontent.com");
	ProjectSettings::get_singleton()->set_setting("authentication/google/desktop/client_secret", "desktop-secret");
	ProjectSettings::get_singleton()->set_setting("authentication/google/web/client_id", "game-web.apps.googleusercontent.com");
	ProjectSettings::get_singleton()->set_setting("authentication/supabase/url", "https://project.supabase.co");
	ProjectSettings::get_singleton()->set_setting("authentication/supabase/anon_key", "anon");
	ProjectSettings::get_singleton()->set_setting("authentication/custom/authorize_url", "https://mine.example/authorize");
	const Dictionary google = AuthSignIn::options_from_settings("google", Dictionary());
	CHECK(String(google["client_id"]) == "game.apps.googleusercontent.com"); // Not the Web one.
	CHECK(String(google["client_secret"]) == "desktop-secret");
	CHECK_FALSE(google.has("port")); // Google takes any.
	Dictionary given;
	given["provider"] = "discord";
	given["port"] = 5000;
	const Dictionary supabase = AuthSignIn::options_from_settings("supabase", given);
	CHECK(String(supabase["url"]) == "https://project.supabase.co");
	CHECK(String(supabase["key"]) == "anon");
	CHECK(String(supabase["provider"]) == "discord");
	CHECK(int(supabase["port"]) == 5000); // What the code gives wins.
	CHECK(int(AuthSignIn::options_from_settings("supabase", Dictionary())["port"]) == 43210);
	CHECK(String(AuthSignIn::options_from_settings("oauth", Dictionary())["authorize_url"]) == "https://mine.example/authorize");
	const char *settings[] = { "authentication/google/desktop/client_id", "authentication/google/desktop/client_secret", "authentication/google/web/client_id", "authentication/supabase/url", "authentication/supabase/anon_key", "authentication/custom/authorize_url" };
	for (const char *setting : settings) {
		ProjectSettings::get_singleton()->set_setting(setting, "");
	}
}

TEST_CASE("[Modules][Authentication] Signing in: the return address as the service has it registered") {
	_enable_plugin();
	AuthSignIn::Flow flow;
	String error;
	Dictionary options;
	options["client_id"] = "game.apps.googleusercontent.com";
	REQUIRE(AuthSignIn::make_flow("google", options, flow, error) == OK);
	CHECK(flow.redirect_uri.is_empty());
	CHECK(flow.listen_on == PackedStringArray({ "127.0.0.1" }));
	options["redirect_uri"] = "http://localhost:43210";
	REQUIRE(AuthSignIn::make_flow("google", options, flow, error) == OK);
	CHECK(flow.port == 43210);
	CHECK(flow.listen_on == PackedStringArray({ "127.0.0.1", "::1" }));
	const Dictionary sent = AuthSignIn::parse_query(AuthSignIn::authorize_address(flow, flow.redirect_uri, "C", "S").get_slicec('?', 1));
	CHECK(String(sent["redirect_uri"]) == "http://localhost:43210"); // Exactly as registered.
	options["redirect_uri"] = "http://127.0.0.1:5000/callback";
	REQUIRE(AuthSignIn::make_flow("google", options, flow, error) == OK);
	CHECK(flow.port == 5000);
	CHECK(flow.listen_on == PackedStringArray({ "127.0.0.1" }));
	options["redirect_uri"] = "http://[::1]:5001/";
	REQUIRE(AuthSignIn::make_flow("google", options, flow, error) == OK);
	CHECK(flow.listen_on == PackedStringArray({ "::1" }));
	// Not an address of this computer, or without its port.
	options["redirect_uri"] = "https://mygame.example/callback";
	CHECK(AuthSignIn::make_flow("google", options, flow, error) == ERR_INVALID_PARAMETER);
	options["redirect_uri"] = "http://localhost/";
	CHECK(AuthSignIn::make_flow("google", options, flow, error) == ERR_INVALID_PARAMETER);
}

TEST_CASE("[Modules][Authentication] Signing in in a web game") {
	_enable_plugin();
	AuthSignIn::Flow flow;
	String error;
	Dictionary options;
	options["client_id"] = "game-web.apps.googleusercontent.com";
	// Google: the ID token straight back (a browser keeps no secret), with a nonce.
	REQUIRE(AuthSignIn::make_flow("google", options, flow, error, true) == OK);
	CHECK(flow.web);
	CHECK(flow.id_token_back);
	CHECK(flow.listen_on.is_empty());
	const Dictionary sent = AuthSignIn::parse_query(AuthSignIn::authorize_address(flow, "https://game.example/index.sign_in.html", "C", "STATE", "NONCE").get_slicec('?', 1));
	CHECK(String(sent["response_type"]) == "id_token");
	CHECK(String(sent["redirect_uri"]) == "https://game.example/index.sign_in.html");
	CHECK(String(sent["nonce"]) == "NONCE");
	CHECK(String(sent["state"]) == "STATE");
	CHECK_FALSE(sent.has("code_challenge"));
	// Its return address is the game's page, not this computer's: no check of it here.
	options["redirect_uri"] = "https://game.example/play/index.sign_in.html";
	CHECK(AuthSignIn::make_flow("google", options, flow, error, true) == OK);
	// Supabase, Auth0 and the others: a code with PKCE, as on a computer.
	Dictionary supabase;
	supabase["url"] = "https://project.supabase.co";
	supabase["key"] = "anon";
	supabase["provider"] = "github";
	REQUIRE(AuthSignIn::make_flow("supabase", supabase, flow, error, true) == OK);
	CHECK_FALSE(flow.id_token_back);

	// What comes back: in the query (a code) or in the fragment (an ID token).
	const Dictionary code = AuthSignIn::parse_answer("https://game.example/index.sign_in.html?code=abc&state=S");
	CHECK(String(code["code"]) == "abc");
	CHECK(String(code["state"]) == "S");
	const Dictionary token = AuthSignIn::parse_answer("https://game.example/index.sign_in.html#id_token=x.y.z&state=S&authuser=0");
	CHECK(String(token["id_token"]) == "x.y.z");
	CHECK(String(token["state"]) == "S");
	CHECK(AuthSignIn::parse_answer("https://game.example/index.sign_in.html#error=access_denied").has("error"));
}

TEST_CASE("[Modules][Authentication] Signing in: the page the browser shows") {
	_enable_plugin();
	const String done = AuthSignIn::page("My <Game>", true, String());
	CHECK(done.contains("Signed in"));
	CHECK(done.contains("My &lt;Game&gt;"));
	CHECK(AuthSignIn::page("Game", false, "access_denied").contains("access_denied"));
}

TEST_CASE("[Modules][Authentication] Signing in needs a service it knows") {
	_enable_plugin();
	Authentication *authentication = Authentication::get_singleton();
	REQUIRE(authentication);
	ERR_PRINT_OFF;
	CHECK(authentication->sign_in_with("nowhere") == ERR_INVALID_PARAMETER);
	ERR_PRINT_ON;
	CHECK_FALSE(authentication->is_signing_in());
}

} // namespace TestAuthSignIn
