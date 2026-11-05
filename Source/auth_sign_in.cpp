/**************************************************************************/
/*  auth_sign_in.cpp                                                      */
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

#include "auth_sign_in.h"

#include "authentication.h"
#include "text.h"

#include <algorithm>

using gobu::Value;

// Authentication.sign_in_with() in a web game: the service's page in a window of its own, and the address it comes
// back to: "<page>.sign_in.html", which the web export writes next to the game (the plugin's "web_files"). That
// page tells the game where it came back (postMessage to its opener; BroadcastChannel when the game is cross-origin
// isolated, which hides the window from it); the game also looks at the window itself while it can (same origin
// again).
static const char *WEB_SCRIPT = R"(
if (!window.gobuSignIn) {
	window.gobuSignInPage = function () {
		const path = location.pathname;
		const base = path.endsWith('.html') ? path.slice(0, -5) : (path.endsWith('/') ? path + 'index' : path);
		return location.origin + base + '.sign_in.html';
	};
	window.gobuSignIn = function (url, done) {
		let finished = false;
		let popup = null;
		let timer = 0;
		const channel = ('BroadcastChannel' in window) ? new BroadcastChannel('gobu_sign_in') : null;
		const finish = function (href) {
			if (finished) {
				return;
			}
			finished = true;
			clearInterval(timer);
			window.removeEventListener('message', onMessage);
			if (channel) {
				channel.close();
			}
			window.gobuSignInCancel = null;
			try {
				if (popup && !popup.closed) {
					popup.close();
				}
			} catch (e) { /* Another origin. */ }
			done(href);
		};
		const onMessage = function (event) {
			if (event.origin === location.origin && event.data && event.data.gobuSignIn) {
				finish(event.data.gobuSignIn);
			}
		};
		window.addEventListener('message', onMessage);
		if (channel) {
			channel.onmessage = function (event) {
				if (event.data && event.data.gobuSignIn) {
					finish(event.data.gobuSignIn);
				}
			};
		}
		window.gobuSignInCancel = function () {
			finish('cancelled');
		};
		popup = window.open(url, 'gobu_sign_in', 'popup,width=520,height=680');
		if (!popup) {
			finish('blocked');
			return;
		}
		timer = setInterval(function () {
			try {
				// Cross-origin isolated, the window looks closed once it leaves this origin: only its page says.
				if (popup.closed && !window.crossOriginIsolated) {
					finish('closed');
					return;
				}
				const href = popup.location.href; // Another origin (the service's page): it throws.
				if (href && href.startsWith(location.origin) && /[?#&](code|id_token|error)=/.test(href)) {
					finish(href);
				}
			} catch (e) { /* Still at the service. */ }
		}, 250);
	};
}
)";

// Engine values the sign-in uses.
static constexpr int OK = 0;
static constexpr int ERR_UNAVAILABLE = 2;
static constexpr int ERR_CANT_OPEN = 19;
static constexpr int ERR_INVALID_PARAMETER = 31;
static constexpr int ERR_BUSY = 44;
static constexpr int HTTP_POST = 2; // HTTPClient.METHOD_POST
static constexpr int RESULT_SUCCESS = 0; // HTTPRequest.RESULT_SUCCESS
static constexpr int STATUS_CONNECTED = 2; // StreamPeerTCP.STATUS_CONNECTED
static constexpr int PROCESS_MODE_ALWAYS = 3; // Node.PROCESS_MODE_ALWAYS
static constexpr int INTERNAL_MODE_BACK = 2; // Node.INTERNAL_MODE_BACK

// The pieces.

std::string AuthSignIn::random_text(int p_bytes) {
	Value crypto = gobu::instantiate("Crypto");
	return text::base64url(crypto.call("generate_random_bytes", { p_bytes }).to_bytes());
}

std::string AuthSignIn::pkce_challenge(const std::string &p_verifier) {
	return text::base64url(Value(p_verifier).call("sha256_buffer").to_bytes()); // ASCII: its UTF-8 is its bytes.
}

std::string AuthSignIn::query(const Value &p_params) {
	std::string out;
	const Value keys = p_params.keys();
	for (int64_t i = 0; i < keys.size(); i++) {
		const Value key = keys.at(i);
		if (!out.empty()) {
			out += "&";
		}
		out += text::uri_encode(key.str()) + "=" + text::uri_encode(p_params.get(key).str());
	}
	return out;
}

Value AuthSignIn::parse_query(const std::string &p_query) {
	Value params = Value::dictionary();
	for (const std::string &pair : text::split(p_query, '&', true)) {
		const size_t equals = pair.find('=');
		const std::string key = text::uri_decode(text::replace(pair.substr(0, equals), "+", " "));
		const std::string value = equals == std::string::npos ? std::string() : text::uri_decode(text::replace(pair.substr(equals + 1), "+", " "));
		params.set(key, value);
	}
	return params;
}

Value AuthSignIn::options_from_settings(const std::string &p_provider, const Value &p_options) {
	Value options = p_options.call("duplicate");
	const std::string provider = text::lower(text::strip(p_provider));
	const std::string section = provider == "oauth" ? std::string("custom") : provider;
	// This platform's block first (its client), then what the section shares (the project, the addresses).
	const std::string base = "authentication/" + section + "/";
	const std::string block = base + AuthToken::platform() + "/";
	const char *texts[] = { "client_id", "client_secret", "url", "anon_key", "domain", "authorize_url", "token_url", "scope", "redirect_uri" };
	for (const char *name : texts) {
		const std::string option = std::string(name) == "anon_key" ? std::string("key") : std::string(name);
		for (const std::string &setting : { block + name, base + name }) {
			if (!options.has(option) && gobu::has_setting(setting)) {
				const std::string value = AuthToken::text_setting(setting);
				if (!value.empty()) {
					options.set(option, value);
				}
			}
		}
	}
	for (const std::string &setting : { block + "port", base + "port" }) {
		if (!options.has("port") && gobu::has_setting(setting)) {
			options.set("port", gobu::setting(setting).to_int());
		}
	}
	return options;
}

static std::string _option(const Value &p_options, const char *p_name, const std::string &p_default = std::string()) {
	return text::strip(p_options.has(p_name) ? p_options.get(p_name).str() : p_default);
}

// "http://<host>:<port>/...": its host (without brackets) and port (0 when it has none).
static bool _parse_local_url(const std::string &p_url, std::string &r_host, int &r_port) {
	if (!text::starts_with(p_url, "http://")) {
		return false;
	}
	std::string rest = p_url.substr(7);
	const size_t end = rest.find_first_of("/?#");
	if (end != std::string::npos) {
		rest = rest.substr(0, end);
	}
	std::string port;
	if (text::starts_with(rest, "[")) {
		const size_t close = rest.find(']');
		if (close == std::string::npos) {
			return false;
		}
		r_host = rest.substr(1, close - 1);
		port = text::starts_with(rest.substr(close + 1), ":") ? rest.substr(close + 2) : std::string();
	} else {
		const size_t colon = rest.rfind(':');
		r_host = rest.substr(0, colon);
		port = colon == std::string::npos ? std::string() : rest.substr(colon + 1);
	}
	r_port = 0;
	for (const char c : port) {
		if (c < '0' || c > '9' || r_port > 65535) {
			return false;
		}
		r_port = r_port * 10 + (c - '0');
	}
	return true;
}

bool AuthSignIn::make_flow(const std::string &p_provider, const Value &p_options, Flow &r_flow, std::string &r_error, bool p_web) {
	Flow flow;
	flow.web = p_web;
	const std::string provider = text::lower(text::strip(p_provider));
	if (provider == "google") {
		flow.authorize_url = "https://accounts.google.com/o/oauth2/v2/auth";
		flow.token_url = "https://oauth2.googleapis.com/token";
		flow.scope = "openid email profile";
		flow.token_field = "id_token";
		flow.id_token_back = p_web; // A "Web application" client's code needs its secret: not in a browser.
	} else if (provider == "supabase") {
		flow.supabase = true;
		flow.supabase_url = text::trim_suffix(_option(p_options, "url"), "/");
		flow.supabase_key = _option(p_options, "key");
		flow.supabase_provider = _option(p_options, "provider");
		flow.token_field = "access_token";
		if (flow.supabase_url.empty() || flow.supabase_key.empty() || flow.supabase_provider.empty()) {
			r_error = "Authentication.sign_in_with(\"supabase\"): it needs the project (Project Settings > Authentication > Supabase: Url and Anon Key) and \"provider\" (\"google\", \"discord\", \"github\"...).";
			return false;
		}
		flow.authorize_url = flow.supabase_url + "/auth/v1/authorize";
		flow.token_url = flow.supabase_url + "/auth/v1/token?grant_type=pkce";
	} else if (provider == "auth0") {
		const std::string domain = AuthToken::auth0_domain(_option(p_options, "domain"));
		if (domain.empty()) {
			r_error = "Authentication.sign_in_with(\"auth0\"): it needs its \"domain\" (Project Settings > Authentication > Auth0).";
			return false;
		}
		flow.authorize_url = "https://" + domain + "/authorize";
		flow.token_url = "https://" + domain + "/oauth/token";
		flow.scope = "openid profile email";
		flow.token_field = "id_token";
	} else if (provider != "oauth") {
		r_error = "Authentication.sign_in_with(): no provider \"" + p_provider + "\" (\"google\", \"supabase\", \"auth0\", or \"oauth\": the Custom service).";
		return false;
	}
	// Any service's addresses, and what each one asks for.
	flow.authorize_url = _option(p_options, "authorize_url", flow.authorize_url);
	flow.token_url = _option(p_options, "token_url", flow.token_url);
	flow.client_id = _option(p_options, "client_id");
	flow.client_secret = _option(p_options, "client_secret");
	flow.scope = _option(p_options, "scope", flow.scope);
	flow.params = p_options.get("params", Value::dictionary());
	if (flow.params.type() != GOBU_TYPE_DICTIONARY) {
		flow.params = Value::dictionary();
	}
	flow.token_field = _option(p_options, "token", flow.token_field);
	const int64_t port = p_options.get("port", 0).to_int();
	if (port < 0 || port > 65535) {
		r_error = "Authentication.sign_in_with(): \"port\" " + std::to_string(port) + " is not a port (0: any free one).";
		return false;
	}
	flow.port = int(port);
	flow.listen_on.push_back("127.0.0.1");
	flow.redirect_uri = _option(p_options, "redirect_uri");
	if (p_web) {
		// The page it comes back to is the game's own ("<page>.sign_in.html", written by the web export).
		flow.listen_on.clear();
	} else if (!flow.redirect_uri.empty()) {
		// As the service has it registered: an address of this computer, with its port.
		std::string host;
		int redirect_port = 0;
		const bool parsed = _parse_local_url(flow.redirect_uri, host, redirect_port);
		if (!parsed || (host != "127.0.0.1" && host != "localhost" && host != "::1") || redirect_port <= 0 || redirect_port > 65535) {
			r_error = "Authentication.sign_in_with(): \"redirect_uri\" must be an address of this computer with its port (http://127.0.0.1:43210/, http://localhost:43210), not \"" + flow.redirect_uri + "\".";
			return false;
		}
		flow.port = redirect_port;
		flow.listen_on.clear();
		if (host != "::1") {
			flow.listen_on.push_back("127.0.0.1");
		}
		if (host != "127.0.0.1") {
			flow.listen_on.push_back("::1"); // A browser may go to "localhost" by IPv6 first.
		}
	}
	if (!flow.supabase && (flow.authorize_url.empty() || (flow.token_url.empty() && !flow.id_token_back))) {
		r_error = "Authentication.sign_in_with(\"oauth\"): it needs the service's \"authorize_url\" and \"token_url\" (Project Settings > Authentication > Custom).";
		return false;
	}
	if (!flow.supabase && flow.client_id.empty()) {
		std::string section = provider == "oauth" ? std::string("Custom") : (provider == "auth0" ? std::string("Auth0") : provider);
		if (provider == "google") {
			section = "Google";
		}
		r_error = "Authentication.sign_in_with(\"" + provider + "\"): it needs \"client_id\" (the game's, from the service's console: Project Settings > Authentication > " + section + ").";
		return false;
	}
	r_flow = flow;
	return true;
}

Value AuthSignIn::parse_answer(const std::string &p_address) {
	const size_t hash = p_address.find('#');
	const std::string before = hash == std::string::npos ? p_address : p_address.substr(0, hash);
	const size_t question = before.find('?');
	Value params = parse_query(question == std::string::npos ? std::string() : text::split(before.substr(question + 1), '?')[0]);
	if (hash != std::string::npos) {
		const Value fragment = parse_query(p_address.substr(hash + 1));
		const Value keys = fragment.keys();
		for (int64_t i = 0; i < keys.size(); i++) {
			params.set(keys.at(i), fragment.get(keys.at(i)));
		}
	}
	return params;
}

std::string AuthSignIn::authorize_address(const Flow &p_flow, const std::string &p_redirect, const std::string &p_challenge, const std::string &p_state, const std::string &p_nonce) {
	Value params = Value::dictionary();
	if (p_flow.supabase) {
		// Supabase Auth keeps the state with the provider itself; the PKCE code is the game's proof.
		params.set("provider", p_flow.supabase_provider);
		params.set("redirect_to", p_redirect);
		params.set("code_challenge", p_challenge);
		params.set("code_challenge_method", "s256");
		if (!p_flow.scope.empty()) {
			params.set("scopes", p_flow.scope);
		}
	} else if (p_flow.id_token_back) {
		params.set("response_type", "id_token");
		params.set("client_id", p_flow.client_id);
		params.set("redirect_uri", p_redirect);
		params.set("scope", p_flow.scope.empty() ? std::string("openid") : p_flow.scope);
		params.set("state", p_state);
		params.set("nonce", p_nonce); // In the token: it answers this sign-in, not an old one.
	} else {
		params.set("response_type", "code");
		params.set("client_id", p_flow.client_id);
		params.set("redirect_uri", p_redirect);
		if (!p_flow.scope.empty()) {
			params.set("scope", p_flow.scope);
		}
		params.set("state", p_state);
		params.set("code_challenge", p_challenge);
		params.set("code_challenge_method", "S256");
	}
	const Value keys = p_flow.params.keys();
	for (int64_t i = 0; i < keys.size(); i++) {
		params.set(keys.at(i), p_flow.params.get(keys.at(i)));
	}
	return p_flow.authorize_url + (text::contains(p_flow.authorize_url, "?") ? "&" : "?") + query(params);
}

std::string AuthSignIn::page(const std::string &p_game, bool p_signed_in, const std::string &p_detail) {
	const std::string game = text::xml_escape(p_game);
	const std::string title = p_signed_in ? "Signed in" : "Could not sign in";
	const std::string detail = p_signed_in ? "You can close this tab and go back to " + game + "." : text::xml_escape(p_detail);
	return "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>" + game +
			"</title><style>body{margin:0;height:100vh;display:grid;place-items:center;font-family:system-ui,sans-serif;background:#1c2128;color:#e8eaed;text-align:center}"
			"h1{font-size:1.6em;margin:0 0 .4em}p{margin:0;color:#aab1bb}</style></head><body><div><h1>" +
			title + "</h1><p>" + detail + "</p></div></body></html>";
}

// Authentication.sign_in_with(): the browser, the address where it comes back, and the code traded for the token.

GobuObject *Authentication::_internal_request(GobuObjectId &r_id, const std::string &p_name, std::function<void(int, int, const std::string &)> p_done) {
	GobuObject *request = gobu::object_of(r_id);
	if (request) {
		gobu::call(request, "cancel_request");
		return request;
	}
	GobuObject *tree = gobu::call(gobu::singleton("Engine"), "get_main_loop").object();
	GobuObject *root = tree ? gobu::call(tree, "get_root").object() : nullptr;
	if (!root) {
		GOBU_ERROR("Authentication: no scene to make its requests in.");
		return nullptr;
	}
	request = gobu::api->classdb_construct_object("HTTPRequest");
	gobu::call(request, "set_name", { p_name });
	gobu::call(request, "set_timeout", { 15.0 });
	gobu::call(request, "set_process_mode", { PROCESS_MODE_ALWAYS });
	const Value done = gobu::callable([p_done](const gobu::Args &p_args) {
		// request_completed(result, response_code, headers, body)
		if (p_args.size() >= 4) {
			p_done(int(p_args[0].to_int()), int(p_args[1].to_int()), p_args[3].to_bytes());
		}
	}, self);
	gobu::call(request, "connect", { "request_completed", done });
	gobu::call(root, "add_child", { Value(request), false, INTERNAL_MODE_BACK });
	r_id = gobu::id_of(request);
	return request;
}

int Authentication::sign_in_with(const std::string &p_provider, const Value &p_options) {
	if (signing_in) {
		GOBU_ERROR("Authentication.sign_in_with(): a sign-in is going on (Authentication.cancel_sign_in() to start another).");
		return ERR_BUSY;
	}
	if (p_provider == "poki") {
		return _sign_in_poki(); // Poki's own (auth_poki.cpp), in a web game on Poki.
	}
	if (p_provider == "crazygames") {
		return _sign_in_crazygames(); // CrazyGames's own (auth_crazygames.cpp), in a web game on CrazyGames.
	}
	const bool web = gobu::has_feature("web");
	if (!web && !gobu::has_feature("pc")) {
		_later([this]() { _sign_in_failed("Signing in with Authentication.sign_in_with() works on computers and the web; on phones, the service's plugin signs in."); });
		return ERR_UNAVAILABLE;
	}
	AuthSignIn::Flow flow;
	std::string error;
	if (!AuthSignIn::make_flow(p_provider, AuthSignIn::options_from_settings(p_provider, p_options), flow, error, web)) {
		GOBU_ERROR(error);
		_later([this, error]() { _sign_in_failed(error); });
		return ERR_INVALID_PARAMETER;
	}
	if (web) {
		return _sign_in_web(flow);
	}
	// Where the browser comes back: the first address must answer; ::1 too, where the system has it.
	std::vector<Value> servers;
	int port = flow.port;
	for (const std::string &address : flow.listen_on) {
		Value server = gobu::instantiate("TCPServer");
		if (server.call("listen", { port, address }).to_int() != OK) {
			if (servers.empty()) {
				const std::string why = "Could not wait for the browser on " + address + ":" + std::to_string(port) + " (is that port in use?).";
				_later([this, why]() { _sign_in_failed(why); });
				return ERR_CANT_OPEN;
			}
			continue;
		}
		port = int(server.call("get_local_port").to_int());
		servers.push_back(server);
	}
	signing_in = true;
	sign_in_exchanging = false;
	sign_in_flow = flow;
	sign_in_servers = servers;
	sign_in_verifier = AuthSignIn::random_text(32);
	sign_in_state = AuthSignIn::random_text(16);
	sign_in_redirect = flow.redirect_uri.empty() ? "http://127.0.0.1:" + std::to_string(port) + "/" : flow.redirect_uri;
	sign_in_deadline = gobu::ticks_msec() + uint64_t(AuthSignIn::TIMEOUT * 1000.0);

	const std::string address = AuthSignIn::authorize_address(flow, sign_in_redirect, AuthSignIn::pkce_challenge(sign_in_verifier), sign_in_state);
	GOBU_VERBOSE("Authentication: signing in at " + address + " (back at " + sign_in_redirect + ").");
	if (gobu::has_environment(AuthSignIn::FOLLOW_ENVIRONMENT)) {
		// Next frame: the game may sign in from a _ready, while the tree adds its nodes.
		_later([this, address]() { _sign_in_follow(address); });
	} else if (gobu::call(gobu::singleton("OS"), "shell_open", { address }).to_int() != OK) {
		_sign_in_stop();
		_later([this]() { _sign_in_failed("Could not open the browser to sign in."); });
		return ERR_CANT_OPEN;
	}
	return OK;
}

void Authentication::cancel_sign_in() {
	if (signing_in) {
		_sign_in_end(std::string(), Value::dictionary(), "The sign-in was cancelled.");
	}
}

// What the browser asks at the game's address: the service's answer (the code, or why not), or anything else a
// browser asks (an icon, a connection opened ahead).
void Authentication::_sign_in_frame() {
	const uint64_t now = gobu::ticks_msec();
	if (now > sign_in_deadline) {
		_sign_in_end(std::string(), Value::dictionary(), "The sign-in took too long.");
		return;
	}
	for (const Value &server : sign_in_servers) {
		while (server.call("is_listening").to_bool() && server.call("is_connection_available").to_bool()) {
			SignInVisit visit;
			visit.peer = server.call("take_connection");
			visit.since = now;
			if (!visit.peer.is_nil()) {
				sign_in_visits.push_back(visit);
			}
		}
	}
	bool answered = false;
	Value answer;
	for (size_t i = 0; i < sign_in_visits.size();) {
		SignInVisit &visit = sign_in_visits[i];
		visit.peer.call("poll");
		if (visit.peer.call("get_status").to_int() != STATUS_CONNECTED || now - visit.since > 10000) {
			sign_in_visits.erase(sign_in_visits.begin() + i);
			continue;
		}
		const int64_t available = std::min<int64_t>(visit.peer.call("get_available_bytes").to_int(), 16384 - int64_t(visit.received.size()));
		if (available > 0) {
			// [error, data]
			const Value got = visit.peer.call("get_partial_data", { available });
			if (got.size() == 2 && got.at(0).to_int() == OK) {
				visit.received += got.at(1).to_bytes();
			}
		}
		if (!text::contains(visit.received, "\r\n\r\n")) {
			if (visit.received.size() >= 16384) {
				sign_in_visits.erase(sign_in_visits.begin() + i);
			} else {
				i++;
			}
			continue;
		}
		// "GET /?code=...&state=... HTTP/1.1"
		const std::vector<std::string> request_line = text::split(text::strip(text::split(visit.received, '\n')[0]), ' ');
		const std::string target = request_line.size() > 1 ? request_line[1] : std::string();
		const size_t question = target.find('?');
		const Value params = AuthSignIn::parse_query(question == std::string::npos ? std::string() : text::split(target.substr(question + 1), '?')[0]);
		const bool is_answer = !answered && !sign_in_exchanging && (params.has("code") || params.has("error"));
		std::string response;
		if (is_answer) {
			const std::string why = _sign_in_refusal(params);
			response = AuthSignIn::page(AuthToken::text_setting("application/config/name"), why.empty(), why);
			answered = true;
			answer = params;
		}
		const std::string head = std::string("HTTP/1.1 ") + (is_answer ? "200 OK" : "404 Not Found") + "\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " + std::to_string(response.size()) + "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
		visit.peer.call("put_data", { Value::bytes(head + response) });
		visit.peer.call("disconnect_from_host");
		sign_in_visits.erase(sign_in_visits.begin() + i);
	}
	if (answered) {
		_sign_in_came_back(answer);
	}
}

// Why the service's answer is not a sign-in for this game (empty: it is).
std::string Authentication::_sign_in_refusal(const Value &p_params) const {
	if (p_params.has("error")) {
		const std::string description = text::strip(p_params.get("error_description", "").str());
		return description.empty() ? "The service did not sign in (" + p_params.get("error").str() + ")." : description;
	}
	if (!sign_in_flow.supabase && p_params.get("state", "").str() != sign_in_state) {
		return "The answer is not of this sign-in (another tab?): try again.";
	}
	return std::string();
}

// A web game: the service's page in a window, the answer back in the address of "<page>.sign_in.html".
int Authentication::_sign_in_web(const AuthSignIn::Flow &p_flow) {
	GobuObject *js = gobu::singleton("JavaScriptBridge");
	if (!js) {
		_later([this]() { _sign_in_failed("This web game can't run JavaScript to sign in."); });
		return ERR_UNAVAILABLE;
	}
	gobu::call(js, "eval", { WEB_SCRIPT, true });
	signing_in = true;
	sign_in_exchanging = false;
	sign_in_flow = p_flow;
	sign_in_verifier = AuthSignIn::random_text(32);
	sign_in_state = AuthSignIn::random_text(16);
	sign_in_nonce = AuthSignIn::random_text(16);
	sign_in_redirect = p_flow.redirect_uri.empty() ? gobu::call(js, "eval", { "window.gobuSignInPage()", true }).str() : p_flow.redirect_uri;
	sign_in_deadline = gobu::ticks_msec() + uint64_t(AuthSignIn::TIMEOUT * 1000.0);
	const std::string address = AuthSignIn::authorize_address(p_flow, sign_in_redirect, AuthSignIn::pkce_challenge(sign_in_verifier), sign_in_state, sign_in_nonce);
	GOBU_VERBOSE("Authentication: signing in at " + address + " (back at " + sign_in_redirect + ").");
	// create_callback() calls it with an Array of the JavaScript arguments.
	sign_in_web_callback = gobu::call(js, "create_callback", { gobu::callable([this](const gobu::Args &p_args) {
		_on_web_sign_in(p_args.empty() ? Value::array() : p_args[0]);
	}, self) });
	const Value window = gobu::call(js, "get_interface", { "window" });
	if (window.object() == nullptr || sign_in_web_callback.object() == nullptr) {
		_sign_in_stop();
		_later([this]() { _sign_in_failed("This web game can't run JavaScript to sign in."); });
		return ERR_UNAVAILABLE;
	}
	gobu::call(window.object(), "gobuSignIn", { address, sign_in_web_callback });
	return OK;
}

void Authentication::_on_web_sign_in(const Value &p_args) {
	if (!signing_in || sign_in_exchanging) {
		return;
	}
	const std::string address = p_args.size() > 0 ? p_args.at(0).str() : std::string();
	if (address == "blocked") {
		_sign_in_end(std::string(), Value::dictionary(), "The browser blocked the sign-in window: call Authentication.sign_in_with() when the player presses a button.");
	} else if (address == "closed") {
		_sign_in_end(std::string(), Value::dictionary(), "The sign-in window was closed.");
	} else if (address != "cancelled") {
		_sign_in_came_back(AuthSignIn::parse_answer(address));
	}
}

void Authentication::_sign_in_came_back(const Value &p_params) {
	const std::string why = _sign_in_refusal(p_params);
	if (!why.empty()) {
		_sign_in_end(std::string(), Value::dictionary(), why);
		return;
	}
	if (sign_in_flow.id_token_back) {
		// The ID token itself: of this sign-in if it carries its nonce.
		const std::string id_token = p_params.get("id_token", "").str();
		if (id_token.empty()) {
			_sign_in_end(std::string(), Value::dictionary(), "The service's answer has no token.");
		} else if (AuthToken::read_claim(id_token, "nonce") != sign_in_nonce) {
			_sign_in_end(std::string(), Value::dictionary(), "The answer is not of this sign-in (another tab?): try again.");
		} else {
			_sign_in_end(id_token, p_params, std::string());
		}
		return;
	}
	sign_in_exchanging = true;
	for (const Value &server : sign_in_servers) {
		server.call("stop");
	}
	if (GobuObject *display = gobu::singleton("Display")) {
		gobu::call(display, "window_move_to_foreground"); // The player was in the browser.
	}
	const std::string code = p_params.get("code", "").str();
	Value headers = Value::array();
	headers.push_back("Accept: application/json");
	std::string body;
	if (sign_in_flow.supabase) {
		headers.push_back("apikey: " + sign_in_flow.supabase_key);
		headers.push_back("Content-Type: application/json");
		Value json = Value::dictionary();
		json.set("auth_code", code);
		json.set("code_verifier", sign_in_verifier);
		body = gobu::instantiate("JSON").call("stringify", { json }).str();
	} else {
		headers.push_back("Content-Type: application/x-www-form-urlencoded");
		Value form = Value::dictionary();
		form.set("grant_type", "authorization_code");
		form.set("code", code);
		form.set("redirect_uri", sign_in_redirect);
		form.set("client_id", sign_in_flow.client_id);
		form.set("code_verifier", sign_in_verifier);
		if (!sign_in_flow.client_secret.empty()) {
			form.set("client_secret", sign_in_flow.client_secret);
		}
		body = AuthSignIn::query(form);
	}
	GobuObject *request = _internal_request(sign_in_token_request, "AuthSignInToken", [this](int p_result, int p_code, const std::string &p_body) {
		_on_sign_in_token(p_result, p_code, p_body);
	});
	if (!request || gobu::call(request, "request", { sign_in_flow.token_url, headers, HTTP_POST, body }).to_int() != OK) {
		_sign_in_end(std::string(), Value::dictionary(), std::string("Could not reach the service to finish signing in (") + (request ? "the request did not start" : "no HTTPRequest") + ").");
	}
}

void Authentication::_on_sign_in_token(int p_result, int p_code, const std::string &p_body) {
	if (!signing_in || !sign_in_exchanging) {
		return;
	}
	Value data = Value::dictionary();
	Value json = gobu::instantiate("JSON");
	if (json.call("parse", { p_body }).to_int() == OK && json.call("get_data").type() == GOBU_TYPE_DICTIONARY) {
		data = json.call("get_data");
	}
	if (p_result != RESULT_SUCCESS || p_code < 200 || p_code >= 300) {
		std::string why;
		for (const char *key : { "error_description", "msg", "message", "error" }) {
			if (why.empty() && data.has(key)) {
				why = text::strip(data.get(key).str());
			}
		}
		_sign_in_end(std::string(), Value::dictionary(), p_result != RESULT_SUCCESS ? "Could not reach the service to finish signing in (HTTPRequest result " + std::to_string(p_result) + ")." : "The service did not sign in (HTTP " + std::to_string(p_code) + ")" + (why.empty() ? std::string(".") : ": " + why));
		return;
	}
	std::string answer = sign_in_flow.token_field.empty() ? std::string() : data.get(sign_in_flow.token_field, "").str();
	if (sign_in_flow.token_field.empty()) {
		answer = data.has("id_token") ? data.get("id_token").str() : data.get("access_token", "").str();
	}
	if (answer.empty()) {
		_sign_in_end(std::string(), Value::dictionary(), "The service's answer has no token.");
		return;
	}
	_sign_in_end(answer, data, std::string());
}

void Authentication::_sign_in_follow(const std::string &p_address) {
	if (!signing_in) {
		return;
	}
	// Following the page itself (AuthSignIn::FOLLOW_ENVIRONMENT): only a page that could not be opened matters.
	GobuObject *page = _internal_request(sign_in_page_request, "AuthSignInPage", [this](int p_result, int, const std::string &) {
		if (signing_in && !sign_in_exchanging && p_result != RESULT_SUCCESS) {
			_sign_in_end(std::string(), Value::dictionary(), "Could not open the sign-in page (result " + std::to_string(p_result) + ").");
		}
	});
	if (page) {
		gobu::call(page, "set_max_redirects", { 8 });
	}
	if (!page || gobu::call(page, "request", { p_address }).to_int() != OK) {
		_sign_in_end(std::string(), Value::dictionary(), "Could not open the sign-in page.");
	}
}

void Authentication::_sign_in_stop() {
	signing_in = false;
	sign_in_exchanging = false;
	sign_in_poki = false;
	sign_in_crazygames = false;
	for (const Value &server : sign_in_servers) {
		server.call("stop");
	}
	sign_in_servers.clear();
	for (SignInVisit &visit : sign_in_visits) {
		visit.peer.call("disconnect_from_host");
	}
	sign_in_visits.clear();
	if (GobuObject *page = gobu::object_of(sign_in_page_request)) {
		gobu::call(page, "cancel_request");
	}
	if (GobuObject *request = gobu::object_of(sign_in_token_request)) {
		gobu::call(request, "cancel_request");
	}
	sign_in_verifier.clear();
	sign_in_state.clear();
	sign_in_nonce.clear();
	if (sign_in_flow.web) {
		// Its window, if it is still open (cancel_sign_in(), the time ran out). The callback stays until the next
		// sign-in: it may be the one running now.
		if (GobuObject *js = gobu::singleton("JavaScriptBridge")) {
			gobu::call(js, "eval", { "window.gobuSignInCancel && window.gobuSignInCancel()", true });
		}
	}
}

void Authentication::_sign_in_end(const std::string &p_token, const Value &p_data, const std::string &p_error) {
	_sign_in_stop();
	if (!p_error.empty()) {
		_sign_in_failed(p_error);
		return;
	}
	GOBU_VERBOSE("Authentication: signed in.");
	token = p_token;
	session = p_data;
	// An online game that asks for a login: the server takes this token as this player's.
	GobuObject *online = gobu::singleton("Online");
	if (online && gobu::has_setting("online/login/check") && gobu::setting("online/login/check").to_int() != 0) {
		gobu::call(online, "login", { p_token });
	}
	_emit("signed_in", { p_token, p_data });
}

void Authentication::_sign_in_failed(const std::string &p_reason) {
	GOBU_VERBOSE("Authentication: could not sign in: " + p_reason);
	_emit("sign_in_failed", { p_reason });
}
