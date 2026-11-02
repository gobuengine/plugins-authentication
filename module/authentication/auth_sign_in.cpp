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

#include "Modules/online/online.h"
#include "auth_token.h"

#include "core/config/project_settings.h"
#include "core/crypto/crypto_core.h"
#include "core/io/json.h"
#include "core/object/callable_mp.h"
#include "core/os/os.h"
#include "scene/main/http_request.h"
#include "scene/main/scene_tree.h"
#include "scene/main/window.h"
#include "platform/web/api/javascript_bridge_singleton.h"
#include "servers/display/display.h"

// Authentication.sign_in_with() in a web game: the service's page in a window of its own, and the address it comes back
// to: "<page>.sign_in.html", written by the web export next to the game. That page tells the game where it
// came back (postMessage to its opener; BroadcastChannel when the game is cross-origin isolated, which hides
// the window from it); the game also looks at the window itself while it can (same origin again).
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

// The pieces.

static String _base64url(const uint8_t *p_data, int p_size) {
	return CryptoCore::b64_encode_str(p_data, p_size).replace_char('+', '-').replace_char('/', '_').replace("=", "");
}

String AuthSignIn::random_text(int p_bytes) {
	PackedByteArray bytes;
	bytes.resize(p_bytes);
	CryptoCore::RandomGenerator generator;
	ERR_FAIL_COND_V(generator.init() != OK || generator.get_random_bytes(bytes.ptrw(), p_bytes) != OK, String());
	return _base64url(bytes.ptr(), bytes.size());
}

String AuthSignIn::pkce_challenge(const String &p_verifier) {
	const CharString ascii = p_verifier.ascii();
	uint8_t hash[32];
	CryptoCore::sha256((const uint8_t *)ascii.get_data(), ascii.length(), hash);
	return _base64url(hash, 32);
}

String AuthSignIn::query(const Dictionary &p_params) {
	String text;
	for (const KeyValue<Variant, Variant> &E : p_params) {
		if (!text.is_empty()) {
			text += "&";
		}
		text += String(E.key).uri_encode() + "=" + String(E.value).uri_encode();
	}
	return text;
}

Dictionary AuthSignIn::parse_query(const String &p_query) {
	Dictionary params;
	for (const String &pair : p_query.split("&", false)) {
		const String key = pair.get_slicec('=', 0).replace_char('+', ' ').uri_decode();
		const String value = pair.contains_char('=') ? pair.substr(pair.find_char('=') + 1).replace_char('+', ' ').uri_decode() : String();
		params[key] = value;
	}
	return params;
}

Dictionary AuthSignIn::options_from_settings(const String &p_provider, const Dictionary &p_options) {
	Dictionary options = p_options.duplicate();
	const String provider = p_provider.strip_edges().to_lower();
	const String section = provider == "oauth" ? String("custom") : provider;
	// This platform's block first (its client), then what the section shares (the project, the addresses).
	const String base = "authentication/" + section + "/";
	const String block = base + AuthToken::platform() + "/";
	const char *texts[] = { "client_id", "client_secret", "url", "anon_key", "domain", "authorize_url", "token_url", "scope", "redirect_uri" };
	for (const char *name : texts) {
		const String option = String(name) == "anon_key" ? String("key") : String(name);
		for (const String &setting : { block + name, base + name }) {
			if (!options.has(option) && ProjectSettings::get_singleton()->has_setting(setting)) {
				const String value = String(GLOBAL_GET(setting)).strip_edges();
				if (!value.is_empty()) {
					options[option] = value;
				}
			}
		}
	}
	for (const String &setting : { block + "port", base + "port" }) {
		if (!options.has("port") && ProjectSettings::get_singleton()->has_setting(setting)) {
			options["port"] = int(GLOBAL_GET(setting));
		}
	}
	return options;
}

Error AuthSignIn::make_flow(const String &p_provider, const Dictionary &p_options, Flow &r_flow, String &r_error, bool p_web) {
	Flow flow;
	flow.web = p_web;
	const String provider = p_provider.strip_edges().to_lower();
	if (provider == "google") {
		flow.authorize_url = "https://accounts.google.com/o/oauth2/v2/auth";
		flow.token_url = "https://oauth2.googleapis.com/token";
		flow.scope = "openid email profile";
		flow.token_field = "id_token";
		flow.id_token_back = p_web; // A "Web application" client's code needs its secret: not in a browser.
	} else if (provider == "supabase") {
		flow.supabase = true;
		flow.supabase_url = String(p_options.get("url", "")).strip_edges().trim_suffix("/");
		flow.supabase_key = String(p_options.get("key", "")).strip_edges();
		flow.supabase_provider = String(p_options.get("provider", "")).strip_edges();
		flow.token_field = "access_token";
		if (flow.supabase_url.is_empty() || flow.supabase_key.is_empty() || flow.supabase_provider.is_empty()) {
			r_error = "Authentication.sign_in_with(\"supabase\"): it needs the project (Project Settings > Authentication > Supabase: Url and Anon Key) and \"provider\" (\"google\", \"discord\", \"github\"...).";
			return ERR_INVALID_PARAMETER;
		}
		flow.authorize_url = flow.supabase_url + "/auth/v1/authorize";
		flow.token_url = flow.supabase_url + "/auth/v1/token?grant_type=pkce";
	} else if (provider == "auth0") {
		const String domain = AuthToken::auth0_domain(p_options.get("domain", ""));
		if (domain.is_empty()) {
			r_error = "Authentication.sign_in_with(\"auth0\"): it needs its \"domain\" (Project Settings > Authentication > Auth0).";
			return ERR_INVALID_PARAMETER;
		}
		flow.authorize_url = "https://" + domain + "/authorize";
		flow.token_url = "https://" + domain + "/oauth/token";
		flow.scope = "openid profile email";
		flow.token_field = "id_token";
	} else if (provider != "oauth") {
		r_error = vformat("Authentication.sign_in_with(): no provider \"%s\" (\"google\", \"supabase\", \"auth0\", or \"oauth\": the Custom service).", p_provider);
		return ERR_INVALID_PARAMETER;
	}
	// Any service's addresses, and what each one asks for.
	flow.authorize_url = String(p_options.get("authorize_url", flow.authorize_url)).strip_edges();
	flow.token_url = String(p_options.get("token_url", flow.token_url)).strip_edges();
	flow.client_id = String(p_options.get("client_id", "")).strip_edges();
	flow.client_secret = String(p_options.get("client_secret", "")).strip_edges();
	flow.scope = String(p_options.get("scope", flow.scope)).strip_edges();
	flow.params = p_options.get("params", Dictionary());
	flow.token_field = String(p_options.get("token", flow.token_field)).strip_edges();
	flow.port = p_options.get("port", 0);
	if (flow.port < 0 || flow.port > 65535) {
		r_error = vformat("Authentication.sign_in_with(): \"port\" %d is not a port (0: any free one).", flow.port);
		return ERR_INVALID_PARAMETER;
	}
	flow.listen_on.push_back("127.0.0.1");
	flow.redirect_uri = String(p_options.get("redirect_uri", "")).strip_edges();
	if (p_web) {
		// The page it comes back to is the game's own ("<page>.sign_in.html", written by the web export).
		flow.listen_on.clear();
	} else if (!flow.redirect_uri.is_empty()) {
		// As the service has it registered: an address of this computer, with its port.
		String scheme;
		String host;
		String path;
		String fragment;
		int port = 0;
		const bool parsed = flow.redirect_uri.parse_url(scheme, host, port, path, fragment) == OK;
		host = host.trim_prefix("[").trim_suffix("]");
		if (!parsed || scheme != "http://" || (host != "127.0.0.1" && host != "localhost" && host != "::1") || port <= 0 || port > 65535) {
			r_error = vformat("Authentication.sign_in_with(): \"redirect_uri\" must be an address of this computer with its port (http://127.0.0.1:43210/, http://localhost:43210), not \"%s\".", flow.redirect_uri);
			return ERR_INVALID_PARAMETER;
		}
		flow.port = port;
		flow.listen_on.clear();
		if (host != "::1") {
			flow.listen_on.push_back("127.0.0.1");
		}
		if (host != "127.0.0.1") {
			flow.listen_on.push_back("::1"); // A browser may go to "localhost" by IPv6 first.
		}
	}
	if (!flow.supabase && (flow.authorize_url.is_empty() || (flow.token_url.is_empty() && !flow.id_token_back))) {
		r_error = "Authentication.sign_in_with(\"oauth\"): it needs the service's \"authorize_url\" and \"token_url\" (Project Settings > Authentication > Custom).";
		return ERR_INVALID_PARAMETER;
	}
	if (!flow.supabase && flow.client_id.is_empty()) {
		r_error = vformat("Authentication.sign_in_with(\"%s\"): it needs \"client_id\" (the game's, from the service's console: Project Settings > Authentication > %s).", provider, provider == "oauth" ? String("Custom") : (provider == "auth0" ? String("Auth0") : provider.capitalize()));
		return ERR_INVALID_PARAMETER;
	}
	r_flow = flow;
	return OK;
}

Dictionary AuthSignIn::parse_answer(const String &p_address) {
	const int hash = p_address.find_char('#');
	const String before = hash < 0 ? p_address : p_address.substr(0, hash);
	Dictionary params = parse_query(before.contains_char('?') ? before.get_slicec('?', 1) : String());
	if (hash >= 0) {
		const Dictionary fragment = parse_query(p_address.substr(hash + 1));
		for (const KeyValue<Variant, Variant> &E : fragment) {
			params[E.key] = E.value;
		}
	}
	return params;
}

String AuthSignIn::authorize_address(const Flow &p_flow, const String &p_redirect, const String &p_challenge, const String &p_state, const String &p_nonce) {
	Dictionary params;
	if (p_flow.supabase) {
		// Supabase Auth keeps the state with the provider itself; the PKCE code is the game's proof.
		params["provider"] = p_flow.supabase_provider;
		params["redirect_to"] = p_redirect;
		params["code_challenge"] = p_challenge;
		params["code_challenge_method"] = "s256";
		if (!p_flow.scope.is_empty()) {
			params["scopes"] = p_flow.scope;
		}
	} else if (p_flow.id_token_back) {
		params["response_type"] = "id_token";
		params["client_id"] = p_flow.client_id;
		params["redirect_uri"] = p_redirect;
		params["scope"] = p_flow.scope.is_empty() ? String("openid") : p_flow.scope;
		params["state"] = p_state;
		params["nonce"] = p_nonce; // In the token: it answers this sign-in, not an old one.
	} else {
		params["response_type"] = "code";
		params["client_id"] = p_flow.client_id;
		params["redirect_uri"] = p_redirect;
		if (!p_flow.scope.is_empty()) {
			params["scope"] = p_flow.scope;
		}
		params["state"] = p_state;
		params["code_challenge"] = p_challenge;
		params["code_challenge_method"] = "S256";
	}
	for (const KeyValue<Variant, Variant> &E : p_flow.params) {
		params[E.key] = E.value;
	}
	return p_flow.authorize_url + (p_flow.authorize_url.contains_char('?') ? "&" : "?") + query(params);
}

String AuthSignIn::page(const String &p_game, bool p_signed_in, const String &p_detail) {
	const String game = p_game.xml_escape();
	const String title = p_signed_in ? String("Signed in") : String("Could not sign in");
	const String detail = p_signed_in ? vformat("You can close this tab and go back to %s.", game) : p_detail.xml_escape();
	return "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>" + game +
			"</title><style>body{margin:0;height:100vh;display:grid;place-items:center;font-family:system-ui,sans-serif;background:#1c2128;color:#e8eaed;text-align:center}"
			"h1{font-size:1.6em;margin:0 0 .4em}p{margin:0;color:#aab1bb}</style></head><body><div><h1>" +
			title + "</h1><p>" + detail + "</p></div></body></html>";
}

// Authentication.sign_in_with(): the browser, the address where it comes back, and the code traded for the token.

HTTPRequest *Authentication::_internal_request(ObjectID &r_id, const String &p_name, const Callable &p_done) {
	HTTPRequest *request = ObjectDB::get_instance<HTTPRequest>(r_id);
	if (request) {
		request->cancel_request();
		return request;
	}
	SceneTree *tree = SceneTree::get_singleton();
	ERR_FAIL_NULL_V(tree, nullptr);
	request = memnew(HTTPRequest);
	request->set_name(p_name);
	request->set_timeout(15.0);
	request->set_process_mode(Node::PROCESS_MODE_ALWAYS);
	request->connect(SNAME("request_completed"), p_done);
	tree->get_root()->add_child(request, false, Node::INTERNAL_MODE_BACK);
	r_id = request->get_instance_id();
	return request;
}

Error Authentication::sign_in_with(const String &p_provider, const Dictionary &p_options) {
	ERR_FAIL_COND_V_MSG(signing_in, ERR_BUSY, "Authentication.sign_in_with(): a sign-in is going on (Authentication.cancel_sign_in() to start another).");
	const bool web = OS::get_singleton()->has_feature("web");
	if (!web && !OS::get_singleton()->has_feature("pc")) {
		callable_mp(this, &Authentication::_sign_in_failed).call_deferred(String("Signing in with Authentication.sign_in_with() works on computers and the web; on phones, the service's plugin signs in."));
		return ERR_UNAVAILABLE;
	}
	AuthSignIn::Flow flow;
	String error;
	if (AuthSignIn::make_flow(p_provider, AuthSignIn::options_from_settings(p_provider, p_options), flow, error, web) != OK) {
		ERR_PRINT(error);
		callable_mp(this, &Authentication::_sign_in_failed).call_deferred(error);
		return ERR_INVALID_PARAMETER;
	}
	if (web) {
		return _sign_in_web(flow);
	}
	// Where the browser comes back: the first address must answer; ::1 too, where the system has it.
	LocalVector<Ref<TCPServer>> servers;
	int port = flow.port;
	for (const String &address : flow.listen_on) {
		Ref<TCPServer> server;
		server.instantiate();
		if (server->listen(port, IPAddress(address)) != OK) {
			if (servers.is_empty()) {
				callable_mp(this, &Authentication::_sign_in_failed).call_deferred(vformat("Could not wait for the browser on %s:%d (is that port in use?).", address, port));
				return ERR_CANT_OPEN;
			}
			continue;
		}
		port = server->get_local_port();
		servers.push_back(server);
	}
	signing_in = true;
	sign_in_exchanging = false;
	sign_in_flow = flow;
	sign_in_servers = servers;
	sign_in_verifier = AuthSignIn::random_text(32);
	sign_in_state = AuthSignIn::random_text(16);
	sign_in_redirect = flow.redirect_uri.is_empty() ? vformat("http://127.0.0.1:%d/", port) : flow.redirect_uri;
	sign_in_deadline = OS::get_singleton()->get_ticks_msec() + uint64_t(AuthSignIn::TIMEOUT * 1000.0);
	SceneTree::get_singleton()->connect(SNAME("process_frame"), callable_mp(this, &Authentication::_sign_in_frame));

	const String address = AuthSignIn::authorize_address(flow, sign_in_redirect, AuthSignIn::pkce_challenge(sign_in_verifier), sign_in_state);
	print_verbose(vformat("Authentication: signing in at %s (back at %s).", address, sign_in_redirect));
	if (OS::get_singleton()->has_environment(AuthSignIn::FOLLOW_ENVIRONMENT)) {
		// At the end of the frame: the game may sign in from a _ready, while the tree adds its nodes.
		callable_mp(this, &Authentication::_sign_in_follow).call_deferred(address);
	} else if (OS::get_singleton()->shell_open(address) != OK) {
		_sign_in_stop();
		callable_mp(this, &Authentication::_sign_in_failed).call_deferred(String("Could not open the browser to sign in."));
		return ERR_CANT_OPEN;
	}
	return OK;
}

void Authentication::cancel_sign_in() {
	if (signing_in) {
		_sign_in_end(String(), Dictionary(), "The sign-in was cancelled.");
	}
}

// What the browser asks at the game's address: the service's answer (the code, or why not), or anything else a
// browser asks (an icon, a connection opened ahead).
void Authentication::_sign_in_frame() {
	if (!signing_in) {
		return;
	}
	const uint64_t now = OS::get_singleton()->get_ticks_msec();
	if (now > sign_in_deadline) {
		_sign_in_end(String(), Dictionary(), "The sign-in took too long.");
		return;
	}
	for (const Ref<TCPServer> &server : sign_in_servers) {
		while (server->is_listening() && server->is_connection_available()) {
			SignInVisit visit;
			visit.peer = server->take_connection();
			visit.since = now;
			if (visit.peer.is_valid()) {
				sign_in_visits.push_back(visit);
			}
		}
	}
	bool answered = false;
	Dictionary answer;
	for (uint32_t i = 0; i < sign_in_visits.size();) {
		SignInVisit &visit = sign_in_visits[i];
		visit.peer->poll();
		if (visit.peer->get_status() != StreamPeerSocket::STATUS_CONNECTED || now - visit.since > 10000) {
			sign_in_visits.remove_at_unordered(i);
			continue;
		}
		const int available = MIN(visit.peer->get_available_bytes(), 16384 - visit.received.size());
		if (available > 0) {
			const int previous = visit.received.size();
			visit.received.resize(previous + available);
			int received = 0;
			visit.peer->get_partial_data(visit.received.ptrw() + previous, available, received);
			visit.received.resize(previous + received);
		}
		const String request = String::utf8((const char *)visit.received.ptr(), visit.received.size());
		if (!request.contains("\r\n\r\n")) {
			if (visit.received.size() >= 16384) {
				sign_in_visits.remove_at_unordered(i);
			} else {
				i++;
			}
			continue;
		}
		// "GET /?code=...&state=... HTTP/1.1"
		const String target = request.get_slicec('\n', 0).strip_edges().get_slicec(' ', 1);
		const Dictionary params = AuthSignIn::parse_query(target.contains_char('?') ? target.get_slicec('?', 1) : String());
		const bool is_answer = !answered && !sign_in_exchanging && (params.has("code") || params.has("error"));
		String response;
		if (is_answer) {
			const String why = _sign_in_refusal(params);
			response = AuthSignIn::page(GLOBAL_GET("application/config/name"), why.is_empty(), why);
			answered = true;
			answer = params;
		}
		const CharString body = response.utf8();
		const String head = vformat("HTTP/1.1 %s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", is_answer ? "200 OK" : "404 Not Found", body.length());
		const CharString head_bytes = head.utf8();
		visit.peer->put_data((const uint8_t *)head_bytes.get_data(), head_bytes.length());
		if (body.length() > 0) {
			visit.peer->put_data((const uint8_t *)body.get_data(), body.length());
		}
		visit.peer->disconnect_from_host();
		sign_in_visits.remove_at_unordered(i);
	}
	if (answered) {
		_sign_in_came_back(answer);
	}
}

// Why the service's answer is not a sign-in for this game (empty: it is).
String Authentication::_sign_in_refusal(const Dictionary &p_params) const {
	if (p_params.has("error")) {
		const String description = String(p_params.get("error_description", "")).strip_edges();
		return description.is_empty() ? vformat("The service did not sign in (%s).", String(p_params["error"])) : description;
	}
	if (!sign_in_flow.supabase && String(p_params.get("state", "")) != sign_in_state) {
		return "The answer is not of this sign-in (another tab?): try again.";
	}
	return String();
}

// A web game: the service's page in a window, the answer back in the address of "<page>.sign_in.html".
Error Authentication::_sign_in_web(const AuthSignIn::Flow &p_flow) {
	JavaScriptBridge *js = JavaScriptBridge::get_singleton();
	if (!js) {
		callable_mp(this, &Authentication::_sign_in_failed).call_deferred(String("This web game can't run JavaScript to sign in."));
		return ERR_UNAVAILABLE;
	}
	js->eval(WEB_SCRIPT, true);
	signing_in = true;
	sign_in_exchanging = false;
	sign_in_flow = p_flow;
	sign_in_verifier = AuthSignIn::random_text(32);
	sign_in_state = AuthSignIn::random_text(16);
	sign_in_nonce = AuthSignIn::random_text(16);
	sign_in_redirect = p_flow.redirect_uri.is_empty() ? String(js->eval("window.gobuSignInPage()", true)) : p_flow.redirect_uri;
	sign_in_deadline = OS::get_singleton()->get_ticks_msec() + uint64_t(AuthSignIn::TIMEOUT * 1000.0);
	SceneTree::get_singleton()->connect(SNAME("process_frame"), callable_mp(this, &Authentication::_sign_in_frame));
	const String address = AuthSignIn::authorize_address(p_flow, sign_in_redirect, AuthSignIn::pkce_challenge(sign_in_verifier), sign_in_state, sign_in_nonce);
	print_verbose(vformat("Authentication: signing in at %s (back at %s).", address, sign_in_redirect));
	sign_in_web_callback = js->create_callback(callable_mp(this, &Authentication::_on_web_sign_in));
	Ref<JavaScriptObject> window = js->get_interface("window");
	if (window.is_null() || sign_in_web_callback.is_null()) {
		_sign_in_stop();
		callable_mp(this, &Authentication::_sign_in_failed).call_deferred(String("This web game can't run JavaScript to sign in."));
		return ERR_UNAVAILABLE;
	}
	window->call(SNAME("gobuSignIn"), address, sign_in_web_callback);
	return OK;
}

void Authentication::_on_web_sign_in(const Array &p_args) {
	if (!signing_in || sign_in_exchanging) {
		return;
	}
	const String address = p_args.is_empty() ? String() : String(p_args[0]);
	if (address == "blocked") {
		_sign_in_end(String(), Dictionary(), "The browser blocked the sign-in window: call Authentication.sign_in_with() when the player presses a button.");
	} else if (address == "closed") {
		_sign_in_end(String(), Dictionary(), "The sign-in window was closed.");
	} else if (address != "cancelled") {
		_sign_in_came_back(AuthSignIn::parse_answer(address));
	}
}

void Authentication::_sign_in_came_back(const Dictionary &p_params) {
	const String why = _sign_in_refusal(p_params);
	if (!why.is_empty()) {
		_sign_in_end(String(), Dictionary(), why);
		return;
	}
	if (sign_in_flow.id_token_back) {
		// The ID token itself: of this sign-in if it carries its nonce.
		const String id_token = p_params.get("id_token", "");
		if (id_token.is_empty()) {
			_sign_in_end(String(), Dictionary(), "The service's answer has no token.");
		} else if (AuthToken::read_claim(id_token, "nonce") != sign_in_nonce) {
			_sign_in_end(String(), Dictionary(), "The answer is not of this sign-in (another tab?): try again.");
		} else {
			_sign_in_end(id_token, p_params, String());
		}
		return;
	}
	sign_in_exchanging = true;
	for (const Ref<TCPServer> &server : sign_in_servers) {
		server->stop();
	}
	if (Display::get_singleton()) {
		Display::get_singleton()->window_move_to_foreground(); // The player was in the browser.
	}
	const String code = p_params["code"];
	Vector<String> headers;
	headers.push_back("Accept: application/json");
	String body;
	if (sign_in_flow.supabase) {
		headers.push_back("apikey: " + sign_in_flow.supabase_key);
		headers.push_back("Content-Type: application/json");
		Dictionary json;
		json["auth_code"] = code;
		json["code_verifier"] = sign_in_verifier;
		body = JSON::stringify(json);
	} else {
		headers.push_back("Content-Type: application/x-www-form-urlencoded");
		Dictionary form;
		form["grant_type"] = "authorization_code";
		form["code"] = code;
		form["redirect_uri"] = sign_in_redirect;
		form["client_id"] = sign_in_flow.client_id;
		form["code_verifier"] = sign_in_verifier;
		if (!sign_in_flow.client_secret.is_empty()) {
			form["client_secret"] = sign_in_flow.client_secret;
		}
		body = AuthSignIn::query(form);
	}
	HTTPRequest *request = _internal_request(sign_in_token_request, "AuthSignInToken", callable_mp(this, &Authentication::_on_sign_in_token));
	if (!request || request->request(sign_in_flow.token_url, headers, HTTPClient::METHOD_POST, body) != OK) {
		_sign_in_end(String(), Dictionary(), vformat("Could not reach the service to finish signing in (%s).", request ? String("the request did not start") : String("no HTTPRequest")));
	}
}

void Authentication::_on_sign_in_token(int p_result, int p_code, const PackedStringArray &p_headers, const PackedByteArray &p_body) {
	if (!signing_in || !sign_in_exchanging) {
		return;
	}
	Dictionary data;
	Ref<JSON> json;
	json.instantiate();
	if (json->parse(String::utf8((const char *)p_body.ptr(), p_body.size())) == OK && json->get_data().get_type() == Variant::DICTIONARY) {
		data = json->get_data();
	}
	if (p_result != HTTPRequest::RESULT_SUCCESS || p_code < 200 || p_code >= 300) {
		String why;
		for (const char *key : { "error_description", "msg", "message", "error" }) {
			if (why.is_empty() && data.has(key)) {
				why = String(data[key]).strip_edges();
			}
		}
		_sign_in_end(String(), Dictionary(), p_result != HTTPRequest::RESULT_SUCCESS ? vformat("Could not reach the service to finish signing in (HTTPRequest result %d).", p_result) : vformat("The service did not sign in (HTTP %d)%s", p_code, why.is_empty() ? String(".") : ": " + why));
		return;
	}
	String answer = sign_in_flow.token_field.is_empty() ? String() : String(data.get(sign_in_flow.token_field, ""));
	if (sign_in_flow.token_field.is_empty()) {
		answer = data.has("id_token") ? String(data["id_token"]) : String(data.get("access_token", ""));
	}
	if (answer.is_empty()) {
		_sign_in_end(String(), Dictionary(), "The service's answer has no token.");
		return;
	}
	_sign_in_end(answer, data, String());
}

void Authentication::_sign_in_follow(const String &p_address) {
	if (!signing_in) {
		return;
	}
	HTTPRequest *page = _internal_request(sign_in_page_request, "AuthSignInPage", callable_mp(this, &Authentication::_on_sign_in_page));
	if (page) {
		page->set_max_redirects(8);
	}
	if (!page || page->request(p_address) != OK) {
		_sign_in_end(String(), Dictionary(), "Could not open the sign-in page.");
	}
}

// Following the page itself (AuthSignIn::FOLLOW_ENVIRONMENT): only a page that could not be opened matters.
void Authentication::_on_sign_in_page(int p_result, int p_code, const PackedStringArray &p_headers, const PackedByteArray &p_body) {
	if (signing_in && !sign_in_exchanging && p_result != HTTPRequest::RESULT_SUCCESS) {
		_sign_in_end(String(), Dictionary(), vformat("Could not open the sign-in page (result %d).", p_result));
	}
}

void Authentication::_sign_in_stop() {
	signing_in = false;
	sign_in_exchanging = false;
	SceneTree *tree = SceneTree::get_singleton();
	if (tree && tree->is_connected(SNAME("process_frame"), callable_mp(this, &Authentication::_sign_in_frame))) {
		tree->disconnect(SNAME("process_frame"), callable_mp(this, &Authentication::_sign_in_frame));
	}
	for (const Ref<TCPServer> &server : sign_in_servers) {
		server->stop();
	}
	sign_in_servers.clear();
	for (SignInVisit &visit : sign_in_visits) {
		visit.peer->disconnect_from_host();
	}
	sign_in_visits.clear();
	if (HTTPRequest *page = ObjectDB::get_instance<HTTPRequest>(sign_in_page_request)) {
		page->cancel_request();
	}
	if (HTTPRequest *request = ObjectDB::get_instance<HTTPRequest>(sign_in_token_request)) {
		request->cancel_request();
	}
	sign_in_verifier = String();
	sign_in_state = String();
	sign_in_nonce = String();
	if (sign_in_flow.web && JavaScriptBridge::get_singleton()) {
		// Its window, if it is still open (cancel_sign_in(), the time ran out). The callback stays until the next
		// sign-in: it may be the one running now.
		JavaScriptBridge::get_singleton()->eval("window.gobuSignInCancel && window.gobuSignInCancel()", true);
	}
}

void Authentication::_sign_in_end(const String &p_token, const Dictionary &p_data, const String &p_error) {
	_sign_in_stop();
	if (!p_error.is_empty()) {
		_sign_in_failed(p_error);
		return;
	}
	print_verbose("Authentication: signed in.");
	token = p_token;
	session = p_data;
	// An online game that asks for a login: the server takes this token as this player's.
	if (Online::get_singleton() && int(GLOBAL_GET("online/login/check")) != Online::LOGIN_OFF) {
		Online::get_singleton()->login(p_token);
	}
	emit_signal(SNAME("signed_in"), p_token, p_data);
}

void Authentication::_sign_in_failed(const String &p_reason) {
	print_verbose(vformat("Authentication: could not sign in: %s", p_reason));
	emit_signal(SNAME("sign_in_failed"), p_reason);
}
