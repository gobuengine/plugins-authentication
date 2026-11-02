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

#include "authentication.h"

#include "Modules/online/online.h"
#include "core/config/project_settings.h"
#include "core/object/callable_mp.h"
#include "core/object/class_db.h"
#include "core/os/os.h"
#include "core/os/time.h"
#include "scene/main/http_request.h"

Authentication *Authentication::singleton = nullptr;

// This game's session.

void Authentication::sign_out() {
	if (token.is_empty()) {
		return;
	}
	token = String();
	session = Dictionary();
	if (Online::get_singleton()) {
		Online::get_singleton()->login(String());
	}
	emit_signal(SNAME("signed_out"));
}

String Authentication::get_account() const {
	return account_of(token);
}

String Authentication::account_of(const String &p_token) const {
	if (p_token.is_empty()) {
		return String();
	}
	const Vector<AuthToken::Service> settings = AuthToken::services_from_settings(OS::get_singleton()->has_environment(SECRET_ENVIRONMENT));
	const int index = AuthToken::service_for(settings, AuthToken::read_claim(p_token, "iss"));
	const String account = index < 0 ? String() : AuthToken::read_claim(p_token, settings[index].account_claim);
	return account.is_empty() ? String() : settings[index].name + ":" + account;
}

// Checking tokens (a server).

// The services of the settings, keeping the keys already read of those whose address did not change.
void Authentication::_configure_services() {
	const PackedByteArray secret = OS::get_singleton()->get_environment(SECRET_ENVIRONMENT).to_utf8_buffer();
	const Vector<AuthToken::Service> settings = AuthToken::services_from_settings(!secret.is_empty());
	LocalVector<Service> configured;
	for (const AuthToken::Service &service_settings : settings) {
		Service service;
		for (const Service &before : services) {
			if (before.settings.name == service_settings.name && before.settings.keys_url == service_settings.keys_url) {
				service = before;
				break;
			}
		}
		service.settings = service_settings;
		service.checker.issuers = service_settings.issuers;
		service.checker.audiences = service_settings.audiences;
		service.checker.account_claim = service_settings.account_claim;
		service.checker.secret = secret;
		configured.push_back(service);
	}
	services = configured;
	if (services.is_empty()) {
		WARN_PRINT_ONCE("Authentication: no service is set up in Project Settings > Authentication (Google, Supabase, Firebase, Auth0 or Custom): every token is turned away.");
	}
}

int Authentication::_find_service(const String &p_name) const {
	for (uint32_t i = 0; i < services.size(); i++) {
		if (services[i].settings.name == p_name) {
			return i;
		}
	}
	return -1;
}

// Which service by the token's issuer, then with that service's keys. The account is "<service>:<id>", so two
// services never meet.
void Authentication::check_token(const String &p_token, const Callable &p_done) {
	_configure_services();
	Dictionary header;
	Dictionary claims;
	String signed_part;
	PackedByteArray signature;
	if (!AuthToken::decode(p_token, header, claims, signed_part, signature)) {
		p_done.call(String(), AuthToken::describe(AuthToken::MALFORMED));
		return;
	}
	Vector<AuthToken::Service> settings;
	for (const Service &service : services) {
		settings.push_back(service.settings);
	}
	const int index = AuthToken::service_for(settings, String(claims.get("iss", "")));
	if (index < 0) {
		p_done.call(String(), String("The login is from a service this game does not take."));
		return;
	}
	Service &service = services[index];
	String account;
	const AuthToken::Status status = service.checker.check(p_token, int64_t(Time::get_singleton()->get_unix_time_from_system()), account);
	if (status == AuthToken::VALID) {
		p_done.call(service.settings.name + ":" + account, String());
		return;
	}
	// The service's keys not read yet, or changed (a key it did not have): read them, at most once a minute, and
	// check it again.
	const bool can_read = !service.settings.keys_url.is_empty() && (service.keys_read_msec == 0 || OS::get_singleton()->get_ticks_msec() - service.keys_read_msec > 60000);
	if (status == AuthToken::UNKNOWN_KEY && (service.keys_reading || can_read)) {
		Waiting entry;
		entry.token = p_token;
		entry.service = service.settings.name;
		entry.done = p_done;
		waiting.push_back(entry);
		if (!service.keys_reading) {
			service.keys_reading = true;
			callable_mp(this, &Authentication::_read_keys).call_deferred(service.settings.name); // Not inside the caller.
		}
		return;
	}
	if (status == AuthToken::UNKNOWN_KEY && !service.checker.has_keys()) {
		ERR_PRINT_ONCE(vformat("Authentication: no keys to check the tokens of %s with (its section in Project Settings > Authentication, or the %s environment variable for an HS256 secret).", service.settings.name, SECRET_ENVIRONMENT));
	}
	p_done.call(String(), AuthToken::describe(status));
}

void Authentication::_read_keys(const String &p_service) {
	const int index = _find_service(p_service);
	if (index < 0) {
		return;
	}
	Service &service = services[index];
	const String url = service.settings.keys_url;
	HTTPRequest *request = _internal_request(service.keys_request, "AuthKeys_" + p_service, callable_mp(this, &Authentication::_on_keys_read).bind(p_service));
	service.keys_read_msec = MAX<uint64_t>(1, OS::get_singleton()->get_ticks_msec());
	if (!request || url.is_empty() || request->request(url) != OK) {
		_on_keys_read(HTTPRequest::RESULT_CANT_CONNECT, 0, PackedStringArray(), PackedByteArray(), p_service);
		return;
	}
	print_verbose(vformat("Authentication: reading the keys of %s at %s.", p_service, url));
}

void Authentication::_on_keys_read(int p_result, int p_code, const PackedStringArray &p_headers, const PackedByteArray &p_body, const String &p_service) {
	const int index = _find_service(p_service);
	if (index < 0) {
		return; // No longer in the settings.
	}
	Service &service = services[index];
	service.keys_reading = false;
	Error err = FAILED;
	if (p_result == HTTPRequest::RESULT_SUCCESS && p_code == 200) {
		err = service.checker.set_keys(String::utf8((const char *)p_body.ptr(), p_body.size()));
	}
	if (err == OK) {
		print_verbose(vformat("Authentication: %d key(s) of %s from %s.", service.checker.get_key_count(), p_service, service.settings.keys_url));
	} else {
		ERR_PRINT(vformat("Authentication: could not read the keys of %s at \"%s\" (result %d, HTTP %d): its tokens can't be checked.", p_service, service.settings.keys_url, p_result, p_code));
	}
	// The tokens that waited for them: out of the list first (an answer may check another one).
	LocalVector<Waiting> ready;
	for (uint32_t i = 0; i < waiting.size();) {
		if (waiting[i].service == p_service) {
			ready.push_back(waiting[i]);
			waiting.remove_at(i);
		} else {
			i++;
		}
	}
	for (const Waiting &entry : ready) {
		const int now = _find_service(p_service);
		if (now < 0) {
			entry.done.call(String(), String("The login is from a service this game does not take."));
			continue;
		}
		String account;
		const AuthToken::Status status = services[now].checker.check(entry.token, int64_t(Time::get_singleton()->get_unix_time_from_system()), account);
		if (status == AuthToken::VALID) {
			entry.done.call(p_service + ":" + account, String());
		} else {
			entry.done.call(String(), services[now].checker.has_keys() ? AuthToken::describe(status) : String("The server could not read the keys of the login service."));
		}
	}
}

// For Online.

void Authentication::_online_check_token(const String &p_token, const Callable &p_done) {
	if (singleton) {
		singleton->check_token(p_token, p_done);
	} else {
		p_done.call(String(), String("This server can't check logins (the Authentication plugin)."));
	}
}

String Authentication::_online_account_of(const String &p_token) {
	return singleton ? singleton->account_of(p_token) : String();
}

void Authentication::_bind_methods() {
	ClassDB::bind_method(D_METHOD("sign_in_with", "provider", "options"), &Authentication::sign_in_with, DEFVAL(Dictionary()));
	ClassDB::bind_method(D_METHOD("cancel_sign_in"), &Authentication::cancel_sign_in);
	ClassDB::bind_method(D_METHOD("is_signing_in"), &Authentication::is_signing_in);
	ClassDB::bind_method(D_METHOD("sign_out"), &Authentication::sign_out);
	ClassDB::bind_method(D_METHOD("get_token"), &Authentication::get_token);
	ClassDB::bind_method(D_METHOD("get_session"), &Authentication::get_session);
	ClassDB::bind_method(D_METHOD("get_account"), &Authentication::get_account);
	ClassDB::bind_method(D_METHOD("account_of", "token"), &Authentication::account_of);
	ClassDB::bind_method(D_METHOD("check_token", "token", "done"), &Authentication::check_token);

	ADD_SIGNAL(MethodInfo("signed_in", PropertyInfo(Variant::STRING, "token"), PropertyInfo(Variant::DICTIONARY, "data")));
	ADD_SIGNAL(MethodInfo("sign_in_failed", PropertyInfo(Variant::STRING, "reason")));
	ADD_SIGNAL(MethodInfo("signed_out"));
}

Authentication::Authentication() {
	singleton = this;
	Online::check_login_token = &Authentication::_online_check_token;
	Online::login_account_of = &Authentication::_online_account_of;

	// Each service, its section: filled in, a server takes its tokens and sign_in_with() signs in with it. What
	// differs per platform (each one's OAuth client) goes in its block: the game reads its own, a server takes the
	// tokens of all of them. Redirect Uri: the return address exactly as the service has it registered; empty,
	// http://127.0.0.1:<port>/ on a computer (Google's "Desktop app" clients take any port), and in a web game
	// "<its page>.sign_in.html", which the web export writes.
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/google/desktop/client_id", PROPERTY_HINT_PLACEHOLDER_TEXT, "A \"Desktop app\" client: <id>.apps.googleusercontent.com"), "");
	GLOBAL_DEF_BASIC("authentication/google/desktop/client_secret", ""); // Not a secret in a game: Google asks for it.
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/google/desktop/redirect_uri", PROPERTY_HINT_PLACEHOLDER_TEXT, "http://127.0.0.1:<any port>/"), "");
	// The web game's, and Android's: it signs in for this one (its own client is only registered at Google).
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/google/web/client_id", PROPERTY_HINT_PLACEHOLDER_TEXT, "A \"Web application\" client"), "");
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/google/web/redirect_uri", PROPERTY_HINT_PLACEHOLDER_TEXT, "https://<host>/<game>.sign_in.html"), "");
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/google/ios/client_id", PROPERTY_HINT_PLACEHOLDER_TEXT, "An \"iOS\" client"), "");
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/supabase/url", PROPERTY_HINT_PLACEHOLDER_TEXT, "https://<project>.supabase.co"), "");
	GLOBAL_DEF_BASIC("authentication/supabase/anon_key", "");
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::INT, "authentication/supabase/desktop/port", PROPERTY_HINT_RANGE, "0,65535"), 43210);
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/supabase/desktop/redirect_uri", PROPERTY_HINT_PLACEHOLDER_TEXT, "http://127.0.0.1:<port>/"), "");
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/supabase/web/redirect_uri", PROPERTY_HINT_PLACEHOLDER_TEXT, "https://<host>/<game>.sign_in.html"), "");
	GLOBAL_DEF_BASIC("authentication/firebase/project_id", "");
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/auth0/domain", PROPERTY_HINT_PLACEHOLDER_TEXT, "<tenant>.auth0.com"), "");
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/auth0/desktop/client_id", PROPERTY_HINT_PLACEHOLDER_TEXT, "A \"Native\" application"), "");
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::INT, "authentication/auth0/desktop/port", PROPERTY_HINT_RANGE, "0,65535"), 43210);
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/auth0/desktop/redirect_uri", PROPERTY_HINT_PLACEHOLDER_TEXT, "http://127.0.0.1:<port>/"), "");
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/auth0/web/client_id", PROPERTY_HINT_PLACEHOLDER_TEXT, "A \"Single Page\" application"), "");
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/auth0/web/redirect_uri", PROPERTY_HINT_PLACEHOLDER_TEXT, "https://<host>/<game>.sign_in.html"), "");
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/auth0/android/client_id", PROPERTY_HINT_PLACEHOLDER_TEXT, "A \"Native\" application"), "");
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/auth0/ios/client_id", PROPERTY_HINT_PLACEHOLDER_TEXT, "A \"Native\" application"), "");
	GLOBAL_DEF_BASIC("authentication/custom/keys_url", "");
	GLOBAL_DEF_BASIC("authentication/custom/issuer", "");
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/custom/audience", PROPERTY_HINT_PLACEHOLDER_TEXT, "Each platform's client, separated by commas"), "");
	GLOBAL_DEF_BASIC("authentication/custom/account_claim", "sub");
	GLOBAL_DEF_BASIC("authentication/custom/authorize_url", "");
	GLOBAL_DEF_BASIC("authentication/custom/token_url", "");
	GLOBAL_DEF_BASIC("authentication/custom/scope", "openid");
	GLOBAL_DEF_BASIC("authentication/custom/desktop/client_id", "");
	GLOBAL_DEF_BASIC("authentication/custom/desktop/client_secret", "");
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::INT, "authentication/custom/desktop/port", PROPERTY_HINT_RANGE, "0,65535"), 43210);
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/custom/desktop/redirect_uri", PROPERTY_HINT_PLACEHOLDER_TEXT, "http://127.0.0.1:<port>/"), "");
	GLOBAL_DEF_BASIC("authentication/custom/web/client_id", "");
	GLOBAL_DEF_BASIC(PropertyInfo(Variant::STRING, "authentication/custom/web/redirect_uri", PROPERTY_HINT_PLACEHOLDER_TEXT, "https://<host>/<game>.sign_in.html"), "");
}

Authentication::~Authentication() {
	if (singleton == this) {
		singleton = nullptr;
		Online::check_login_token = nullptr;
		Online::login_account_of = nullptr;
		if (signing_in) {
			_sign_in_stop();
		}
	}
}
