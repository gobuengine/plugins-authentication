/**************************************************************************/
/*  authentication.cpp                                                    */
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

#include "text.h"

#include <algorithm>

using gobu::api;
using gobu::Value;

Authentication *Authentication::singleton = nullptr;

// What waits for the next frame.

void Authentication::_later(std::function<void()> p_function) {
	later.push_back(std::move(p_function));
}

void Authentication::frame() {
	// Those of this frame; the ones they add, next frame.
	std::vector<std::function<void()>> now;
	now.swap(later);
	for (const std::function<void()> &function : now) {
		function();
	}
	if (signing_in) {
		_sign_in_frame();
	}
}

void Authentication::_emit(const char *p_signal, std::initializer_list<Value> p_args) {
	std::vector<const GobuVariant *> args;
	for (const Value &arg : p_args) {
		args.push_back(arg.raw());
	}
	api->object_emit_signal(self, p_signal, args.data(), int64_t(args.size()));
}

// This game's session.

void Authentication::sign_out() {
	if (token.empty()) {
		return;
	}
	token.clear();
	session = Value::dictionary();
	if (GobuObject *online = gobu::singleton("Online")) {
		gobu::call(online, "login", { "" });
	}
	_emit("signed_out");
}

std::string Authentication::get_account() const {
	return account_of(token);
}

std::string Authentication::account_of(const std::string &p_token) const {
	if (p_token.empty()) {
		return std::string();
	}
	const std::vector<AuthToken::Service> settings = AuthToken::services_from_settings(gobu::has_environment(SECRET_ENVIRONMENT));
	const int index = AuthToken::service_for(settings, AuthToken::read_claim(p_token, "iss"));
	const std::string account = index < 0 ? std::string() : AuthToken::read_claim(p_token, settings[index].account_claim);
	return account.empty() ? std::string() : settings[index].name + ":" + account;
}

// Checking tokens (a server).

// The services of the settings, keeping the keys already read of those whose address did not change.
void Authentication::_configure_services() {
	const std::string secret = gobu::environment(SECRET_ENVIRONMENT);
	std::vector<Service> configured;
	for (const AuthToken::Service &service_settings : AuthToken::services_from_settings(!secret.empty())) {
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
	static bool warned = false;
	if (services.empty() && !warned) {
		warned = true;
		GOBU_WARNING("Authentication: no service is set up in Project Settings > Authentication (Google, Supabase, Firebase, Auth0 or Custom): every token is turned away.");
	}
}

int Authentication::_find_service(const std::string &p_name) const {
	for (size_t i = 0; i < services.size(); i++) {
		if (services[i].settings.name == p_name) {
			return int(i);
		}
	}
	return -1;
}

static int64_t _now() {
	return int64_t(gobu::call(gobu::singleton("Time"), "get_unix_time_from_system").to_float());
}

static void _answer(const Value &p_done, const std::string &p_account, const std::string &p_reason) {
	p_done.call("call", { p_account, p_reason });
}

// Which service by the token's issuer, then with that service's keys. The account is "<service>:<id>", so two
// services never meet.
void Authentication::check_token(const std::string &p_token, const Value &p_done) {
	_configure_services();
	Value header;
	Value claims;
	std::string signed_part;
	std::string signature;
	if (!AuthToken::decode(p_token, header, claims, signed_part, signature)) {
		_answer(p_done, std::string(), AuthToken::describe(AuthToken::MALFORMED));
		return;
	}
	std::vector<AuthToken::Service> settings;
	for (const Service &service : services) {
		settings.push_back(service.settings);
	}
	const int index = AuthToken::service_for(settings, claims.get("iss", "").str());
	if (index < 0) {
		_answer(p_done, std::string(), "The login is from a service this game does not take.");
		return;
	}
	Service &service = services[index];
	std::string account;
	const AuthToken::Status status = service.checker.check(p_token, _now(), account);
	if (status == AuthToken::VALID) {
		_answer(p_done, service.settings.name + ":" + account, std::string());
		return;
	}
	// The service's keys not read yet, or changed (a key it did not have): read them, at most once a minute, and
	// check it again.
	const bool can_read = !service.settings.keys_url.empty() && (service.keys_read_msec == 0 || gobu::ticks_msec() - service.keys_read_msec > 60000);
	if (status == AuthToken::UNKNOWN_KEY && (service.keys_reading || can_read)) {
		waiting.push_back({ p_token, service.settings.name, p_done });
		if (!service.keys_reading) {
			service.keys_reading = true;
			const std::string name = service.settings.name;
			_later([this, name]() { _read_keys(name); }); // Not inside the caller.
		}
		return;
	}
	if (status == AuthToken::UNKNOWN_KEY && !service.checker.has_keys()) {
		GOBU_ERROR("Authentication: no keys to check the tokens of " + service.settings.name + " with (its section in Project Settings > Authentication, or the " + SECRET_ENVIRONMENT + " environment variable for an HS256 secret).");
	}
	_answer(p_done, std::string(), AuthToken::describe(status));
}

void Authentication::_read_keys(const std::string &p_service) {
	const int index = _find_service(p_service);
	if (index < 0) {
		return;
	}
	const std::string url = services[index].settings.keys_url;
	GobuObject *request = _internal_request(services[index].keys_request, "AuthKeys_" + p_service, [this, p_service](int p_result, int p_code, const std::string &p_body) {
		_on_keys_read(p_result, p_code, p_body, p_service);
	});
	services[index].keys_read_msec = std::max<uint64_t>(1, gobu::ticks_msec());
	if (!request || url.empty() || gobu::call(request, "request", { url }).to_int() != 0) {
		_on_keys_read(2 /* HTTPRequest.RESULT_CANT_CONNECT */, 0, std::string(), p_service);
		return;
	}
	GOBU_VERBOSE("Authentication: reading the keys of " + p_service + " at " + url + ".");
}

void Authentication::_on_keys_read(int p_result, int p_code, const std::string &p_body, const std::string &p_service) {
	const int index = _find_service(p_service);
	if (index < 0) {
		return; // No longer in the settings.
	}
	Service &service = services[index];
	service.keys_reading = false;
	if (p_result == 0 && p_code == 200 && service.checker.set_keys(p_body)) {
		GOBU_VERBOSE("Authentication: " + std::to_string(service.checker.get_key_count()) + " key(s) of " + p_service + " from " + service.settings.keys_url + ".");
	} else {
		GOBU_ERROR("Authentication: could not read the keys of " + p_service + " at \"" + service.settings.keys_url + "\" (result " + std::to_string(p_result) + ", HTTP " + std::to_string(p_code) + "): its tokens can't be checked.");
	}
	// The tokens that waited for them: out of the list first (an answer may check another one).
	std::vector<Waiting> ready;
	for (size_t i = 0; i < waiting.size();) {
		if (waiting[i].service == p_service) {
			ready.push_back(waiting[i]);
			waiting.erase(waiting.begin() + i);
		} else {
			i++;
		}
	}
	for (const Waiting &entry : ready) {
		const int now = _find_service(p_service);
		if (now < 0) {
			_answer(entry.done, std::string(), "The login is from a service this game does not take.");
			continue;
		}
		std::string account;
		const AuthToken::Status status = services[now].checker.check(entry.token, _now(), account);
		if (status == AuthToken::VALID) {
			_answer(entry.done, p_service + ":" + account, std::string());
		} else {
			_answer(entry.done, std::string(), services[now].checker.has_keys() ? AuthToken::describe(status) : std::string("The server could not read the keys of the login service."));
		}
	}
}

// The class: its methods, signals and settings.

namespace {

Authentication *_of(void *p_instance) {
	return static_cast<Authentication *>(p_instance);
}

std::string _text(const GobuVariant *p_value) {
	return Value::copy_of(p_value).str();
}

void _return(GobuVariant *r_return, const Value &p_value) {
	api->variant_destroy(r_return);
	api->variant_new_copy(r_return, p_value.raw());
}

void _sign_in_with(void *, void *p_instance, const GobuVariant *const *p_args, int64_t p_count, GobuVariant *r_return, GobuCallError *) {
	const Value options = p_count > 1 ? Value::copy_of(p_args[1]) : Value::dictionary();
	_return(r_return, Value(_of(p_instance)->sign_in_with(_text(p_args[0]), options)));
}

void _cancel_sign_in(void *, void *p_instance, const GobuVariant *const *, int64_t, GobuVariant *, GobuCallError *) {
	_of(p_instance)->cancel_sign_in();
}

void _is_signing_in(void *, void *p_instance, const GobuVariant *const *, int64_t, GobuVariant *r_return, GobuCallError *) {
	_return(r_return, Value(_of(p_instance)->is_signing_in()));
}

void _sign_out(void *, void *p_instance, const GobuVariant *const *, int64_t, GobuVariant *, GobuCallError *) {
	_of(p_instance)->sign_out();
}

void _get_token(void *, void *p_instance, const GobuVariant *const *, int64_t, GobuVariant *r_return, GobuCallError *) {
	_return(r_return, Value(_of(p_instance)->get_token()));
}

void _get_session(void *, void *p_instance, const GobuVariant *const *, int64_t, GobuVariant *r_return, GobuCallError *) {
	_return(r_return, _of(p_instance)->get_session());
}

void _get_account(void *, void *p_instance, const GobuVariant *const *, int64_t, GobuVariant *r_return, GobuCallError *) {
	_return(r_return, Value(_of(p_instance)->get_account()));
}

void _account_of(void *, void *p_instance, const GobuVariant *const *p_args, int64_t, GobuVariant *r_return, GobuCallError *) {
	_return(r_return, Value(_of(p_instance)->account_of(_text(p_args[0]))));
}

void _check_token(void *, void *p_instance, const GobuVariant *const *p_args, int64_t, GobuVariant *, GobuCallError *) {
	_of(p_instance)->check_token(_text(p_args[0]), Value::copy_of(p_args[1]));
}

void *_create(void *, GobuObject *p_object) {
	return new Authentication(p_object);
}

void _free(void *, void *p_instance) {
	delete _of(p_instance);
}

void _method(const char *p_name, GobuMethodFunc p_func, std::initializer_list<GobuArgInfo> p_args = {}, int p_return_type = -1, const Value *p_default = nullptr) {
	const std::vector<GobuArgInfo> args(p_args);
	const GobuVariant *defaults[] = { p_default ? p_default->raw() : nullptr };
	GobuMethodInfo info = {};
	info.name = p_name;
	info.func = p_func;
	info.has_return = p_return_type >= 0;
	info.return_info = { "", p_return_type >= 0 ? p_return_type : GOBU_TYPE_NIL, 0, nullptr };
	info.arg_count = int32_t(args.size());
	info.args = args.data();
	info.default_arg_count = p_default ? 1 : 0;
	info.default_args = p_default ? defaults : nullptr;
	api->register_method(gobu::plugin, Authentication::CLASS_NAME, &info);
}

// A setting of the plugin, as the engine's own (GLOBAL_DEF_BASIC): its default unless the project set it, shown in
// Project Settings > Authentication.
void _setting(const char *p_name, const Value &p_default, int p_hint = 0, const char *p_hint_string = "") {
	GobuObject *settings = gobu::singleton("ProjectSettings");
	if (!gobu::call(settings, "has_setting", { p_name }).to_bool()) {
		gobu::call(settings, "set_setting", { p_name, p_default });
	}
	gobu::call(settings, "set_initial_value", { p_name, p_default });
	Value info = Value::dictionary();
	info.set("name", p_name);
	info.set("type", p_default.type());
	info.set("hint", p_hint);
	info.set("hint_string", p_hint_string);
	gobu::call(settings, "add_property_info", { info });
	gobu::call(settings, "set_as_basic", { p_name, true });
}

constexpr int HINT_RANGE = 1; // PROPERTY_HINT_RANGE
constexpr int HINT_PLACEHOLDER = 20; // PROPERTY_HINT_PLACEHOLDER_TEXT

} // namespace

bool Authentication::register_class() {
	GobuClassInfo info = {};
	info.name = CLASS_NAME;
	info.parent = "Object";
	info.create_instance = _create;
	info.free_instance = _free;
	if (!api->register_class(gobu::plugin, &info)) {
		return false;
	}

	const Value no_options = Value::dictionary();
	_method("sign_in_with", _sign_in_with, { { "provider", GOBU_TYPE_STRING, 0, nullptr }, { "options", GOBU_TYPE_DICTIONARY, 0, nullptr } }, GOBU_TYPE_INT, &no_options);
	_method("cancel_sign_in", _cancel_sign_in);
	_method("is_signing_in", _is_signing_in, {}, GOBU_TYPE_BOOL);
	_method("sign_out", _sign_out);
	_method("get_token", _get_token, {}, GOBU_TYPE_STRING);
	_method("get_session", _get_session, {}, GOBU_TYPE_DICTIONARY);
	_method("get_account", _get_account, {}, GOBU_TYPE_STRING);
	_method("account_of", _account_of, { { "token", GOBU_TYPE_STRING, 0, nullptr } }, GOBU_TYPE_STRING);
	_method("check_token", _check_token, { { "token", GOBU_TYPE_STRING, 0, nullptr }, { "done", GOBU_TYPE_CALLABLE, 0, nullptr } });

	const GobuArgInfo signed_in[] = { { "token", GOBU_TYPE_STRING, 0, nullptr }, { "data", GOBU_TYPE_DICTIONARY, 0, nullptr } };
	api->register_signal(gobu::plugin, CLASS_NAME, "signed_in", signed_in, 2);
	const GobuArgInfo failed[] = { { "reason", GOBU_TYPE_STRING, 0, nullptr } };
	api->register_signal(gobu::plugin, CLASS_NAME, "sign_in_failed", failed, 1);
	api->register_signal(gobu::plugin, CLASS_NAME, "signed_out", nullptr, 0);

	// Each service, its section: filled in, a server takes its tokens and sign_in_with() signs in with it. What
	// differs per platform (each one's OAuth client) goes in its block: the game reads its own, a server takes the
	// tokens of all of them. Redirect Uri: the return address exactly as the service has it registered; empty,
	// http://127.0.0.1:<port>/ on a computer (Google's "Desktop app" clients take any port), and in a web game
	// "<its page>.sign_in.html", which the web export writes (plugin.json "web_files").
	_setting("authentication/google/desktop/client_id", "", HINT_PLACEHOLDER, "A \"Desktop app\" client: <id>.apps.googleusercontent.com");
	_setting("authentication/google/desktop/client_secret", ""); // Not a secret in a game: Google asks for it.
	_setting("authentication/google/desktop/redirect_uri", "", HINT_PLACEHOLDER, "http://127.0.0.1:<any port>/");
	// The web game's, and Android's: it signs in for this one (its own client is only registered at Google).
	_setting("authentication/google/web/client_id", "", HINT_PLACEHOLDER, "A \"Web application\" client");
	_setting("authentication/google/web/redirect_uri", "", HINT_PLACEHOLDER, "https://<host>/<game>.sign_in.html");
	_setting("authentication/google/ios/client_id", "", HINT_PLACEHOLDER, "An \"iOS\" client");
	_setting("authentication/supabase/url", "", HINT_PLACEHOLDER, "https://<project>.supabase.co");
	_setting("authentication/supabase/anon_key", "");
	_setting("authentication/supabase/desktop/port", 43210, HINT_RANGE, "0,65535");
	_setting("authentication/supabase/desktop/redirect_uri", "", HINT_PLACEHOLDER, "http://127.0.0.1:<port>/");
	_setting("authentication/supabase/web/redirect_uri", "", HINT_PLACEHOLDER, "https://<host>/<game>.sign_in.html");
	_setting("authentication/firebase/project_id", "");
	_setting("authentication/auth0/domain", "", HINT_PLACEHOLDER, "<tenant>.auth0.com");
	_setting("authentication/auth0/desktop/client_id", "", HINT_PLACEHOLDER, "A \"Native\" application");
	_setting("authentication/auth0/desktop/port", 43210, HINT_RANGE, "0,65535");
	_setting("authentication/auth0/desktop/redirect_uri", "", HINT_PLACEHOLDER, "http://127.0.0.1:<port>/");
	_setting("authentication/auth0/web/client_id", "", HINT_PLACEHOLDER, "A \"Single Page\" application");
	_setting("authentication/auth0/web/redirect_uri", "", HINT_PLACEHOLDER, "https://<host>/<game>.sign_in.html");
	_setting("authentication/auth0/android/client_id", "", HINT_PLACEHOLDER, "A \"Native\" application");
	_setting("authentication/auth0/ios/client_id", "", HINT_PLACEHOLDER, "A \"Native\" application");
	_setting("authentication/custom/keys_url", "");
	_setting("authentication/custom/issuer", "");
	_setting("authentication/custom/audience", "", HINT_PLACEHOLDER, "Each platform's client, separated by commas");
	_setting("authentication/custom/account_claim", "sub");
	_setting("authentication/custom/authorize_url", "");
	_setting("authentication/custom/token_url", "");
	_setting("authentication/custom/scope", "openid");
	_setting("authentication/custom/desktop/client_id", "");
	_setting("authentication/custom/desktop/client_secret", "");
	_setting("authentication/custom/desktop/port", 43210, HINT_RANGE, "0,65535");
	_setting("authentication/custom/desktop/redirect_uri", "", HINT_PLACEHOLDER, "http://127.0.0.1:<port>/");
	_setting("authentication/custom/web/client_id", "");
	_setting("authentication/custom/web/redirect_uri", "", HINT_PLACEHOLDER, "https://<host>/<game>.sign_in.html");
	return true;
}

Authentication::Authentication(GobuObject *p_self) :
		self(p_self) {
	session = Value::dictionary();
	sign_in_flow.params = Value::dictionary();
	if (!singleton) {
		singleton = this;
	}
}

Authentication::~Authentication() {
	if (singleton == this) {
		if (signing_in) {
			_sign_in_stop();
		}
		singleton = nullptr;
	}
}
