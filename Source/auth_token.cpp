/**************************************************************************/
/*  auth_token.cpp                                                        */
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

#include "auth_token.h"

#include "text.h"

#include <cmath>

using gobu::Value;

// Crypto's hash for HMAC and signatures (HashingContext.HASH_SHA256).
static constexpr int HASH_SHA256 = 2;

// The keys of a JWKS come as their numbers (RSA: n, e; P-256: x, y); mbedTLS reads a public key as PEM, a
// SubjectPublicKeyInfo in DER: written here.

static std::string _der(uint8_t p_tag, const std::string &p_content) {
	std::string out(1, char(p_tag));
	const size_t length = p_content.size();
	if (length < 0x80) {
		out += char(length);
	} else if (length < 0x100) {
		out += char(0x81);
		out += char(length);
	} else {
		out += char(0x82);
		out += char(length >> 8);
		out += char(length & 0xff);
	}
	return out + p_content;
}

// An unsigned big-endian number as an INTEGER: without leading zeros, and a zero before a high bit (else it
// would be negative).
static std::string _der_integer(const std::string &p_value) {
	size_t start = 0;
	while (start + 1 < p_value.size() && p_value[start] == 0) {
		start++;
	}
	std::string content;
	if (p_value.empty() || (uint8_t(p_value[start]) & 0x80)) {
		content += char(0);
	}
	return _der(0x02, content + p_value.substr(start));
}

// AlgorithmIdentifier: rsaEncryption with NULL parameters; id-ecPublicKey with the curve prime256v1.
static const uint8_t RSA_ALGORITHM[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };
static const uint8_t P256_ALGORITHM[] = { 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

static Value _public_key(const uint8_t *p_algorithm, size_t p_algorithm_size, const std::string &p_key_bits) {
	const std::string bits = std::string(1, char(0)) + p_key_bits; // No unused bits.
	const std::string der = _der(0x30, std::string(reinterpret_cast<const char *>(p_algorithm), p_algorithm_size) + _der(0x03, bits));
	const std::string base64 = text::base64(der);
	std::string pem = "-----BEGIN PUBLIC KEY-----\n";
	for (size_t i = 0; i < base64.size(); i += 64) {
		pem += base64.substr(i, 64) + "\n";
	}
	pem += "-----END PUBLIC KEY-----\n";
	Value key = gobu::instantiate("CryptoKey");
	if (key.is_nil() || key.call("load_from_string", { pem, true }).to_int() != 0) {
		return Value();
	}
	return key;
}

static bool _parse_json(const std::string &p_utf8, Value &r_object) {
	// JSON.parse_string() would print every bad token a player sends.
	Value json = gobu::instantiate("JSON");
	if (json.call("parse", { p_utf8 }).to_int() != 0) {
		return false;
	}
	const Value data = json.call("get_data");
	if (data.type() != GOBU_TYPE_DICTIONARY) {
		return false;
	}
	r_object = data;
	return true;
}

// A claim as text: JSON numbers are floats here, and an account id "42" is not "42.0".
static std::string _claim_text(const Value &p_value) {
	if (p_value.type() == GOBU_TYPE_FLOAT) {
		const double number = p_value.to_float();
		if (std::floor(number) == number && std::fabs(number) < 9.0e15) {
			return std::to_string(int64_t(number));
		}
		return std::string();
	}
	if (p_value.type() == GOBU_TYPE_INT) {
		return std::to_string(p_value.to_int());
	}
	if (p_value.type() == GOBU_TYPE_STRING) {
		return p_value.str();
	}
	return std::string();
}

bool AuthToken::decode(const std::string &p_token, Value &r_header, Value &r_claims, std::string &r_signed, std::string &r_signature) {
	const std::vector<std::string> parts = text::split(text::strip(p_token), '.');
	if (parts.size() != 3 || parts[0].empty() || parts[1].empty()) {
		return false;
	}
	std::string header;
	std::string claims;
	if (!text::base64_decode(parts[0], header) || !text::base64_decode(parts[1], claims) || !_parse_json(header, r_header) || !_parse_json(claims, r_claims)) {
		return false;
	}
	r_signed = parts[0] + "." + parts[1];
	if (!text::base64_decode(parts[2], r_signature)) {
		r_signature.clear();
	}
	return true;
}

std::string AuthToken::read_claim(const std::string &p_token, const std::string &p_claim) {
	Value header;
	Value claims;
	std::string signed_part;
	std::string signature;
	if (!decode(p_token, header, claims, signed_part, signature)) {
		return std::string();
	}
	return _claim_text(claims.get(p_claim));
}

std::string AuthToken::ecdsa_signature_der(const std::string &p_raw) {
	if (p_raw.size() != 64) {
		return std::string();
	}
	return _der(0x30, _der_integer(p_raw.substr(0, 32)) + _der_integer(p_raw.substr(32, 32)));
}

Value AuthToken::key_from_jwk(const Value &p_jwk, std::string &r_alg) {
	if (p_jwk.get("use", "sig").str() != "sig") {
		return Value(); // An encryption key.
	}
	const std::string kty = p_jwk.get("kty", "").str();
	const std::string alg = p_jwk.get("alg", "").str();
	if (kty == "RSA" && (alg.empty() || alg == "RS256")) {
		std::string n;
		std::string e;
		if (!text::base64_decode(p_jwk.get("n", "").str(), n) || !text::base64_decode(p_jwk.get("e", "").str(), e) || n.size() < 128 || e.empty()) {
			return Value(); // Under 1024 bits: not a key to trust.
		}
		r_alg = "RS256";
		return _public_key(RSA_ALGORITHM, sizeof(RSA_ALGORITHM), _der(0x30, _der_integer(n) + _der_integer(e)));
	}
	if (kty == "EC" && p_jwk.get("crv", "").str() == "P-256" && (alg.empty() || alg == "ES256")) {
		std::string x;
		std::string y;
		if (!text::base64_decode(p_jwk.get("x", "").str(), x) || !text::base64_decode(p_jwk.get("y", "").str(), y) || x.size() != 32 || y.size() != 32) {
			return Value();
		}
		r_alg = "ES256";
		return _public_key(P256_ALGORITHM, sizeof(P256_ALGORITHM), std::string(1, char(0x04)) + x + y); // Uncompressed.
	}
	return Value();
}

bool AuthToken::set_keys(const std::string &p_jwks) {
	Value jwks;
	if (!_parse_json(p_jwks, jwks)) {
		return false;
	}
	std::map<std::string, Key> found;
	const Value list = jwks.get("keys", Value::array());
	for (int64_t i = 0; list.type() == GOBU_TYPE_ARRAY && i < list.size(); i++) {
		const Value entry = list.at(i);
		if (entry.type() != GOBU_TYPE_DICTIONARY) {
			continue;
		}
		Key key;
		key.key = key_from_jwk(entry, key.alg);
		if (!key.key.is_nil()) {
			found[entry.get("kid", "").str()] = key;
		}
	}
	if (found.empty()) {
		return false;
	}
	keys = found;
	return true;
}

AuthToken::Status AuthToken::check(const std::string &p_token, int64_t p_now, std::string &r_account) const {
	Value header;
	Value claims;
	std::string signed_part;
	std::string signature;
	if (!decode(p_token, header, claims, signed_part, signature)) {
		return MALFORMED;
	}
	const std::string alg = header.get("alg", "").str();
	if (alg == "HS256") {
		if (secret.empty()) {
			return UNKNOWN_KEY;
		}
		Value crypto = gobu::instantiate("Crypto");
		const std::string expected = crypto.call("hmac_digest", { HASH_SHA256, Value::bytes(secret), Value::bytes(signed_part) }).to_bytes();
		// Compared whole, in the same time: how much of it matches tells nothing.
		uint8_t difference = expected.size() == signature.size() && !expected.empty() ? 0 : 1;
		for (size_t i = 0; i < expected.size() && i < signature.size(); i++) {
			difference |= uint8_t(expected[i] ^ signature[i]);
		}
		if (difference) {
			return BAD_SIGNATURE;
		}
	} else if (alg == "RS256" || alg == "ES256") {
		const std::string kid = header.get("kid", "").str();
		auto key = keys.find(kid);
		if (key == keys.end() && kid.empty() && keys.size() == 1) {
			key = keys.begin(); // A service with one key may not name it.
		}
		if (key == keys.end()) {
			return UNKNOWN_KEY;
		}
		if (key->second.alg != alg) {
			return BAD_SIGNATURE;
		}
		const Value hash = Value(signed_part).call("sha256_buffer"); // Its text is ASCII: its UTF-8 is its bytes.
		const std::string der = alg == "ES256" ? ecdsa_signature_der(signature) : signature;
		Value crypto = gobu::instantiate("Crypto");
		if (der.empty() || crypto.is_nil() || !crypto.call("verify", { HASH_SHA256, hash, Value::bytes(der), key->second.key }).to_bool()) {
			return BAD_SIGNATURE;
		}
	} else {
		return UNSUPPORTED;
	}

	if (claims.has("exp") && claims.get("exp").to_float() + LEEWAY < double(p_now)) {
		return EXPIRED;
	}
	if (claims.has("nbf") && claims.get("nbf").to_float() - LEEWAY > double(p_now)) {
		return NOT_YET_VALID;
	}
	if (!issuers.empty() && !text::has(issuers, claims.get("iss", "").str())) {
		return WRONG_ISSUER;
	}
	if (!audiences.empty()) {
		const Value aud = claims.get("aud");
		bool listed = false;
		for (const std::string &audience : audiences) {
			if (aud.type() == GOBU_TYPE_ARRAY) {
				for (int64_t i = 0; i < aud.size(); i++) {
					listed = listed || aud.at(i).str() == audience;
				}
			} else {
				listed = listed || (aud.type() == GOBU_TYPE_STRING && aud.str() == audience);
			}
		}
		if (!listed) {
			return WRONG_AUDIENCE;
		}
	}
	for (const std::pair<const std::string, std::string> &claim : required) {
		if (_claim_text(claims.get(claim.first)) != claim.second) {
			return WRONG_AUDIENCE; // For another game.
		}
	}
	r_account = _claim_text(claims.get(account_claim));
	return r_account.empty() ? NO_ACCOUNT : VALID;
}

std::string AuthToken::auth0_domain(const std::string &p_domain) {
	return text::trim_suffix(text::trim_prefix(text::trim_prefix(text::strip(p_domain), "https://"), "http://"), "/");
}

std::string AuthToken::platform() {
	if (gobu::has_feature("web")) {
		return "web";
	}
	if (gobu::has_feature("android")) {
		return "android";
	}
	if (gobu::has_feature("ios")) {
		return "ios";
	}
	return "desktop";
}

std::string AuthToken::text_setting(const std::string &p_name) {
	return gobu::has_setting(p_name) ? text::strip(gobu::setting(p_name).str()) : std::string();
}

std::vector<std::string> AuthToken::client_ids(const std::string &p_section) {
	std::vector<std::string> ids;
	for (const char *block : { "desktop", "web", "android", "ios" }) {
		const std::string id = text_setting("authentication/" + p_section + "/" + block + "/client_id");
		if (!id.empty() && !text::has(ids, id)) {
			ids.push_back(id);
		}
	}
	return ids;
}

std::vector<AuthToken::Service> AuthToken::services_from_settings(bool p_secret) {
	std::vector<Service> services;
	// Google: a client per platform (Android signs in for the Web one, the server's).
	const std::vector<std::string> google = client_ids("google");
	if (!google.empty()) {
		Service service;
		service.name = "google";
		service.keys_url = "https://www.googleapis.com/oauth2/v3/certs";
		service.issuers.push_back("https://accounts.google.com");
		service.issuers.push_back("accounts.google.com"); // Google writes it both ways.
		service.audiences = google;
		services.push_back(service);
	}
	const std::string supabase = text::trim_suffix(text_setting("authentication/supabase/url"), "/");
	if (!supabase.empty()) {
		Service service;
		service.name = "supabase";
		service.keys_url = supabase + "/auth/v1/.well-known/jwks.json";
		service.issuers.push_back(supabase + "/auth/v1");
		service.audiences.push_back("authenticated");
		services.push_back(service);
	}
	const std::string firebase = text_setting("authentication/firebase/project_id");
	if (!firebase.empty()) {
		Service service;
		service.name = "firebase";
		service.keys_url = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
		service.issuers.push_back("https://securetoken.google.com/" + firebase);
		service.audiences.push_back(firebase);
		services.push_back(service);
	}
	const std::string auth0 = auth0_domain(text_setting("authentication/auth0/domain"));
	if (!auth0.empty()) {
		Service service;
		service.name = "auth0";
		service.keys_url = "https://" + auth0 + "/.well-known/jwks.json";
		service.issuers.push_back("https://" + auth0 + "/");
		service.audiences = client_ids("auth0"); // Its ID tokens', one application per platform.
		services.push_back(service);
	}
	// CrazyGames: its players' tokens (getUserToken, RS256), for this game's id there.
	const std::string crazygames = text_setting("authentication/crazygames/game_id");
	if (!crazygames.empty()) {
		Service service;
		service.name = "crazygames";
		service.keys_url = gobu::has_environment("GOBU_CRAZYGAMES_KEYS_URL") ? gobu::environment("GOBU_CRAZYGAMES_KEYS_URL") : std::string("https://userportal.crazygames.com/.well-known/jwks.json");
		service.account_claim = "userId";
		service.prefix = "crazygames:";
		service.required["gameId"] = crazygames;
		services.push_back(service);
	}
	const std::string keys_url = text_setting("authentication/custom/keys_url");
	const std::string issuer = text_setting("authentication/custom/issuer");
	if (!keys_url.empty() || !issuer.empty() || (services.empty() && p_secret)) {
		Service service;
		service.name = "custom";
		service.keys_url = keys_url;
		if (!issuer.empty()) {
			service.issuers.push_back(issuer);
		}
		for (const std::string &audience : text::split(text_setting("authentication/custom/audience"), ',', true)) {
			if (!text::strip(audience).empty()) {
				service.audiences.push_back(text::strip(audience));
			}
		}
		service.account_claim = text_setting("authentication/custom/account_claim");
		if (service.account_claim.empty()) {
			service.account_claim = "sub";
		}
		services.push_back(service);
	}
	return services;
}

int AuthToken::service_for(const std::vector<Service> &p_services, const std::string &p_issuer) {
	int any = -1;
	for (size_t i = 0; i < p_services.size(); i++) {
		if (!p_services[i].prefix.empty()) {
			continue; // Picked by its prefix only.
		}
		if (text::has(p_services[i].issuers, p_issuer)) {
			return int(i);
		}
		if (p_services[i].issuers.empty()) {
			any = int(i);
		}
	}
	return any;
}

std::string AuthToken::describe(Status p_status) {
	switch (p_status) {
		case VALID:
			return std::string();
		case MALFORMED:
			return "Not a login token.";
		case UNKNOWN_KEY:
			return "The login was signed with a key this server does not know.";
		case UNSUPPORTED:
			return "The login is signed in a way this server does not check (RS256, ES256 or HS256).";
		case BAD_SIGNATURE:
			return "The login is not valid.";
		case EXPIRED:
			return "The login expired: log in again.";
		case NOT_YET_VALID:
			return "The login is not valid yet (is this machine's clock right?).";
		case WRONG_ISSUER:
			return "The login is from another service.";
		case WRONG_AUDIENCE:
			return "The login is for another game.";
		case NO_ACCOUNT:
			return "The login names no account.";
	}
	return std::string();
}
