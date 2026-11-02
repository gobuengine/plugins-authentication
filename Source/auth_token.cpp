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

#include "core/config/project_settings.h"
#include "core/crypto/crypto_core.h"
#include "core/crypto/hashing_context.h"
#include "core/io/json.h"
#include "core/math/math_funcs.h"
#include "core/os/os.h"
#include "core/variant/array.h"

#include <utility>

// The keys of a JWKS come as their numbers (RSA: n, e; P-256: x, y); mbedTLS reads a public key as PEM, a
// SubjectPublicKeyInfo in DER: written here.

static PackedByteArray _bytes(const uint8_t *p_data, int p_size) {
	PackedByteArray out;
	out.resize(p_size);
	memcpy(out.ptrw(), p_data, p_size);
	return out;
}

static PackedByteArray _der(uint8_t p_tag, const PackedByteArray &p_content) {
	PackedByteArray out;
	out.push_back(p_tag);
	const int length = p_content.size();
	if (length < 0x80) {
		out.push_back(length);
	} else if (length < 0x100) {
		out.push_back(0x81);
		out.push_back(length);
	} else {
		out.push_back(0x82);
		out.push_back(length >> 8);
		out.push_back(length & 0xff);
	}
	out.append_array(p_content);
	return out;
}

// An unsigned big-endian number as an INTEGER: without leading zeros, and a zero before a high bit (else it
// would be negative).
static PackedByteArray _der_integer(const PackedByteArray &p_value) {
	int start = 0;
	while (start < p_value.size() - 1 && p_value[start] == 0) {
		start++;
	}
	PackedByteArray content;
	if (p_value.is_empty() || (p_value[start] & 0x80)) {
		content.push_back(0);
	}
	content.append_array(p_value.slice(start));
	return _der(0x02, content);
}

// AlgorithmIdentifier: rsaEncryption with NULL parameters; id-ecPublicKey with the curve prime256v1.
static const uint8_t RSA_ALGORITHM[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };
static const uint8_t P256_ALGORITHM[] = { 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

static Ref<CryptoKey> _public_key(const uint8_t *p_algorithm, int p_algorithm_size, const PackedByteArray &p_key_bits) {
	PackedByteArray bits;
	bits.push_back(0); // No unused bits.
	bits.append_array(p_key_bits);
	PackedByteArray content = _bytes(p_algorithm, p_algorithm_size);
	content.append_array(_der(0x03, bits));
	const PackedByteArray der = _der(0x30, content);

	const String base64 = CryptoCore::b64_encode_str(der.ptr(), der.size());
	String pem = "-----BEGIN PUBLIC KEY-----\n";
	for (int i = 0; i < base64.length(); i += 64) {
		pem += base64.substr(i, 64) + "\n";
	}
	pem += "-----END PUBLIC KEY-----\n";
	Ref<CryptoKey> key = Ref<CryptoKey>(CryptoKey::create());
	if (key.is_null() || key->load_from_string(pem, true) != OK) {
		return Ref<CryptoKey>();
	}
	return key;
}

static bool _parse_json(const PackedByteArray &p_utf8, Dictionary &r_object) {
	Ref<JSON> json;
	json.instantiate();
	// JSON::parse_string() would print every bad token a player sends.
	if (json->parse(String::utf8((const char *)p_utf8.ptr(), p_utf8.size())) != OK || json->get_data().get_type() != Variant::DICTIONARY) {
		return false;
	}
	r_object = json->get_data();
	return true;
}

// A claim as text: JSON numbers are floats here, and an account id "42" is not "42.0".
static String _claim_text(const Variant &p_value) {
	if (p_value.get_type() == Variant::FLOAT && Math::is_equal_approx(double(p_value), Math::round(double(p_value))) && Math::abs(double(p_value)) < 9.0e15) {
		return itos(int64_t(double(p_value)));
	}
	if (p_value.get_type() == Variant::STRING || p_value.get_type() == Variant::INT) {
		return p_value;
	}
	return String();
}

PackedByteArray AuthToken::base64url_decode(const String &p_text) {
	String text = p_text.replace_char('-', '+').replace_char('_', '/');
	if (text.length() % 4 == 1) {
		return PackedByteArray();
	}
	while (text.length() % 4) {
		text += "=";
	}
	const CharString ascii = text.ascii();
	PackedByteArray out;
	out.resize(text.length() / 4 * 3 + 3);
	size_t length = 0;
	if (CryptoCore::b64_decode(out.ptrw(), out.size(), &length, (const uint8_t *)ascii.get_data(), ascii.length()) != OK) {
		return PackedByteArray();
	}
	out.resize(length);
	return out;
}

bool AuthToken::decode(const String &p_token, Dictionary &r_header, Dictionary &r_claims, String &r_signed, PackedByteArray &r_signature) {
	const PackedStringArray parts = p_token.strip_edges().split(".");
	if (parts.size() != 3 || parts[0].is_empty() || parts[1].is_empty()) {
		return false;
	}
	if (!_parse_json(base64url_decode(parts[0]), r_header) || !_parse_json(base64url_decode(parts[1]), r_claims)) {
		return false;
	}
	r_signed = parts[0] + "." + parts[1];
	r_signature = base64url_decode(parts[2]);
	return true;
}

String AuthToken::read_claim(const String &p_token, const String &p_claim) {
	Dictionary header;
	Dictionary claims;
	String signed_part;
	PackedByteArray signature;
	if (!decode(p_token, header, claims, signed_part, signature)) {
		return String();
	}
	return _claim_text(claims.get(p_claim, Variant()));
}

PackedByteArray AuthToken::ecdsa_signature_der(const PackedByteArray &p_raw) {
	if (p_raw.size() != 64) {
		return PackedByteArray();
	}
	PackedByteArray numbers = _der_integer(p_raw.slice(0, 32));
	numbers.append_array(_der_integer(p_raw.slice(32, 64)));
	return _der(0x30, numbers);
}

Ref<CryptoKey> AuthToken::key_from_jwk(const Dictionary &p_jwk, String &r_alg) {
	if (String(p_jwk.get("use", "sig")) != "sig") {
		return Ref<CryptoKey>(); // An encryption key.
	}
	const String kty = p_jwk.get("kty", "");
	const String alg = p_jwk.get("alg", "");
	if (kty == "RSA" && (alg.is_empty() || alg == "RS256")) {
		const PackedByteArray n = base64url_decode(p_jwk.get("n", ""));
		const PackedByteArray e = base64url_decode(p_jwk.get("e", ""));
		if (n.size() < 128 || e.is_empty()) {
			return Ref<CryptoKey>(); // Under 1024 bits: not a key to trust.
		}
		PackedByteArray numbers = _der_integer(n);
		numbers.append_array(_der_integer(e));
		r_alg = "RS256";
		return _public_key(RSA_ALGORITHM, sizeof(RSA_ALGORITHM), _der(0x30, numbers));
	}
	if (kty == "EC" && String(p_jwk.get("crv", "")) == "P-256" && (alg.is_empty() || alg == "ES256")) {
		const PackedByteArray x = base64url_decode(p_jwk.get("x", ""));
		const PackedByteArray y = base64url_decode(p_jwk.get("y", ""));
		if (x.size() != 32 || y.size() != 32) {
			return Ref<CryptoKey>();
		}
		PackedByteArray point;
		point.push_back(0x04); // Uncompressed.
		point.append_array(x);
		point.append_array(y);
		r_alg = "ES256";
		return _public_key(P256_ALGORITHM, sizeof(P256_ALGORITHM), point);
	}
	return Ref<CryptoKey>();
}

Error AuthToken::set_keys(const String &p_jwks) {
	const CharString utf8 = p_jwks.utf8();
	Dictionary jwks;
	if (!_parse_json(_bytes((const uint8_t *)utf8.get_data(), utf8.length()), jwks)) {
		return ERR_PARSE_ERROR;
	}
	HashMap<String, Key> found;
	for (const Variant &entry : Array(jwks.get("keys", Array()))) {
		if (entry.get_type() != Variant::DICTIONARY) {
			continue;
		}
		Key key;
		key.key = key_from_jwk(entry, key.alg);
		if (key.key.is_valid()) {
			found[String(Dictionary(entry).get("kid", ""))] = key;
		}
	}
	if (found.is_empty()) {
		return ERR_INVALID_DATA;
	}
	keys = std::move(found);
	return OK;
}

AuthToken::Status AuthToken::check(const String &p_token, int64_t p_now, String &r_account) const {
	Dictionary header;
	Dictionary claims;
	String signed_part;
	PackedByteArray signature;
	if (!decode(p_token, header, claims, signed_part, signature)) {
		return MALFORMED;
	}
	const CharString signed_utf8 = signed_part.utf8();
	const PackedByteArray signed_bytes = _bytes((const uint8_t *)signed_utf8.get_data(), signed_utf8.length());
	const String alg = header.get("alg", "");
	if (alg == "HS256") {
		if (secret.is_empty()) {
			return UNKNOWN_KEY;
		}
		Ref<HMACContext> hmac = Ref<HMACContext>(HMACContext::create());
		ERR_FAIL_COND_V(hmac.is_null() || hmac->start(HashingContext::HASH_SHA256, secret) != OK, BAD_SIGNATURE);
		hmac->update(signed_bytes);
		const PackedByteArray expected = hmac->finish();
		// Compared whole, in the same time: how much of it matches tells nothing.
		uint8_t difference = expected.size() == signature.size() ? 0 : 1;
		for (int i = 0; i < expected.size() && i < signature.size(); i++) {
			difference |= expected[i] ^ signature[i];
		}
		if (difference) {
			return BAD_SIGNATURE;
		}
	} else if (alg == "RS256" || alg == "ES256") {
		const String kid = header.get("kid", "");
		const Key *key = keys.getptr(kid);
		if (!key && kid.is_empty() && keys.size() == 1) {
			key = &keys.begin()->value; // A service with one key may not name it.
		}
		if (!key) {
			return UNKNOWN_KEY;
		}
		if (key->alg != alg) {
			return BAD_SIGNATURE;
		}
		PackedByteArray hash;
		hash.resize(32);
		CryptoCore::sha256(signed_bytes.ptr(), signed_bytes.size(), hash.ptrw());
		const PackedByteArray der = alg == "ES256" ? ecdsa_signature_der(signature) : signature;
		Ref<Crypto> crypto = Ref<Crypto>(Crypto::create());
		if (der.is_empty() || crypto.is_null() || !crypto->verify(HashingContext::HASH_SHA256, hash, der, key->key)) {
			return BAD_SIGNATURE;
		}
	} else {
		return UNSUPPORTED;
	}

	if (claims.has("exp") && double(claims["exp"]) + LEEWAY < double(p_now)) {
		return EXPIRED;
	}
	if (claims.has("nbf") && double(claims["nbf"]) - LEEWAY > double(p_now)) {
		return NOT_YET_VALID;
	}
	if (!issuers.is_empty() && !issuers.has(String(claims.get("iss", "")))) {
		return WRONG_ISSUER;
	}
	if (!audiences.is_empty()) {
		const Variant aud = claims.get("aud", Variant());
		bool listed = false;
		for (const String &audience : audiences) {
			listed = listed || (aud.get_type() == Variant::ARRAY ? Array(aud).has(audience) : String(aud) == audience);
		}
		if (!listed) {
			return WRONG_AUDIENCE;
		}
	}
	r_account = _claim_text(claims.get(account_claim, Variant()));
	return r_account.is_empty() ? NO_ACCOUNT : VALID;
}

String AuthToken::auth0_domain(const String &p_domain) {
	return p_domain.strip_edges().trim_prefix("https://").trim_prefix("http://").trim_suffix("/");
}

String AuthToken::platform() {
	OS *os = OS::get_singleton();
	if (os->has_feature("web")) {
		return "web";
	}
	if (os->has_feature("android")) {
		return "android";
	}
	if (os->has_feature("ios")) {
		return "ios";
	}
	return "desktop";
}

PackedStringArray AuthToken::client_ids(const String &p_section) {
	PackedStringArray ids;
	for (const char *block : { "desktop", "web", "android", "ios" }) {
		const String setting = "authentication/" + p_section + "/" + block + "/client_id";
		if (ProjectSettings::get_singleton()->has_setting(setting)) {
			const String id = String(GLOBAL_GET(setting)).strip_edges();
			if (!id.is_empty() && !ids.has(id)) {
				ids.push_back(id);
			}
		}
	}
	return ids;
}

Vector<AuthToken::Service> AuthToken::services_from_settings(bool p_secret) {
	Vector<Service> services;
	// Google: a client per platform (Android signs in for the Web one, the server's).
	const PackedStringArray google = client_ids("google");
	if (!google.is_empty()) {
		Service service;
		service.name = "google";
		service.keys_url = "https://www.googleapis.com/oauth2/v3/certs";
		service.issuers.push_back("https://accounts.google.com");
		service.issuers.push_back("accounts.google.com"); // Google writes it both ways.
		service.audiences = google;
		services.push_back(service);
	}
	const String supabase = String(GLOBAL_GET("authentication/supabase/url")).strip_edges().trim_suffix("/");
	if (!supabase.is_empty()) {
		Service service;
		service.name = "supabase";
		service.keys_url = supabase + "/auth/v1/.well-known/jwks.json";
		service.issuers.push_back(supabase + "/auth/v1");
		service.audiences.push_back("authenticated");
		services.push_back(service);
	}
	const String firebase = String(GLOBAL_GET("authentication/firebase/project_id")).strip_edges();
	if (!firebase.is_empty()) {
		Service service;
		service.name = "firebase";
		service.keys_url = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
		service.issuers.push_back("https://securetoken.google.com/" + firebase);
		service.audiences.push_back(firebase);
		services.push_back(service);
	}
	const String auth0 = auth0_domain(GLOBAL_GET("authentication/auth0/domain"));
	if (!auth0.is_empty()) {
		Service service;
		service.name = "auth0";
		service.keys_url = "https://" + auth0 + "/.well-known/jwks.json";
		service.issuers.push_back("https://" + auth0 + "/");
		service.audiences = client_ids("auth0"); // Its ID tokens', one application per platform.
		services.push_back(service);
	}
	const String keys_url = String(GLOBAL_GET("authentication/custom/keys_url")).strip_edges();
	const String issuer = String(GLOBAL_GET("authentication/custom/issuer")).strip_edges();
	if (!keys_url.is_empty() || !issuer.is_empty() || (services.is_empty() && p_secret)) {
		Service service;
		service.name = "custom";
		service.keys_url = keys_url;
		if (!issuer.is_empty()) {
			service.issuers.push_back(issuer);
		}
		for (const String &audience : String(GLOBAL_GET("authentication/custom/audience")).split(",", false)) {
			if (!audience.strip_edges().is_empty()) {
				service.audiences.push_back(audience.strip_edges());
			}
		}
		service.account_claim = String(GLOBAL_GET("authentication/custom/account_claim")).strip_edges();
		if (service.account_claim.is_empty()) {
			service.account_claim = "sub";
		}
		services.push_back(service);
	}
	return services;
}

int AuthToken::service_for(const Vector<Service> &p_services, const String &p_issuer) {
	int any = -1;
	for (int i = 0; i < p_services.size(); i++) {
		if (p_services[i].issuers.has(p_issuer)) {
			return i;
		}
		if (p_services[i].issuers.is_empty()) {
			any = i;
		}
	}
	return any;
}

String AuthToken::describe(Status p_status) {
	switch (p_status) {
		case VALID:
			return String();
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
	return String();
}
