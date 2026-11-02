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

#include "core/crypto/crypto.h"
#include "core/string/ustring.h"
#include "core/templates/hash_map.h"
#include "core/templates/vector.h"
#include "core/variant/dictionary.h"

// Who a player is, from the token its login service gave it (Supabase, Firebase, Auth0, Clerk, a game's own
// server...): a JSON Web Token the service signed, checked with the service's public keys (its JWKS: RS256,
// ES256) or a secret only the server has (HS256). The account is one of its claims ("sub" by default).
class AuthToken {
public:
	enum Status {
		VALID,
		MALFORMED, // Not a JWT.
		UNKNOWN_KEY, // Signed with a key this checker does not have (the service changed its keys?).
		UNSUPPORTED, // An algorithm other than RS256, ES256 and HS256 (never "none").
		BAD_SIGNATURE,
		EXPIRED,
		NOT_YET_VALID,
		WRONG_ISSUER,
		WRONG_AUDIENCE,
		NO_ACCOUNT, // No account claim.
	};

	static constexpr int LEEWAY = 60; // Seconds of clock difference with the service.

	PackedStringArray issuers; // The "iss" it takes (any, when empty).
	PackedStringArray audiences; // The "aud" it takes, any of them (a text or a list in the token); any, when empty.
	String account_claim = "sub";
	PackedByteArray secret; // HS256.

	// The service's public keys (the JSON of its JWKS URL): RSA and P-256 keys, by "kid". Replaces the ones
	// there were; an error when there is none it can use.
	Error set_keys(const String &p_jwks);
	int get_key_count() const { return keys.size(); }
	bool has_keys() const { return !keys.is_empty() || !secret.is_empty(); }

	Status check(const String &p_token, int64_t p_now, String &r_account) const;
	// What a player is told.
	static String describe(Status p_status);

	// A claim of a token, unchecked: its issuer (which service it is), a host's own account (it trusts itself).
	static String read_claim(const String &p_token, const String &p_claim);
	static bool decode(const String &p_token, Dictionary &r_header, Dictionary &r_claims, String &r_signed, PackedByteArray &r_signature);
	static PackedByteArray base64url_decode(const String &p_text);
	// A JWK as a key Crypto can verify with (r_alg: "RS256" or "ES256"), null when it is of no use.
	static Ref<CryptoKey> key_from_jwk(const Dictionary &p_jwk, String &r_alg);
	// A JWT's ES256 signature (r and s, 32 bytes each) as mbedTLS reads it (DER).
	static PackedByteArray ecdsa_signature_der(const PackedByteArray &p_raw);

	// A login service of Project Settings > Online > Login, from its section: where its keys are, the issuers
	// its tokens come from, and for whom they are.
	struct Service {
		String name; // "google", "supabase", "firebase", "auth0" or "custom": the start of its accounts.
		String keys_url;
		PackedStringArray issuers;
		PackedStringArray audiences; // Each platform's client: a token for any of them is for this game.
		String account_claim = "sub";
	};
	// The services whose sections are filled in. Custom goes last: without an issuer (a secret only, p_secret),
	// it takes the tokens no other service names.
	static Vector<Service> services_from_settings(bool p_secret);
	// The service a token's issuer is of (-1: none).
	static int service_for(const Vector<Service> &p_services, const String &p_issuer);
	static String auth0_domain(const String &p_domain); // "tenant.auth0.com", however it was written.
	// The platform block of a section this game reads: "desktop", "web", "android" or "ios".
	static String platform();
	// The client IDs of every platform block of a section that has them (each platform signs in with its own).
	static PackedStringArray client_ids(const String &p_section);

private:
	struct Key {
		String alg;
		Ref<CryptoKey> key;
	};
	HashMap<String, Key> keys; // By "kid" ("" a key without one).
};
