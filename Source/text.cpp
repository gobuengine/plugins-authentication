/**************************************************************************/
/*  text.cpp                                                              */
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

#include "text.h"

#include <cstdint>

namespace text {

static bool _is_space(char p_char) {
	return p_char == ' ' || p_char == '\t' || p_char == '\r' || p_char == '\n';
}

std::string strip(const std::string &p_text) {
	size_t begin = 0;
	size_t end = p_text.size();
	while (begin < end && _is_space(p_text[begin])) {
		begin++;
	}
	while (end > begin && _is_space(p_text[end - 1])) {
		end--;
	}
	return p_text.substr(begin, end - begin);
}

std::string lower(const std::string &p_text) {
	std::string out = p_text;
	for (char &c : out) {
		if (c >= 'A' && c <= 'Z') {
			c = char(c - 'A' + 'a');
		}
	}
	return out;
}

bool starts_with(const std::string &p_text, const std::string &p_prefix) {
	return p_text.size() >= p_prefix.size() && p_text.compare(0, p_prefix.size(), p_prefix) == 0;
}

bool ends_with(const std::string &p_text, const std::string &p_suffix) {
	return p_text.size() >= p_suffix.size() && p_text.compare(p_text.size() - p_suffix.size(), p_suffix.size(), p_suffix) == 0;
}

bool contains(const std::string &p_text, const std::string &p_part) {
	return p_text.find(p_part) != std::string::npos;
}

std::string trim_prefix(const std::string &p_text, const std::string &p_prefix) {
	return starts_with(p_text, p_prefix) ? p_text.substr(p_prefix.size()) : p_text;
}

std::string trim_suffix(const std::string &p_text, const std::string &p_suffix) {
	return ends_with(p_text, p_suffix) ? p_text.substr(0, p_text.size() - p_suffix.size()) : p_text;
}

std::string replace(const std::string &p_text, const std::string &p_from, const std::string &p_to) {
	if (p_from.empty()) {
		return p_text;
	}
	std::string out;
	size_t at = 0;
	for (size_t found = p_text.find(p_from); found != std::string::npos; found = p_text.find(p_from, at)) {
		out += p_text.substr(at, found - at) + p_to;
		at = found + p_from.size();
	}
	return out + p_text.substr(at);
}

std::vector<std::string> split(const std::string &p_text, char p_separator, bool p_skip_empty) {
	std::vector<std::string> parts;
	size_t at = 0;
	while (true) {
		const size_t found = p_text.find(p_separator, at);
		const std::string part = p_text.substr(at, found == std::string::npos ? std::string::npos : found - at);
		if (!p_skip_empty || !part.empty()) {
			parts.push_back(part);
		}
		if (found == std::string::npos) {
			return parts;
		}
		at = found + 1;
	}
}

bool has(const std::vector<std::string> &p_list, const std::string &p_item) {
	for (const std::string &item : p_list) {
		if (item == p_item) {
			return true;
		}
	}
	return false;
}

static const char HEX[] = "0123456789ABCDEF";

std::string uri_encode(const std::string &p_text) {
	std::string out;
	for (const char c : p_text) {
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
			out += c;
		} else {
			const uint8_t byte = uint8_t(c);
			out += '%';
			out += HEX[byte >> 4];
			out += HEX[byte & 15];
		}
	}
	return out;
}

static int _hex_value(char p_char) {
	if (p_char >= '0' && p_char <= '9') {
		return p_char - '0';
	}
	if (p_char >= 'a' && p_char <= 'f') {
		return p_char - 'a' + 10;
	}
	if (p_char >= 'A' && p_char <= 'F') {
		return p_char - 'A' + 10;
	}
	return -1;
}

std::string uri_decode(const std::string &p_text) {
	std::string out;
	for (size_t i = 0; i < p_text.size(); i++) {
		if (p_text[i] == '%' && i + 2 < p_text.size() && _hex_value(p_text[i + 1]) >= 0 && _hex_value(p_text[i + 2]) >= 0) {
			out += char(_hex_value(p_text[i + 1]) * 16 + _hex_value(p_text[i + 2]));
			i += 2;
		} else {
			out += p_text[i];
		}
	}
	return out;
}

std::string xml_escape(const std::string &p_text) {
	std::string out;
	for (const char c : p_text) {
		switch (c) {
			case '&':
				out += "&amp;";
				break;
			case '<':
				out += "&lt;";
				break;
			case '>':
				out += "&gt;";
				break;
			case '"':
				out += "&quot;";
				break;
			case '\'':
				out += "&apos;";
				break;
			default:
				out += c;
		}
	}
	return out;
}

static const char BASE64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64(const std::string &p_bytes) {
	std::string out;
	size_t i = 0;
	for (; i + 2 < p_bytes.size(); i += 3) {
		const uint32_t n = (uint32_t(uint8_t(p_bytes[i])) << 16) | (uint32_t(uint8_t(p_bytes[i + 1])) << 8) | uint8_t(p_bytes[i + 2]);
		out += BASE64[(n >> 18) & 63];
		out += BASE64[(n >> 12) & 63];
		out += BASE64[(n >> 6) & 63];
		out += BASE64[n & 63];
	}
	const size_t rest = p_bytes.size() - i;
	if (rest == 1) {
		const uint32_t n = uint32_t(uint8_t(p_bytes[i])) << 16;
		out += BASE64[(n >> 18) & 63];
		out += BASE64[(n >> 12) & 63];
		out += "==";
	} else if (rest == 2) {
		const uint32_t n = (uint32_t(uint8_t(p_bytes[i])) << 16) | (uint32_t(uint8_t(p_bytes[i + 1])) << 8);
		out += BASE64[(n >> 18) & 63];
		out += BASE64[(n >> 12) & 63];
		out += BASE64[(n >> 6) & 63];
		out += '=';
	}
	return out;
}

std::string base64url(const std::string &p_bytes) {
	std::string out = base64(p_bytes);
	for (char &c : out) {
		c = c == '+' ? '-' : (c == '/' ? '_' : c);
	}
	while (!out.empty() && out.back() == '=') {
		out.pop_back();
	}
	return out;
}

static int _base64_value(char p_char) {
	if (p_char >= 'A' && p_char <= 'Z') {
		return p_char - 'A';
	}
	if (p_char >= 'a' && p_char <= 'z') {
		return p_char - 'a' + 26;
	}
	if (p_char >= '0' && p_char <= '9') {
		return p_char - '0' + 52;
	}
	if (p_char == '+' || p_char == '-') {
		return 62;
	}
	if (p_char == '/' || p_char == '_') {
		return 63;
	}
	return -1;
}

bool base64_decode(const std::string &p_text, std::string &r_bytes) {
	std::string digits = p_text;
	while (!digits.empty() && digits.back() == '=') {
		digits.pop_back();
	}
	if (digits.size() % 4 == 1) {
		return false;
	}
	std::string out;
	uint32_t buffer = 0;
	int bits = 0;
	for (const char c : digits) {
		const int value = _base64_value(c);
		if (value < 0) {
			return false;
		}
		buffer = (buffer << 6) | uint32_t(value);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out += char((buffer >> bits) & 0xff);
		}
	}
	r_bytes = out;
	return true;
}

} // namespace text
