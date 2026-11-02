/**************************************************************************/
/*  text.h                                                                */
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

#include <string>
#include <vector>

// Text as UTF-8 bytes (std::string), and binary data the same way.
namespace text {

std::string strip(const std::string &p_text); // Spaces, tabs and line ends at both ends.
std::string lower(const std::string &p_text); // ASCII.
bool starts_with(const std::string &p_text, const std::string &p_prefix);
bool ends_with(const std::string &p_text, const std::string &p_suffix);
bool contains(const std::string &p_text, const std::string &p_part);
std::string trim_prefix(const std::string &p_text, const std::string &p_prefix);
std::string trim_suffix(const std::string &p_text, const std::string &p_suffix);
std::string replace(const std::string &p_text, const std::string &p_from, const std::string &p_to);
// The parts between each p_separator (empty ones too, unless p_skip_empty).
std::vector<std::string> split(const std::string &p_text, char p_separator, bool p_skip_empty = false);
bool has(const std::vector<std::string> &p_list, const std::string &p_item);

std::string uri_encode(const std::string &p_text); // All but A-Z a-z 0-9 - _ . ~ as %XX.
std::string uri_decode(const std::string &p_text);
std::string xml_escape(const std::string &p_text);

std::string base64(const std::string &p_bytes);
std::string base64url(const std::string &p_bytes); // URL-safe, without padding.
// Standard or URL-safe, with or without padding; false when it is not base64.
bool base64_decode(const std::string &p_text, std::string &r_bytes);

} // namespace text
