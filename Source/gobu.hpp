/**************************************************************************/
/*  gobu.hpp                                                              */
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

#include "gobu_plugin.h"

#include <cstdint>
#include <functional>
#include <initializer_list>
#include <string>
#include <vector>

// A thin C++ layer over gobu_plugin.h: the engine's values, and its classes and singletons reached by name. The
// plugin has nothing of the engine but this interface, so it is a library of its own.
namespace gobu {

extern const GobuPluginApi *api;
extern GobuPluginHandle plugin;

// An engine value (Variant): copied with its references, released when it goes.
class Value {
	mutable GobuVariant variant;

	struct Adopt {};
	Value(const GobuVariant &p_variant, Adopt) :
			variant(p_variant) {}

public:
	Value();
	Value(bool p_value);
	Value(int p_value);
	Value(int64_t p_value);
	Value(double p_value);
	Value(const char *p_text);
	Value(const std::string &p_text);
	Value(GobuObject *p_object); // Keeps a RefCounted alive.
	Value(const Value &p_other);
	Value &operator=(const Value &p_other);
	~Value();

	// One the engine wrote (an r_return): this one owns it now.
	static Value adopt(const GobuVariant &p_variant) { return Value(p_variant, Adopt()); }
	static Value copy_of(const GobuVariant *p_variant);
	static Value bytes(const std::string &p_bytes); // PackedByteArray.
	static Value array();
	static Value dictionary();

	int type() const;
	bool is_nil() const { return type() == GOBU_TYPE_NIL; }
	bool to_bool() const;
	int64_t to_int() const;
	double to_float() const;
	std::string str() const; // A String's UTF-8; anything else, as text.
	std::string to_bytes() const; // A PackedByteArray's bytes.
	GobuObject *object() const; // nullptr when it is not one.

	// A method of the value, built-in (String, Dictionary, Callable...) or of its object.
	Value call(const char *p_method, std::initializer_list<Value> p_args = {}) const;

	// A Dictionary's (or an object's property).
	Value get(const Value &p_key, const Value &p_default = Value()) const;
	bool has(const Value &p_key) const;
	void set(const Value &p_key, const Value &p_value);
	Value keys() const; // An Array.
	// An Array's (a packed array's).
	int64_t size() const;
	Value at(int64_t p_index) const;
	void push_back(const Value &p_value);

	const GobuVariant *raw() const { return &variant; }
};

using Args = std::vector<Value>;

Value call(GobuObject *p_object, const char *p_method, std::initializer_list<Value> p_args = {});
GobuObject *singleton(const char *p_name); // nullptr when the engine has none by that name.
Value instantiate(const char *p_class);
GobuObjectId id_of(GobuObject *p_object);
GobuObject *object_of(GobuObjectId p_id); // nullptr once it was freed.

// A Callable that runs p_function, valid while p_owner lives.
Value callable(std::function<void(const Args &)> p_function, GobuObject *p_owner);

bool has_setting(const std::string &p_name);
Value setting(const std::string &p_name);

void log(int p_type, const std::string &p_message, const char *p_function, const char *p_file, int p_line);
bool is_verbose();

uint64_t ticks_msec();
bool has_feature(const char *p_feature);
bool has_environment(const char *p_name);
std::string environment(const char *p_name);

} // namespace gobu

#define GOBU_ERROR(m_message) gobu::log(GOBU_LOG_ERROR, m_message, __FUNCTION__, __FILE__, __LINE__)
#define GOBU_WARNING(m_message) gobu::log(GOBU_LOG_WARNING, m_message, __FUNCTION__, __FILE__, __LINE__)
#define GOBU_VERBOSE(m_message)                                               \
	if (gobu::is_verbose()) {                                                 \
		gobu::log(GOBU_LOG_INFO, m_message, __FUNCTION__, __FILE__, __LINE__); \
	} else                                                                    \
		((void)0)
