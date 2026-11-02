/**************************************************************************/
/*  gobu.cpp                                                              */
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

#include "gobu.hpp"

namespace gobu {

const GobuPluginApi *api = nullptr;
GobuPluginHandle plugin = nullptr;

Value::Value() {
	api->variant_new_nil(&variant);
}

Value::Value(bool p_value) {
	api->variant_new_bool(&variant, p_value);
}

Value::Value(int p_value) {
	api->variant_new_int(&variant, p_value);
}

Value::Value(int64_t p_value) {
	api->variant_new_int(&variant, p_value);
}

Value::Value(double p_value) {
	api->variant_new_float(&variant, p_value);
}

Value::Value(const char *p_text) {
	api->variant_new_string(&variant, p_text ? p_text : "", -1);
}

Value::Value(const std::string &p_text) {
	api->variant_new_string(&variant, p_text.data(), int64_t(p_text.size()));
}

Value::Value(GobuObject *p_object) {
	if (p_object) {
		api->variant_new_object(&variant, p_object);
	} else {
		api->variant_new_nil(&variant);
	}
}

Value::Value(const Value &p_other) {
	api->variant_new_copy(&variant, &p_other.variant);
}

Value &Value::operator=(const Value &p_other) {
	if (this != &p_other) {
		GobuVariant copy;
		api->variant_new_copy(&copy, &p_other.variant);
		api->variant_destroy(&variant);
		variant = copy;
	}
	return *this;
}

Value::~Value() {
	api->variant_destroy(&variant);
}

Value Value::copy_of(const GobuVariant *p_variant) {
	GobuVariant copy;
	api->variant_new_copy(&copy, p_variant);
	return adopt(copy);
}

Value Value::bytes(const std::string &p_bytes) {
	GobuVariant packed;
	api->variant_new_packed_byte_array(&packed, reinterpret_cast<const uint8_t *>(p_bytes.data()), int64_t(p_bytes.size()));
	return adopt(packed);
}

Value Value::array() {
	GobuVariant array;
	api->array_new(&array);
	return adopt(array);
}

Value Value::dictionary() {
	GobuVariant dictionary;
	api->dictionary_new(&dictionary);
	return adopt(dictionary);
}

int Value::type() const {
	return api->variant_get_type(&variant);
}

bool Value::to_bool() const {
	return api->variant_to_bool(&variant);
}

int64_t Value::to_int() const {
	return api->variant_to_int(&variant);
}

double Value::to_float() const {
	return api->variant_to_float(&variant);
}

std::string Value::str() const {
	const int64_t length = api->variant_to_utf8(&variant, nullptr, 0);
	std::string text(size_t(length) + 1, '\0');
	api->variant_to_utf8(&variant, text.data(), length + 1);
	text.resize(size_t(length));
	return text;
}

std::string Value::to_bytes() const {
	if (type() != GOBU_TYPE_PACKED_BYTE_ARRAY) {
		return std::string();
	}
	const uint8_t *data = api->packed_byte_array_data(&variant);
	return data ? std::string(reinterpret_cast<const char *>(data), size_t(api->variant_size(&variant))) : std::string();
}

GobuObject *Value::object() const {
	return type() == GOBU_TYPE_OBJECT ? api->variant_to_object(&variant) : nullptr;
}

Value Value::call(const char *p_method, std::initializer_list<Value> p_args) const {
	std::vector<const GobuVariant *> args;
	for (const Value &arg : p_args) {
		args.push_back(arg.raw());
	}
	GobuVariant result;
	GobuCallError error = {};
	api->variant_call(&variant, p_method, args.data(), int64_t(args.size()), &result, &error);
	if (error.error != GOBU_CALL_OK) {
		GOBU_ERROR(std::string("Authentication: calling \"") + p_method + "\" failed (error " + std::to_string(error.error) + ", argument " + std::to_string(error.argument) + ").");
	}
	return adopt(result);
}

Value Value::get(const Value &p_key, const Value &p_default) const {
	if (type() == GOBU_TYPE_DICTIONARY) {
		const GobuVariant *found = api->dictionary_find(&variant, p_key.raw());
		return found ? copy_of(found) : p_default;
	}
	GobuVariant value;
	if (!api->variant_get(&variant, p_key.raw(), &value)) {
		api->variant_destroy(&value);
		return p_default;
	}
	return adopt(value);
}

bool Value::has(const Value &p_key) const {
	if (type() == GOBU_TYPE_DICTIONARY) {
		return api->dictionary_find(&variant, p_key.raw()) != nullptr;
	}
	return call("has", { p_key }).to_bool();
}

void Value::set(const Value &p_key, const Value &p_value) {
	if (type() == GOBU_TYPE_DICTIONARY) {
		GobuVariant *slot = api->dictionary_index(&variant, p_key.raw());
		api->variant_destroy(slot);
		api->variant_new_copy(slot, p_value.raw());
		return;
	}
	api->variant_set(&variant, p_key.raw(), p_value.raw());
}

Value Value::keys() const {
	GobuVariant keys;
	api->dictionary_keys(&variant, &keys);
	return adopt(keys);
}

int64_t Value::size() const {
	return api->variant_size(&variant);
}

Value Value::at(int64_t p_index) const {
	GobuVariant value;
	if (!api->variant_get_indexed(&variant, p_index, &value)) {
		api->variant_destroy(&value);
		return Value();
	}
	return adopt(value);
}

void Value::push_back(const Value &p_value) {
	if (type() == GOBU_TYPE_ARRAY) {
		api->array_push_back(&variant, p_value.raw());
	} else {
		call("push_back", { p_value });
	}
}

Value call(GobuObject *p_object, const char *p_method, std::initializer_list<Value> p_args) {
	if (!p_object) {
		GOBU_ERROR(std::string("Authentication: calling \"") + p_method + "\" of no object.");
		return Value();
	}
	std::vector<const GobuVariant *> args;
	for (const Value &arg : p_args) {
		args.push_back(arg.raw());
	}
	GobuVariant result;
	GobuCallError error = {};
	api->object_call(p_object, p_method, args.data(), int64_t(args.size()), &result, &error);
	if (error.error != GOBU_CALL_OK) {
		GOBU_ERROR(std::string("Authentication: calling \"") + p_method + "\" failed (error " + std::to_string(error.error) + ", argument " + std::to_string(error.argument) + ").");
	}
	return Value::adopt(result);
}

GobuObject *singleton(const char *p_name) {
	return api->get_singleton(p_name);
}

Value instantiate(const char *p_class) {
	GobuVariant object;
	api->classdb_instantiate(p_class, &object);
	return Value::adopt(object);
}

GobuObjectId id_of(GobuObject *p_object) {
	return api->object_get_instance_id(p_object);
}

GobuObject *object_of(GobuObjectId p_id) {
	return p_id ? api->object_from_instance_id(p_id) : nullptr;
}

namespace {

struct CallableData {
	std::function<void(const Args &)> function;
};

void _callable_call(void *p_userdata, const GobuVariant *const *p_args, int64_t p_arg_count, GobuVariant *r_return, GobuCallError *) {
	Args args;
	for (int64_t i = 0; i < p_arg_count; i++) {
		args.push_back(Value::copy_of(p_args[i]));
	}
	static_cast<CallableData *>(p_userdata)->function(args);
	api->variant_new_nil(r_return);
}

void _callable_free(void *p_userdata) {
	delete static_cast<CallableData *>(p_userdata);
}

} // namespace

Value callable(std::function<void(const Args &)> p_function, GobuObject *p_owner) {
	GobuVariant result;
	api->callable_new_custom(&result, _callable_call, new CallableData{ std::move(p_function) }, _callable_free, p_owner);
	return Value::adopt(result);
}

bool has_setting(const std::string &p_name) {
	GobuVariant value;
	const bool found = api->get_setting(p_name.c_str(), &value);
	api->variant_destroy(&value);
	return found;
}

Value setting(const std::string &p_name) {
	GobuVariant value;
	api->get_setting(p_name.c_str(), &value);
	return Value::adopt(value);
}

void log(int p_type, const std::string &p_message, const char *p_function, const char *p_file, int p_line) {
	api->log(p_type, p_message.c_str(), p_function, p_file, p_line);
}

bool is_verbose() {
	return call(singleton("OS"), "is_stdout_verbose").to_bool();
}

uint64_t ticks_msec() {
	return uint64_t(call(singleton("Time"), "get_ticks_msec").to_int());
}

bool has_feature(const char *p_feature) {
	return call(singleton("OS"), "has_feature", { p_feature }).to_bool();
}

bool has_environment(const char *p_name) {
	return call(singleton("OS"), "has_environment", { p_name }).to_bool();
}

std::string environment(const char *p_name) {
	return call(singleton("OS"), "get_environment", { p_name }).str();
}

} // namespace gobu
