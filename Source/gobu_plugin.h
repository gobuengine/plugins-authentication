/**************************************************************************/
/*  gobu_plugin.h                                                         */
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

/*
 * The interface between Gobu and an external plugin (a .dll, .so, .dylib or
 * WebAssembly side module). It is plain C, so a plugin can be written in C,
 * C++, Zig, Rust... and built with any compiler. Copy this header into the
 * plugin's sources: it is all a plugin needs.
 *
 * A plugin exports one function (`gobu_plugin_init` unless plugin.json names
 * another `entry`):
 *
 *     GOBU_PLUGIN_EXPORT bool gobu_plugin_init(const GobuPluginApi *api,
 *             GobuPluginHandle handle, GobuPluginInfo *r_info);
 *
 * There it checks `api->version` / `api->size`, registers its classes and
 * returns true. Everything else of the engine is reached by name: call a
 * method of any value or object (`variant_call`, `object_call`), read a
 * singleton (`get_singleton`), instantiate a class (`classdb_instantiate`).
 * Renaming an engine class does not change this interface.
 *
 * Rules:
 * - A GobuVariant is the engine's own value. Initialize it with a
 *   `variant_new_*` function (or receive it initialized) and release it with
 *   `variant_destroy`. Copying its bytes is not a copy.
 * - An output GobuVariant (`r_dest`, `r_return`, `r_value`...) is written as
 *   uninitialized memory: it is not destroyed first.
 * - Strings cross as UTF-8. A length below zero means "up to the NUL".
 * - Registration only happens inside the init function.
 * - Call the engine from the main thread, except `object_call_deferred`.
 * - New functions are only ever added at the end of GobuPluginApi, so a plugin
 *   built for version N runs on N or later; `size` says which ones exist.
 */

#ifndef GOBU_PLUGIN_H
#define GOBU_PLUGIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GOBU_PLUGIN_API_VERSION 3

#if defined(_WIN32)
#define GOBU_PLUGIN_EXPORT __declspec(dllexport)
#elif defined(__EMSCRIPTEN__)
/* `used`: a side module built with -sSIDE_MODULE=2 only keeps what is marked. */
#define GOBU_PLUGIN_EXPORT __attribute__((used, visibility("default")))
#elif defined(__GNUC__) || defined(__clang__)
#define GOBU_PLUGIN_EXPORT __attribute__((visibility("default")))
#else
#define GOBU_PLUGIN_EXPORT
#endif

/* The engine's Variant (24 bytes). Only build it with the API functions. */
typedef struct GobuVariant {
	uint64_t opaque[3];
} GobuVariant;

typedef struct GobuObject GobuObject; /* An engine Object. */
typedef uint64_t GobuObjectId; /* Stable across frees: 0 or a freed id gives NULL. */
typedef struct GobuPluginData *GobuPluginHandle; /* This plugin, for registration. */

typedef enum GobuVariantType {
	GOBU_TYPE_NIL,
	GOBU_TYPE_BOOL,
	GOBU_TYPE_INT,
	GOBU_TYPE_FLOAT,
	GOBU_TYPE_STRING,
	GOBU_TYPE_VECTOR2,
	GOBU_TYPE_VECTOR2I,
	GOBU_TYPE_RECT2,
	GOBU_TYPE_RECT2I,
	GOBU_TYPE_VECTOR3,
	GOBU_TYPE_VECTOR3I,
	GOBU_TYPE_TRANSFORM2D,
	GOBU_TYPE_VECTOR4,
	GOBU_TYPE_VECTOR4I,
	GOBU_TYPE_PLANE,
	GOBU_TYPE_QUATERNION,
	GOBU_TYPE_AABB,
	GOBU_TYPE_BASIS,
	GOBU_TYPE_TRANSFORM3D,
	GOBU_TYPE_PROJECTION,
	GOBU_TYPE_COLOR,
	GOBU_TYPE_STRING_NAME,
	GOBU_TYPE_NODE_PATH,
	GOBU_TYPE_RID,
	GOBU_TYPE_OBJECT,
	GOBU_TYPE_CALLABLE,
	GOBU_TYPE_SIGNAL,
	GOBU_TYPE_DICTIONARY,
	GOBU_TYPE_ARRAY,
	GOBU_TYPE_PACKED_BYTE_ARRAY,
	GOBU_TYPE_PACKED_INT32_ARRAY,
	GOBU_TYPE_PACKED_INT64_ARRAY,
	GOBU_TYPE_PACKED_FLOAT32_ARRAY,
	GOBU_TYPE_PACKED_FLOAT64_ARRAY,
	GOBU_TYPE_PACKED_STRING_ARRAY,
	GOBU_TYPE_PACKED_VECTOR2_ARRAY,
	GOBU_TYPE_PACKED_VECTOR3_ARRAY,
	GOBU_TYPE_PACKED_COLOR_ARRAY,
	GOBU_TYPE_PACKED_VECTOR4_ARRAY,
	GOBU_TYPE_MAX,
} GobuVariantType;

typedef enum GobuCallErrorType {
	GOBU_CALL_OK,
	GOBU_CALL_ERROR_INVALID_METHOD,
	GOBU_CALL_ERROR_INVALID_ARGUMENT, /* `expected` is the GobuVariantType wanted. */
	GOBU_CALL_ERROR_TOO_MANY_ARGUMENTS, /* `expected` is the argument count. */
	GOBU_CALL_ERROR_TOO_FEW_ARGUMENTS, /* `expected` is the argument count. */
	GOBU_CALL_ERROR_INSTANCE_IS_NULL,
	GOBU_CALL_ERROR_METHOD_NOT_CONST,
} GobuCallErrorType;

typedef struct GobuCallError {
	int32_t error; /* GobuCallErrorType */
	int32_t argument;
	int32_t expected;
} GobuCallError;

/* An argument, return value, signal argument or property. */
typedef struct GobuArgInfo {
	const char *name;
	int32_t type; /* GobuVariantType; GOBU_TYPE_NIL with GOBU_ARG_ANY_VARIANT accepts anything. */
	uint32_t flags; /* GobuArgFlags */
	const char *class_name; /* For GOBU_TYPE_OBJECT: the expected class, or NULL. */
} GobuArgInfo;

typedef enum GobuArgFlags {
	GOBU_ARG_ANY_VARIANT = 1 << 0,
} GobuArgFlags;

/* A method of a plugin class. `instance` is what create_instance returned (NULL for a static method).
 * `r_return` is initialized to nil: assign it with a variant_new_* function. */
typedef void (*GobuMethodFunc)(void *method_userdata, void *instance, const GobuVariant *const *args, int64_t arg_count, GobuVariant *r_return, GobuCallError *r_error);

typedef enum GobuMethodFlags {
	GOBU_METHOD_STATIC = 1 << 0,
	GOBU_METHOD_VARARG = 1 << 1, /* Takes extra arguments past `args`. */
	GOBU_METHOD_CONST = 1 << 2,
} GobuMethodFlags;

typedef struct GobuMethodInfo {
	const char *name;
	GobuMethodFunc func;
	void *userdata;
	uint32_t flags; /* GobuMethodFlags */
	bool has_return;
	GobuArgInfo return_info;
	int32_t arg_count;
	const GobuArgInfo *args;
	int32_t default_arg_count; /* Defaults of the last arguments. */
	const GobuVariant *const *default_args;
} GobuMethodInfo;

/* Creates the plugin's data for a new object of the class. The object is
 * already of the plugin class; it must not be freed here. */
typedef void *(*GobuCreateInstanceFunc)(void *class_userdata, GobuObject *object);
/* The object is being freed: release the data. Its signals are still connected. */
typedef void (*GobuFreeInstanceFunc)(void *class_userdata, void *instance);
/* Object notifications (NOTIFICATION_READY, NOTIFICATION_PROCESS...). */
typedef void (*GobuNotificationFunc)(void *class_userdata, void *instance, int32_t what, bool reversed);

typedef enum GobuClassFlags {
	GOBU_CLASS_ABSTRACT = 1 << 0, /* Cannot be instantiated (only its subclasses). */
	GOBU_CLASS_HIDDEN = 1 << 1, /* Not listed in the editor's Create dialogs. */
} GobuClassFlags;

typedef struct GobuClassInfo {
	const char *name;
	const char *parent; /* An engine class: "Shared", "Actor", "Spatial2D"... */
	uint32_t flags; /* GobuClassFlags */
	void *userdata;
	GobuCreateInstanceFunc create_instance;
	GobuFreeInstanceFunc free_instance;
	GobuNotificationFunc notification; /* May be NULL. */
} GobuClassInfo;

/* A callable made by the plugin (a signal handler, a callback for the engine). */
typedef void (*GobuCallableFunc)(void *userdata, const GobuVariant *const *args, int64_t arg_count, GobuVariant *r_return, GobuCallError *r_error);
typedef void (*GobuFreeFunc)(void *userdata);

/* Called on the main thread once per frame, before the scene is processed. */
typedef void (*GobuProcessFunc)(void *userdata, double delta);

typedef enum GobuLogType {
	GOBU_LOG_INFO,
	GOBU_LOG_WARNING,
	GOBU_LOG_ERROR,
} GobuLogType;

/* Online providers (version 2): where the players of an online game meet, for an online service (its
 * matchmaking, relays, accounts). The engine makes the connection Online uses out of these functions, so the
 * game's code is the same with every provider. Peer ids: the server (a player that hosts, or a dedicated
 * server) is 1; the provider gives the others (any other positive id). Everything happens on the main
 * thread: the provider calls the events from its poll(). */
typedef enum GobuOnlineSendMode {
	GOBU_ONLINE_SEND_RELIABLE,
	GOBU_ONLINE_SEND_UNRELIABLE,
} GobuOnlineSendMode;

/* Given to open/join/match; valid until close(). Pass `connection` back to every event. */
typedef struct GobuOnlineEvents {
	void *connection;
	/* Ready: this game is peer `my_id` (1: it is the server, as a game that matched first and made the
	 * game may be). open() needs none: that game is the server at once. */
	void (*connected)(void *connection, int32_t my_id);
	void (*failed)(void *connection, const char *reason); /* Could not join or match. */
	void (*peer_joined)(void *connection, int32_t peer);
	void (*peer_left)(void *connection, int32_t peer);
	void (*packet)(void *connection, int32_t from, const uint8_t *data, int64_t size);
	void (*closed)(void *connection, const char *reason); /* Lost: the server left, the service ended it. */
	/* Host migration: the host left and the game that was peer `previous_id` is the host now, peer 1 (when
	 * that is this game, it is the server from now on; the other players come as peer_joined). The game goes
	 * on. A provider without migration calls closed() instead. */
	void (*host_changed)(void *connection, int32_t previous_id);
} GobuOnlineEvents;

typedef enum GobuOnlineProviderFlags {
	GOBU_ONLINE_CAN_OPEN = 1 << 0, /* open(): this game hosts the game, or is a dedicated server. */
	GOBU_ONLINE_CAN_JOIN = 1 << 1, /* join(address). */
	GOBU_ONLINE_CAN_MATCH = 1 << 2, /* match(): the service finds a game with room or makes one. */
} GobuOnlineProviderFlags;

typedef struct GobuOnlineProviderInfo {
	const char *name; /* As Project Settings > Online > Session > Provider names it ("colyseus"). */
	uint32_t flags; /* GobuOnlineProviderFlags */
	void *userdata;
	/* Each starts a connection and returns its data (given to the functions below), or NULL with `r_error`
	 * set to a String. A function its flags leave out may be NULL. */
	void *(*open)(void *userdata, int32_t port, int32_t max_players, const GobuOnlineEvents *events, GobuVariant *r_error);
	void *(*join)(void *userdata, const char *address, int32_t port, const GobuOnlineEvents *events, GobuVariant *r_error);
	void *(*match)(void *userdata, const char *mode, int32_t max_players, const GobuOnlineEvents *events, GobuVariant *r_error);
	/* To a peer, or to every peer with `to` 0. `mode`: GobuOnlineSendMode. */
	void (*send)(void *connection, int32_t to, const uint8_t *data, int64_t size, int32_t mode);
	void (*poll)(void *connection);
	void (*kick)(void *connection, int32_t peer); /* The server turns a player away. May be NULL. */
	void (*close)(void *connection); /* Frees it: no event after this. */
} GobuOnlineProviderInfo;

typedef struct GobuPluginApi {
	uint32_t version; /* GOBU_PLUGIN_API_VERSION of the engine. */
	uint32_t size; /* sizeof(GobuPluginApi) of the engine. */

	/* Log. `file`/`function` may be NULL. */
	void (*log)(int32_t type, const char *message, const char *function, const char *file, int32_t line);

	/* Memory the engine may free (or that the plugin frees with mem_free). */
	void *(*mem_alloc)(size_t bytes);
	void *(*mem_realloc)(void *ptr, size_t bytes);
	void (*mem_free)(void *ptr);

	/* Values. */
	void (*variant_new_nil)(GobuVariant *r_dest);
	void (*variant_new_copy)(GobuVariant *r_dest, const GobuVariant *src);
	void (*variant_new_type)(GobuVariant *r_dest, int32_t type); /* The type's default value. */
	void (*variant_new_bool)(GobuVariant *r_dest, bool value);
	void (*variant_new_int)(GobuVariant *r_dest, int64_t value);
	void (*variant_new_float)(GobuVariant *r_dest, double value);
	void (*variant_new_string)(GobuVariant *r_dest, const char *utf8, int64_t length);
	void (*variant_new_string_name)(GobuVariant *r_dest, const char *utf8, int64_t length);
	void (*variant_new_object)(GobuVariant *r_dest, GobuObject *object); /* Keeps a Shared alive. */
	void (*variant_new_packed_byte_array)(GobuVariant *r_dest, const uint8_t *data, int64_t size);
	void (*variant_destroy)(GobuVariant *value);
	int32_t (*variant_get_type)(const GobuVariant *value);

	bool (*variant_to_bool)(const GobuVariant *value);
	int64_t (*variant_to_int)(const GobuVariant *value);
	double (*variant_to_float)(const GobuVariant *value);
	GobuObject *(*variant_to_object)(const GobuVariant *value); /* NULL if not an object or freed. */
	/* The text of a String, StringName or NodePath (anything else: its text form). Writes up to
	 * `buffer_size - 1` bytes and a NUL, and returns the full length: call with NULL/0 to measure. */
	int64_t (*variant_to_utf8)(const GobuVariant *value, char *buffer, int64_t buffer_size);
	void (*variant_stringify)(const GobuVariant *value, GobuVariant *r_string);
	bool (*variant_equals)(const GobuVariant *a, const GobuVariant *b);

	/* Call a method of any value, built-in (String, Array, Dictionary...) or object. */
	void (*variant_call)(GobuVariant *self, const char *method, const GobuVariant *const *args, int64_t arg_count, GobuVariant *r_return, GobuCallError *r_error);
	/* self[key] / self.key: Dictionary keys, Array indices, object properties. */
	bool (*variant_get)(const GobuVariant *self, const GobuVariant *key, GobuVariant *r_value);
	bool (*variant_set)(GobuVariant *self, const GobuVariant *key, const GobuVariant *value);
	bool (*variant_get_indexed)(const GobuVariant *self, int64_t index, GobuVariant *r_value);
	bool (*variant_set_indexed)(GobuVariant *self, int64_t index, const GobuVariant *value);

	/* Containers, in place. A GobuVariant pointer returned here lives as long as the element. */
	int64_t (*variant_size)(const GobuVariant *container); /* Array, Dictionary, packed array, string. */
	void (*array_new)(GobuVariant *r_dest);
	GobuVariant *(*array_index)(GobuVariant *array, int64_t index); /* NULL if out of range. */
	void (*array_push_back)(GobuVariant *array, const GobuVariant *value);
	void (*array_resize)(GobuVariant *array, int64_t size);
	void (*dictionary_new)(GobuVariant *r_dest);
	GobuVariant *(*dictionary_index)(GobuVariant *dictionary, const GobuVariant *key); /* Adds nil if missing. */
	const GobuVariant *(*dictionary_find)(const GobuVariant *dictionary, const GobuVariant *key); /* NULL if missing. */
	void (*dictionary_keys)(const GobuVariant *dictionary, GobuVariant *r_array);
	uint8_t *(*packed_byte_array_data)(GobuVariant *array); /* NULL if empty. */
	void (*packed_byte_array_resize)(GobuVariant *array, int64_t size);

	/* Callables. `object`, if any, is the owner: the callable stops being valid when it is freed. */
	void (*callable_new_custom)(GobuVariant *r_dest, GobuCallableFunc func, void *userdata, GobuFreeFunc free_userdata, GobuObject *object);
	void (*callable_new_method)(GobuVariant *r_dest, GobuObject *object, const char *method);

	/* Objects. */
	GobuObjectId (*object_get_instance_id)(const GobuObject *object);
	GobuObject *(*object_from_instance_id)(GobuObjectId id);
	/* The data create_instance returned, if `object` is of a class of this plugin; NULL otherwise. */
	void *(*object_get_plugin_instance)(GobuPluginHandle plugin, const GobuObject *object);
	void (*object_call)(GobuObject *object, const char *method, const GobuVariant *const *args, int64_t arg_count, GobuVariant *r_return, GobuCallError *r_error);
	/* Queued and run on the main thread at the end of the frame. Can be called from any thread. */
	void (*object_call_deferred)(GobuObject *object, const char *method, const GobuVariant *const *args, int64_t arg_count);
	void (*object_emit_signal)(GobuObject *object, const char *signal, const GobuVariant *const *args, int64_t arg_count);
	bool (*object_is_class)(const GobuObject *object, const char *class_name);
	GobuObject *(*get_singleton)(const char *name); /* "ProjectSettings", "Engine", "OS"... */
	bool (*classdb_instantiate)(const char *class_name, GobuVariant *r_object);
	/* The new object without a reference: hand it to a Variant (variant_new_object), which keeps a
	 * Shared alive, or add it to the scene. classdb_instantiate is the safe form. */
	GobuObject *(*classdb_construct_object)(const char *class_name);

	/* Registration (only inside the init function). */
	bool (*register_class)(GobuPluginHandle plugin, const GobuClassInfo *info);
	bool (*register_method)(GobuPluginHandle plugin, const char *class_name, const GobuMethodInfo *info);
	bool (*register_signal)(GobuPluginHandle plugin, const char *class_name, const char *signal, const GobuArgInfo *args, int32_t arg_count);
	bool (*register_property)(GobuPluginHandle plugin, const char *class_name, const GobuArgInfo *info, const char *setter, const char *getter);
	bool (*register_constant)(GobuPluginHandle plugin, const char *class_name, const char *enum_name, const char *name, int64_t value);
	void (*add_process_callback)(GobuPluginHandle plugin, GobuProcessFunc func, void *userdata);

	/* The project and the plugin. */
	bool (*get_setting)(const char *name, GobuVariant *r_value);
	/* The plugin's folder (res://plugins/<id>). Same buffer rules as variant_to_utf8. */
	int64_t (*plugin_get_path)(GobuPluginHandle plugin, char *buffer, int64_t buffer_size);
	bool (*is_editor)(void);

	/* Version 2. */
	/* Only inside the init function. The engine copies `info` (its `name` too). */
	bool (*register_online_provider)(GobuPluginHandle plugin, const GobuOnlineProviderInfo *info);

	/* Version 3. */
	/* Only inside the init function, after register_class: a new object of `class_name` (a class of this
	 * plugin, not a Shared nor GOBU_CLASS_HIDDEN) reached by `name` as the engine's singletons are
	 * (`Name.method()` in a script, get_singleton).
	 * The engine owns it and frees it at shutdown, before `deinitialize`. NULL if it can't be made. */
	GobuObject *(*register_singleton)(GobuPluginHandle plugin, const char *name, const char *class_name);
} GobuPluginApi;

/* Filled by the plugin's init function. */
typedef struct GobuPluginInfo {
	void *userdata;
	/* Called once when the engine shuts down, once the scene and the scripts are freed. If objects
	 * of the plugin's classes are still alive then, the plugin is left loaded and this is not called. */
	void (*deinitialize)(void *userdata);
} GobuPluginInfo;

typedef bool (*GobuPluginInitFunc)(const GobuPluginApi *api, GobuPluginHandle plugin, GobuPluginInfo *r_info);

#ifdef __cplusplus
}
#endif

#endif /* GOBU_PLUGIN_H */
