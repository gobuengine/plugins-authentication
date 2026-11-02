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

#include "register_types.h"

#include "authentication.h"

#include "core/config/engine.h"
#include "core/object/class_db.h"
#include "core/plugin/plugin_manager.h"

static Authentication *authentication = nullptr;

// A project that enabled the plugin: what it brings.
static void _enable_authentication() {
	GDREGISTER_CLASS(Authentication);
	authentication = memnew(Authentication);
	Engine::get_singleton()->add_singleton(Engine::Singleton("Authentication", Authentication::get_singleton()));
}

void initialize_authentication_module(ModuleInitializationLevel p_level) {
	if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) {
		return;
	}
	GobuPlugins::BuiltIn plugin;
	plugin.id = Authentication::PLUGIN_ID;
	plugin.name = "Authentication";
	plugin.description = "Players sign in with Google, Supabase, Firebase, Auth0 or any other service: the game gets their token, to call the service's API or to join an online game, and a server checks it. Set it up in Project Settings > Authentication.";
	plugin.category = "Services";
	plugin.classes.push_back("Authentication");
	plugin.enable = &_enable_authentication;
	GobuPlugins::register_built_in(plugin);
}

void uninitialize_authentication_module(ModuleInitializationLevel p_level) {
	if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE || !authentication) {
		return;
	}
	Engine::get_singleton()->remove_singleton("Authentication");
	memdelete(authentication);
	authentication = nullptr;
}
