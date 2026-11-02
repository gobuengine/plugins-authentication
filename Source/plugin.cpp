/**************************************************************************/
/*  plugin.cpp                                                            */
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

// Once a frame: what waits for it, and a sign-in going on.
static void _frame(void *, double) {
	if (Authentication::singleton) {
		Authentication::singleton->frame();
	}
}

// The plugin's entry (plugin.json "entry"): Gobu calls it when it loads the library, in a project that enabled
// the plugin. The class, its singleton (freed by Gobu at the end) and its settings.
extern "C" GOBU_PLUGIN_EXPORT bool gobu_plugin_init(const GobuPluginApi *p_api, GobuPluginHandle p_plugin, GobuPluginInfo *r_info) {
	if (p_api->version < 3 || p_api->size < sizeof(GobuPluginApi)) {
		return false; // A Gobu older than this plugin: register_singleton() is version 3.
	}
	gobu::api = p_api;
	gobu::plugin = p_plugin;
	r_info->userdata = nullptr;
	r_info->deinitialize = nullptr;
	if (!Authentication::register_class()) {
		return false;
	}
	if (!p_api->register_singleton(p_plugin, Authentication::CLASS_NAME, Authentication::CLASS_NAME)) {
		return false;
	}
	p_api->add_process_callback(p_plugin, _frame, nullptr);
	return true;
}
