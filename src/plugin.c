/*
 * Copyright 2010-2021, Tarantool AUTHORS, please see AUTHORS file.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "module.h"
#include <stdlib.h>
#include <assert.h>

enum {
	CFG_URI_OPTION_HOST = 0,
	CFG_URI_OPTION_TRANSPORT = 1,
	CFG_URI_OPTION_MAX
};

struct cfg_uri_option {
	const char **values;
	int size;
};

struct cfg_uri {
	const char *host;
	struct cfg_uri_option transport;
};

struct cfg_uri_array {
	struct cfg_uri *uris;
	int size;
};

struct cfg_uri_array *
cfg_uri_array_new(const char *option_name)
{
	fprintf(stderr, "cfg_uri_array_new\n");
	return NULL;
}

void
cfg_uri_array_delete(struct cfg_uri_array *uri_array)
{
	fprintf(stderr, "cfg_uri_array_delete\n");
}

int
cfg_uri_array_size(const struct cfg_uri_array *uri_array)
{
	fprintf(stderr, "cfg_uri_array_size\n");
	return 0;
}

const char *
cfg_uri_array_get_uri(const struct cfg_uri_array *uri_array, int idx)
{
	fprintf(stderr, "cfg_uri_array_get_uri\n");
	return NULL;
}

int
cfg_uri_array_check_uri(const struct cfg_uri_array *uri_array,
			int (*check_uri)(const char *, const char *),
			const char *option_name)
{
	fprintf(stderr, "cfg_uri_array_check_uri\n");
	return 0;
}

#if 0

static int
cfg_uri_get_option(struct lua_State *L, const char *name,
		   struct cfg_uri_option *uri_option)
{
	if (lua_isnil(L, -1))
		return 0;
	if (!lua_istable(L, -1)) {
		diag_set(ClientError, ER_CFG, name,
			 "URI option should be a table");
		return -1;
	}
	int size = lua_objlen(L, -1);
	if (size == 0)
		return 0;
	uri_option->values =
		(const char **)calloc(size, sizeof(char *));
	if (uri_option->values == NULL) {
		diag_set(OutOfMemory, size * sizeof(char *),
			 "calloc", "cfg_uri_option");
		return -1;
	}
	uri_option->size = size;
	for (int i = 0; i < uri_option->size; i++) {
		lua_rawgeti(L, -1, i + 1);
		uri_option->values[i] = lua_tostring(L, -1);
		lua_pop(L, 1);
	}
	return 0;
}

static void
cfg_uri_destroy(struct cfg_uri *uri)
{
	free(uri->transport.values);
}

static void
cfg_uri_init(struct cfg_uri *uri)
{
	memset(uri, 0, sizeof(struct cfg_uri));
}

static int
cfg_uri_get(struct lua_State *L, const char *name,
	    struct cfg_uri *uri, int idx)
{
	const char *cfg_uri_options[CFG_URI_OPTION_MAX] = {
		/* CFG_URI_OPTION_HOST */      "uri",
		/* CFG_URI_OPTION_TRANSPORT */ "transport",
	};
	for (unsigned i = 0; i < lengthof(cfg_uri_options); i++) {
		lua_rawgeti(L, -1, idx + 1);
		lua_pushstring(L, cfg_uri_options[i]);
		lua_gettable(L, -2);
		switch (i) {
		case CFG_URI_OPTION_HOST:
			if (!lua_isstring(L, -1)) {
				diag_set(ClientError, ER_CFG, name,
					 "URI should be a string");
				goto fail;
			}
			uri->host = lua_tostring(L, -1);
			break;
		case CFG_URI_OPTION_TRANSPORT:
			if (cfg_uri_get_option(L, name, &uri->transport) != 0)
				goto fail;
			break;
		default:
			unreachable();
		}
		lua_pop(L, 2);
	}
	return 0;
fail:
	lua_pop(L, 2);
	cfg_uri_destroy(uri);
	return -1;
}

static struct cfg_uri_array *
cfg_uri_array_new_impl()
{
	return xcalloc(1, sizeof(struct cfg_uri_array));
}

static void
cfg_uri_array_delete_impl(struct cfg_uri_array *uri_array)
{
	free(uri_array);
}

static int
cfg_uri_array_create_impl(lua_State *L, const char *name,
			  struct cfg_uri_array *uri_array)
{
	int rc = 0;
	memset(uri_array, 0, sizeof(*uri_array));
	if (cfg_get_uri_array(L, name))
		return -1;
	if (!lua_istable(L, -1)) {
		if (!lua_isnil(L, -1)) {
			diag_set(ClientError, ER_CFG, name,
				 "should be a table");
			rc = -1;
		}
		lua_pop(L, 1);
		return rc;
	}
	int size = lua_objlen(L, -1);
	if (size == 0) {
		diag_set(ClientError, ER_CFG, name,
			 "URI table should not be empty");
		lua_pop(L, 1);
		return -1;
	}
	uri_array->uris = (struct cfg_uri *)calloc(size, sizeof(struct cfg_uri));
	if (uri_array->uris == NULL) {
		diag_set(OutOfMemory, size * sizeof(struct cfg_uri),
			 "calloc", "cfg_uri");
		lua_pop(L, 1);
		return -1;
	}
	for (uri_array->size = 0; uri_array->size < size; uri_array->size++) {
		int i = uri_array->size;
		cfg_uri_init(&uri_array->uris[i]);
		rc = cfg_uri_get(L, name, &uri_array->uris[i], i);
		if (rc != 0)
			break;
	}
	lua_pop(L, 1);
	if (rc != 0)
		cfg_uri_array_destroy(uri_array);
	return rc;
}

static void
cfg_uri_array_destroy_impl(struct cfg_uri_array *uri_array)
{
	for (int i = 0; i < uri_array->size; i++)
		cfg_uri_destroy(&uri_array->uris[i]);
	free(uri_array->uris);
}

static int
cfg_uri_array_size_impl(const struct cfg_uri_array *uri_array)
{
	return uri_array->size;
}

static const char *
cfg_uri_array_get_uri_impl(const struct cfg_uri_array *uri_array, int idx)
{
	assert(idx < uri_array->size);
	return uri_array->uris[idx].host;
}

static int
cfg_uri_array_check_impl(const struct cfg_uri_array *uri_array,
		    cfg_uri_array_checker checker,
		    const char *option_name)
{
	for (int i = 0; i < uri_array->size; i++) {
		if (checker(uri_array->uris[i].host, option_name) != 0)
			return -1;
	}
	return 0;
}

extern char normalize_uri_ee_lua[];

int
tt_plugin_entry(struct lua_State *L)
{
	char buf[MAX_OPT_NAME_LEN];
	snprintf(buf, MAX_OPT_NAME_LEN,
		 "return box.internal.change_template_cfg('listen', 'number, string, table')");
	if (luaT_dostring(L, buf) != 0)
		return -1;
	if (luaT_loadbuffer(L, normalize_uri_ee_lua,
			    strlen(normalize_uri_ee_lua),
			    "normalize_uri_ee.lua") ||
	    lua_pcall(L, 0, 0, 0) != 0) {
		return -1;
	}
	return 0;
}

#endif