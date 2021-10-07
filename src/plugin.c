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

#define lengthof(array) (sizeof (array) / sizeof ((array)[0]))

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

static int
cfg_get_uri_array(struct lua_State *L, const char *param)
{
	char buf[MAX_OPT_NAME_LEN];
	snprintf(buf, MAX_OPT_NAME_LEN,
		 "return box.internal.cfg_get_%s(box.cfg.%s)",
		 param, param);
	if (luaT_dostring(L, buf) != 0)
		return -1;
	return 0;
}

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

static struct evio_service *
iproto_service_array_new_impl(void)
{
	return evio_service_alloc(IPROTO_LISTEN_SOCKET_MAX);
}

static void
iproto_service_array_delete_impl(struct evio_service *array)
{
	free(array);
}

static void
iproto_service_array_init_impl(struct evio_service *array, size_t *size,
			       struct ev_loop *loop, evio_accept_f on_accept,
			       void *on_accept_param)
{
	for (int i = 0; i < IPROTO_LISTEN_SOCKET_MAX; i++) {
		struct evio_service *service = evio_service_by_index(array, i);
		evio_service_init(loop, service, "service",
				  on_accept, on_accept_param);
	}
	*size = 0;
}

static const char *
iproto_service_array_fill_listen_info_impl(struct evio_service *array,
					   size_t size, char *buf)
{
	if (size == 0)
		return NULL;
	int cnt = 0;
	char *p = buf;
	const unsigned max = IPROTO_LISTEN_INFO_MAXLEN;
	for (int i = 0; i < size; i++) {
		/*
		 * We write the listening addresses to the buffer,
		 * separated by commas. After each write operation,
		 * we shift the pointer by the number of bytes written.
		 */
		struct evio_service *service = evio_service_by_index(array, i);
		cnt += evio_service_bound_address(p + cnt, service);
		if (i != size - 1)
			cnt += snprintf(p + cnt, max - cnt, ", ");
	}
	return buf;
}

static void
iproto_service_array_attach_impl(struct evio_service *dst, size_t *dst_size,
				 const struct evio_service *src,
				 size_t src_size)
{
	for (int i = 0; i < src_size; i++) {
		struct evio_service *d = evio_service_by_index(dst, i);
		const struct evio_service *s =
			evio_service_by_index((struct evio_service *)src, i);
		evio_service_attach(d, s);
	}
	*dst_size = src_size;
}

static void
iproto_service_array_detach_impl(struct evio_service *array, size_t *size)
{
	for (int i = 0; i < *size; i++) {
		struct evio_service *service = evio_service_by_index(array, i);
		evio_service_detach(service);
	}
	*size = 0;
}

static int
iproto_service_array_check_listen_impl(struct evio_service *array,
				       size_t size)
{
	for (int i = 0; i < size; i++) {
		struct evio_service *service = evio_service_by_index(array, i);
		if (evio_service_is_active(service))
			return -1;
	}
	return 0;
}

static int
iproto_service_array_start_listen_impl(struct evio_service *array,
				       size_t size)
{
	for (int i = 0; i < size; i++) {
		struct evio_service *service = evio_service_by_index(array, i);
		if (evio_service_listen(service) != 0)
			return -1;
	}
	return 0;
}

static void
iproto_service_array_stop_listen_impl(struct evio_service *array,
				      size_t *size)
{
	for (int i = 0; i < *size; i++) {
		struct evio_service *service = evio_service_by_index(array, i);
		evio_service_stop(service);
	}
	*size = 0;
}

static int
iproto_service_array_bind_impl(struct evio_service *array, size_t *size,
			       const struct cfg_uri_array *uri_array)
{
	int count = cfg_uri_array_size(uri_array);
	assert(count < IPROTO_LISTEN_SOCKET_MAX);
	for (*size = 0; *size < count; (*size)++) {
		const char *uri = cfg_uri_array_get_uri(uri_array, *size);
		struct evio_service *service =
			evio_service_by_index(array, *size);
		if (evio_service_bind(service, uri) != 0)
			return -1;
	}
	return 0;
}

extern char normalize_uri_ee_lua[];

int
tt_plugin_entry(struct lua_State *L)
{
	cfg_uri_array_new = cfg_uri_array_new_impl;
	cfg_uri_array_delete = cfg_uri_array_delete_impl;
	cfg_uri_array_create = cfg_uri_array_create_impl;
	cfg_uri_array_destroy = cfg_uri_array_destroy_impl;
	cfg_uri_array_size = cfg_uri_array_size_impl;
	cfg_uri_array_get_uri = cfg_uri_array_get_uri_impl;
	cfg_uri_array_check = cfg_uri_array_check_impl;
	iproto_service_array_new = iproto_service_array_new_impl;
	iproto_service_array_delete = iproto_service_array_delete_impl;
	iproto_service_array_init = iproto_service_array_init_impl;
	iproto_service_array_fill_listen_info =
		iproto_service_array_fill_listen_info_impl;
	iproto_service_array_attach = iproto_service_array_attach_impl;
	iproto_service_array_detach = iproto_service_array_detach_impl;
	iproto_service_array_check_listen =
		iproto_service_array_check_listen_impl;
	iproto_service_array_start_listen =
		iproto_service_array_start_listen_impl;
	iproto_service_array_stop_listen =
		iproto_service_array_stop_listen_impl;
	iproto_service_array_bind = iproto_service_array_bind_impl;
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