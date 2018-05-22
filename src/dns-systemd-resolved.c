/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2017  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <gdbus.h>
#include <glib.h>
#include <connman/dbus.h>

#include "connman.h"

#define SYSTEMD_RESOLVED_SERVICE "org.freedesktop.resolve1"
#define SYSTEMD_RESOLVED_PATH "/org/freedesktop/resolve1"

struct mdns_data {
	int index;
	bool enabled;
};

static GHashTable *interface_hash;
static DBusConnection *connection;
static GDBusClient *client;
static GDBusProxy *resolved_proxy;

/* update after a full set of instructions has been received */
static guint update_interfaces_source;

struct dns_interface {
	GList *domains;
	GList *servers;
	int index;
	bool needs_domain_update;
	bool needs_server_update;
};

static gboolean compare_index(gconstpointer a, gconstpointer b)
{
	gint ai = GPOINTER_TO_UINT(a);
	gint bi = GPOINTER_TO_UINT(b);

	return ai == bi;
}

static void free_dns_interface(gpointer data)
{
	struct dns_interface *iface = data;

	if (!iface)
		return;

	g_list_free_full(iface->domains, g_free);
	g_list_free_full(iface->servers, g_free);

	g_free(iface);
}

static void setlinkdns_append(DBusMessageIter *iter, void *user_data)
{
	struct dns_interface *iface = user_data;
	int result;
	unsigned int i;
	int type;
	char ipv4_bytes[4];
	char ipv6_bytes[16];
	GList *list;
	DBusMessageIter address_array, struct_array, byte_array;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_INT32, &iface->index);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "(iay)",
			&address_array);

	for (list = iface->servers; list; list = g_list_next(list)) {
		char *server = list->data;

		DBG("index: %d, server: %s", iface->index, server);

		dbus_message_iter_open_container(&address_array,
				DBUS_TYPE_STRUCT, NULL, &struct_array);

		type = connman_inet_check_ipaddress(server);

		if (type == AF_INET) {
			result = inet_pton(type, server, ipv4_bytes);
			if (!result) {
				DBG("Failed to parse IPv4 address: %s",
						server);
				return;
			}

			dbus_message_iter_append_basic(&struct_array,
					DBUS_TYPE_INT32, &type);

			dbus_message_iter_open_container(&struct_array,
					DBUS_TYPE_ARRAY, "y", &byte_array);

			for (i = 0; i < sizeof(ipv4_bytes); i++) {
				dbus_message_iter_append_basic(&byte_array,
						DBUS_TYPE_BYTE,
						&(ipv4_bytes[i]));
			}

			dbus_message_iter_close_container(&struct_array,
					&byte_array);
		} else if (type == AF_INET6) {
			result = inet_pton(type, server, ipv6_bytes);
			if (!result) {
				DBG("Failed to parse IPv6 address: %s", server);
				return;
			}

			dbus_message_iter_append_basic(&struct_array,
					DBUS_TYPE_INT32, &type);

			dbus_message_iter_open_container(&struct_array,
					DBUS_TYPE_ARRAY, "y", &byte_array);

			for (i = 0; i < sizeof(ipv6_bytes); i++) {
				dbus_message_iter_append_basic(&byte_array,
						DBUS_TYPE_BYTE,
						&(ipv6_bytes[i]));
			}

			dbus_message_iter_close_container(&struct_array,
					&byte_array);
		}

		dbus_message_iter_close_container(&address_array,
				&struct_array);
	}

	dbus_message_iter_close_container(iter, &address_array);
}

static void setlinkdomains_append(DBusMessageIter *iter, void *user_data)
{
	struct dns_interface *iface = user_data;
	GList *list;
	DBusMessageIter domain_array, struct_array;
	gboolean only_routing = FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_INT32, &iface->index);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "(sb)",
						&domain_array);

	for (list = iface->domains; list; list = g_list_next(list)) {
		char *domain = list->data;

		DBG("index: %d, domain: %s", iface->index, domain);

		dbus_message_iter_open_container(&domain_array,
				DBUS_TYPE_STRUCT, NULL, &struct_array);

		dbus_message_iter_append_basic(&struct_array, DBUS_TYPE_STRING,
				&domain);

		dbus_message_iter_append_basic(&struct_array, DBUS_TYPE_BOOLEAN,
				&only_routing);

		dbus_message_iter_close_container(&domain_array, &struct_array);
	}

	dbus_message_iter_close_container(iter, &domain_array);
}

static int set_systemd_resolved_values(struct dns_interface *iface)
{
	if (!resolved_proxy || !iface)
		return -ENOENT;

	/* No async error processing -- just fire and forget */

	if (iface->needs_server_update) {
		if (!g_dbus_proxy_method_call(resolved_proxy, "SetLinkDNS",
				setlinkdns_append, NULL, iface, NULL))
			return -EINVAL;

		iface->needs_server_update = FALSE;
	}

	if (iface->needs_domain_update) {
		if (!g_dbus_proxy_method_call(resolved_proxy, "SetLinkDomains",
				setlinkdomains_append, NULL, iface, NULL))
			return -EINVAL;

		iface->needs_domain_update = FALSE;
	}

	return 0;
}

static bool is_empty(struct dns_interface *iface)
{
	if (!iface)
		return FALSE;

	return (!iface->domains && !iface->servers);
}

static void update_interface(gpointer key, gpointer value, gpointer data)
{
	struct dns_interface *iface = value;
	GList **removed_items = data;

	set_systemd_resolved_values(iface);

	if (is_empty(iface))
		*removed_items = g_list_prepend(*removed_items, iface);
}

static int update_systemd_resolved(gpointer data)
{
	GList *removed_items = NULL, *list;

	if (!interface_hash) {
		DBG("no interface hash when updating");

		return G_SOURCE_REMOVE;
	}

	g_hash_table_foreach(interface_hash, update_interface, &removed_items);

	for (list = removed_items; list; list = g_list_next(list)) {
		struct dns_interface *iface = list->data;

		g_hash_table_remove(interface_hash,
				GUINT_TO_POINTER(iface->index));
	}

	g_list_free(removed_items);

	update_interfaces_source = 0;

	return G_SOURCE_REMOVE;
}

static GList *remove_string(GList *str_list, const char *str)
{
	GList *match = NULL;

	match = g_list_find_custom(str_list, str,
			(GCompareFunc) g_strcmp0);
	if (match) {
		g_free(match->data);
			return g_list_delete_link(str_list, match);
	}

	return str_list;
}

static void remove_values(struct dns_interface *iface, const char *domain,
							const char *server)
{
	if (!iface)
		return;

	if (domain) {
		iface->domains = remove_string(iface->domains, domain);
		iface->needs_domain_update = TRUE;
	}

	if (server) {
		iface->servers = remove_string(iface->servers, server);
		iface->needs_server_update = TRUE;
	}
}

int __connman_dnsproxy_remove(int index, const char *domain,
							const char *server)
{
	struct dns_interface *iface;

	DBG("%d, %s, %s", index, domain ? domain : "no domain",
			server ? server : "no server");

	if (!interface_hash || index < 0)
		return -EINVAL;

	iface = g_hash_table_lookup(interface_hash, GUINT_TO_POINTER(index));

	if (!iface)
		return -EINVAL;

	remove_values(iface, domain, server);

	if (!update_interfaces_source)
		update_interfaces_source = g_idle_add(update_systemd_resolved,
				NULL);

	return 0;
}

static GList *replace_to_end(GList *str_list, const char *str)
{
	GList *list;

	for (list = str_list; list; list = g_list_next(list)) {
		char *orig = list->data;

		if (g_strcmp0(orig, str) == 0) {
			str_list = g_list_remove(str_list, orig);
			g_free(orig);
			break;
		}
	}

	return g_list_append(str_list, g_strdup(str));
}

int __connman_dnsproxy_append(int index, const char *domain,
							const char *server)
{
	struct dns_interface *iface;

	DBG("%d, %s, %s", index, domain ? domain : "no domain",
			server ? server : "no server");

	if (!interface_hash || index < 0)
		return -EINVAL;

	iface = g_hash_table_lookup(interface_hash, GUINT_TO_POINTER(index));

	if (!iface) {
		iface = g_new0(struct dns_interface, 1);
		if (!iface)
			return -ENOMEM;

		iface->index = index;
		g_hash_table_replace(interface_hash, GUINT_TO_POINTER(index), iface);
	}

	if (domain) {
		iface->domains = replace_to_end(iface->domains, domain);
		iface->needs_domain_update = TRUE;
	}

	if (server) {
		iface->servers = replace_to_end(iface->servers, server);
		iface->needs_server_update = TRUE;
	}

	if (!update_interfaces_source)
		update_interfaces_source = g_idle_add(update_systemd_resolved,
				NULL);

	return 0;
}

int __connman_dnsproxy_add_listener(int index)
{
	DBG("");

	return -ENXIO;
}

void __connman_dnsproxy_remove_listener(int index)
{
	DBG("");
}

static int setup_resolved(void)
{
	connection = connman_dbus_get_connection();
	if (!connection)
		return -ENXIO;

	client = g_dbus_client_new(connection, SYSTEMD_RESOLVED_SERVICE,
			SYSTEMD_RESOLVED_PATH);

	if (!client)
		return -EINVAL;

	resolved_proxy = g_dbus_proxy_new(client, SYSTEMD_RESOLVED_PATH,
			"org.freedesktop.resolve1.Manager");

	if (!resolved_proxy)
		return -EINVAL;

	return 0;
}

static void setlinkmulticastdns_append(DBusMessageIter *iter, void *user_data) {
	struct mdns_data *data = user_data;
	char *val = "no";

	if (data->enabled)
		val = "yes";

	DBG("SetLinkMulticastDNS: %d/%s", data->index, val);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_INT32, &data->index);
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &val);
}

int __connman_dnsproxy_set_mdns(int index, bool enabled)
{
	struct mdns_data data = { .index = index, .enabled = enabled };

	if (!resolved_proxy)
		return -ENOENT;

	if (index < 0)
		return -EINVAL;

	if (!g_dbus_proxy_method_call(resolved_proxy, "SetLinkMulticastDNS",
			setlinkmulticastdns_append, NULL, &data, NULL))
		return -EINVAL;

	return 0;
}

int __connman_dnsproxy_init(void)
{
	int ret;

	DBG("");

	ret = setup_resolved();
	if (ret)
		return ret;

	interface_hash = g_hash_table_new_full(g_direct_hash,
						compare_index,
						NULL,
						free_dns_interface);
	if (!interface_hash)
		return -ENOMEM;

	return 0;
}

void __connman_dnsproxy_cleanup(void)
{
	DBG("");

	if (update_interfaces_source) {
		/*
		 * It might be that we don't get to an idle loop anymore, so
		 * run the update function once more to clean up.
		 */
		 g_source_remove(update_interfaces_source);
		 update_systemd_resolved(NULL);
		 update_interfaces_source = 0;
	}

	if (interface_hash) {
		g_hash_table_destroy(interface_hash);
		interface_hash = NULL;
	}

	if (resolved_proxy) {
		g_dbus_proxy_unref(resolved_proxy);
		resolved_proxy = NULL;
	}

	if (client) {
		g_dbus_client_unref(client);
		client = NULL;
	}

	if (connection) {
		dbus_connection_unref(connection);
		connection = NULL;
	}
}
