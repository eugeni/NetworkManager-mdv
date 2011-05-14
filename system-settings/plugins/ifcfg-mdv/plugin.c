/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
 *
 * Dan Williams <dcbw@redhat.com>
 * Søren Sandmann <sandmann@daimi.au.dk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#include <config.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#include <gmodule.h>
#include <glib-object.h>
#include <glib/gi18n.h>
#include <gio/gio.h>

#include <dbus/dbus-glib.h>

#include <nm-setting-connection.h>

#include "common.h"
#include "nm-dbus-glib-types.h"
#include "plugin.h"
#include "nm-system-config-interface.h"
#include "nm-ifcfg-connection.h"
#include "nm-inotify-helper.h"
#include "shvar.h"
#include "writer.h"
#include "utils.h"
#include "utils-mdv.h"

static void system_config_interface_init (NMSystemConfigInterface *system_config_interface_class);

static void connection_changed_handler (SCPluginIfcfg *plugin,
                                        const char *path,
                                        NMIfcfgConnection *connection,
                                        gboolean *do_remove,
                                        gboolean *do_new);

static void handle_connection_remove_or_new (SCPluginIfcfg *plugin,
                                             const char *path,
                                             NMIfcfgConnection *connection,
                                             gboolean do_remove,
                                             gboolean do_new);

G_DEFINE_TYPE_EXTENDED (SCPluginIfcfg, sc_plugin_ifcfg, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE,
											   system_config_interface_init))

#define SC_PLUGIN_IFCFG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_IFCFG, SCPluginIfcfgPrivate))


typedef struct {
	GHashTable *connections;

	gulong ih_event_id;
	int sc_network_wd;
	char *hostname;

	GFileMonitor *ifcfg_monitor;
	guint ifcfg_monitor_id;

	GFileMonitor *wireless_d_monitor;
	guint wireless_d_monitor_id;
} SCPluginIfcfgPrivate;


static void
connection_unmanaged_changed (NMIfcfgConnection *connection,
                              GParamSpec *pspec,
                              gpointer user_data)
{
	g_signal_emit_by_name (SC_PLUGIN_IFCFG (user_data), NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
}

static void
connection_ifcfg_changed (NMIfcfgConnection *connection, gpointer user_data)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (user_data);
	gboolean do_remove = FALSE, do_new = FALSE;
	const char *path;

	path = nm_ifcfg_connection_get_filename (connection);
	g_return_if_fail (path != NULL);

	connection_changed_handler (plugin, path, connection, &do_remove, &do_new);
	handle_connection_remove_or_new (plugin, path, connection, do_remove, do_new);
}

static NMIfcfgConnection *
read_one_connection (SCPluginIfcfg *plugin, const char *filename)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	NMIfcfgConnection *connection;
	GError *error = NULL;
	gboolean ignore_error = FALSE;

	PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "parsing %s ... ", filename);

	connection = nm_ifcfg_connection_new (filename, &error, &ignore_error);
	if (connection) {
		NMSettingConnection *s_con;
		const char *cid;

		s_con = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (connection), NM_TYPE_SETTING_CONNECTION);
		g_assert (s_con);

		cid = nm_setting_connection_get_id (s_con);
		g_assert (cid);

		g_hash_table_insert (priv->connections,
		                     (gpointer) nm_ifcfg_connection_get_filename (connection),
		                     g_object_ref (connection));
		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    read connection '%s'", cid);

		if (nm_ifcfg_connection_get_unmanaged_spec (connection)) {
			PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "Ignoring connection '%s' and its "
			              "device because NM_CONTROLLED was not true or ONBOOT was set.", cid);
			g_signal_emit_by_name (plugin, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
		} else {
			/* Wait for the connection to become unmanaged once it knows the
			 * UDI of it's device, if/when the device gets plugged in.
			 */
			g_signal_connect (G_OBJECT (connection), "notify::unmanaged",
			                  G_CALLBACK (connection_unmanaged_changed), plugin);
		}

		/* watch changes of ifcfg hardlinks */
		g_signal_connect (G_OBJECT (connection), "ifcfg-changed",
		                  G_CALLBACK (connection_ifcfg_changed), plugin);
	} else {
		if (!ignore_error) {
			PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "    error: %s",
			              (error && error->message) ? error->message : "(unknown)");
		}
		g_error_free (error);
	}

	return connection;
}

static void
read_connections (SCPluginIfcfg *plugin)
{
	static const gchar *dirs[] = { IFCFG_DIR, IFCFG_WIRELESS_D_DIR, NULL };
	const gchar **current;

	for (current = dirs; current && *current; current++) {
		GError *err = NULL;
		GDir *dir = g_dir_open (*current, 0, &err);

		if (dir) {
			const char *item;

			while ((item = g_dir_read_name (dir))) {
				char *full_path = g_build_filename (*current, item, NULL);

				if (mdv_should_ignore_file (full_path)) {
					g_free(full_path);
					continue;
				}

				read_one_connection (plugin, full_path);
				g_free (full_path);
			}

			g_dir_close (dir);
		} else {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Can not read directory '%s': %s", *current, err->message);
			g_error_free (err);
		}
	}
}

/* Monitoring */

static void
connection_changed_handler (SCPluginIfcfg *plugin,
                            const char *path,
                            NMIfcfgConnection *connection,
                            gboolean *do_remove,
                            gboolean *do_new)
{
	NMIfcfgConnection *new;
	GError *error = NULL;
	gboolean ignore_error = FALSE;
	const char *new_unmanaged = NULL, *old_unmanaged = NULL;

	g_return_if_fail (plugin != NULL);
	g_return_if_fail (path != NULL);
	g_return_if_fail (connection != NULL);
	g_return_if_fail (do_remove != NULL);
	g_return_if_fail (do_new != NULL);

	PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "updating %s", path);

	new = (NMIfcfgConnection *) nm_ifcfg_connection_new (path, &error, &ignore_error);
	if (!new) {
		/* errors reading connection; remove it */
		if (!ignore_error) {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    error: %s",
			             (error && error->message) ? error->message : "(unknown)");
		}
		g_clear_error (&error);

		PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "removed %s.", path);
		*do_remove = TRUE;
		return;
	}

	/* Successfully read connection changes */

	old_unmanaged = nm_ifcfg_connection_get_unmanaged_spec (NM_IFCFG_CONNECTION (connection));
	new_unmanaged = nm_ifcfg_connection_get_unmanaged_spec (NM_IFCFG_CONNECTION (new));

	if (new_unmanaged) {
		if (!old_unmanaged) {
			/* Unexport the connection by destroying it, then re-creating it as unmanaged */
			*do_remove = *do_new = TRUE;
		}
	} else {
		if (old_unmanaged) {  /* now managed */
			NMSettingConnection *s_con;
			const char *cid;

			s_con = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (new), NM_TYPE_SETTING_CONNECTION);
			g_assert (s_con);

			cid = nm_setting_connection_get_id (s_con);
			g_assert (cid);

			PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "Managing connection '%s' and its "
			              "device because NM_CONTROLLED was true.", cid);
			g_signal_emit_by_name (plugin, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, connection);
		}

		if (!nm_sysconfig_connection_update (NM_SYSCONFIG_CONNECTION (connection),
		                                     NM_CONNECTION (new),
		                                     TRUE,
		                                     &error)) {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    error updating: %s",
			             (error && error->message) ? error->message : "(unknown)");
			g_clear_error (&error);
		}

		/* Update unmanaged status */
		g_object_set (connection, "unmanaged", new_unmanaged, NULL);
		g_signal_emit_by_name (plugin, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
	}
	g_object_unref (new);
}

static void
handle_connection_remove_or_new (SCPluginIfcfg *plugin,
                                 const char *path,
                                 NMIfcfgConnection *connection,
                                 gboolean do_remove,
                                 gboolean do_new)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);

	g_return_if_fail (plugin != NULL);
	g_return_if_fail (path != NULL);

	if (do_remove) {
		const char *unmanaged;

		g_return_if_fail (connection != NULL);

		unmanaged = nm_ifcfg_connection_get_unmanaged_spec (connection);
		g_hash_table_remove (priv->connections, path);
		g_signal_emit_by_name (connection, "removed");

		/* Emit unmanaged changes _after_ removing the connection */
		if (unmanaged)
			g_signal_emit_by_name (plugin, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
	}

	if (do_new) {
		connection = read_one_connection (plugin, path);
		if (connection) {
			if (!nm_ifcfg_connection_get_unmanaged_spec (connection))
				g_signal_emit_by_name (plugin, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, connection);
		}
	}
}
static void
dir_changed (GFileMonitor *monitor,
		   GFile *file,
		   GFile *other_file,
		   GFileMonitorEvent event_type,
		   gpointer user_data)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (user_data);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	char *path;
	NMIfcfgConnection *connection;
	gboolean do_remove = FALSE, do_new = FALSE;

	path = g_file_get_path (file);
	if (mdv_should_ignore_file (path)) {
		g_free (path);
		return;
	}

	connection = g_hash_table_lookup (priv->connections, path);
	if (!connection) {
		do_new = TRUE;
	} else {
		switch (event_type) {
		case G_FILE_MONITOR_EVENT_DELETED:
			PLUGIN_PRINT (IFCFG_PLUGIN_NAME, "removed %s.", path);
			do_remove = TRUE;
			break;
		case G_FILE_MONITOR_EVENT_CREATED:
		case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
			/* Update */
			connection_changed_handler (plugin, path, connection, &do_remove, &do_new);
			break;
		default:
			break;
		}
	}

	handle_connection_remove_or_new (plugin, path, connection, do_remove, do_new);

	g_free (path);
}

static void
setup_ifcfg_monitoring (SCPluginIfcfg *plugin)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GFile *file;
	GFileMonitor *monitor;

	priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);

	file = g_file_new_for_path (IFCFG_DIR "/");
	monitor = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);

	if (monitor) {
		priv->ifcfg_monitor_id = g_signal_connect (monitor, "changed", G_CALLBACK (dir_changed), plugin);
		priv->ifcfg_monitor = monitor;
	}

	file = g_file_new_for_path (IFCFG_WIRELESS_D_DIR "/");
	monitor = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);

	if (monitor) {
		priv->wireless_d_monitor_id = g_signal_connect (monitor, "changed", G_CALLBACK (dir_changed), plugin);
		priv->wireless_d_monitor = monitor;
	}
}

static GSList *
get_connections (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GSList *list = NULL;
	GHashTableIter iter;
	gpointer value;

	if (!priv->connections) {
		setup_ifcfg_monitoring (plugin);
		read_connections (plugin);
	}

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		NMIfcfgConnection *exported = NM_IFCFG_CONNECTION (value);

		if (!nm_ifcfg_connection_get_unmanaged_spec (exported))
			list = g_slist_prepend (list, value);
	}

	return list;
}

static void
check_unmanaged (gpointer key, gpointer data, gpointer user_data)
{
	GSList **list = (GSList **) user_data;
	NMIfcfgConnection *connection = NM_IFCFG_CONNECTION (data);
	const char *unmanaged_spec;
	GSList *iter;

	unmanaged_spec = nm_ifcfg_connection_get_unmanaged_spec (connection);
	if (!unmanaged_spec)
		return;

	/* Just return if the unmanaged spec is already in the list */
	for (iter = *list; iter; iter = g_slist_next (iter)) {
		if (!strcmp ((char *) iter->data, unmanaged_spec))
			return;
	}

	*list = g_slist_prepend (*list, g_strdup (unmanaged_spec));
}

static GSList *
get_unmanaged_specs (NMSystemConfigInterface *config)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (config);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (config);
	GSList *list = NULL;

	if (!priv->connections) {
		setup_ifcfg_monitoring (plugin);
		read_connections (plugin);
	}

	g_hash_table_foreach (priv->connections, check_unmanaged, &list);
	return list;
}

static gboolean
add_connection (NMSystemConfigInterface *config,
                NMConnection *connection,
                GError **error)
{
	return writer_new_connection (connection, IFCFG_DIR, NULL, error);
}

#define SC_NETWORK_FILE SYSCONFDIR"/sysconfig/network"

static char *
plugin_get_hostname (SCPluginIfcfg *plugin)
{
	shvarFile *network;
	char *hostname;
	gboolean ignore_localhost;

	network = svNewFile (SC_NETWORK_FILE);
	if (!network) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Could not get hostname: failed to read " SC_NETWORK_FILE);
		return FALSE;
	}

	hostname = svGetValue (network, "HOSTNAME", FALSE);
	ignore_localhost = svTrueValue (network, "NM_IGNORE_HOSTNAME_LOCALHOST", FALSE);
	if (ignore_localhost) {
		/* Ignore a hostname of 'localhost' or 'localhost.localdomain' to preserve
		 * 'network' service behavior.
		 */
		if (hostname && (!strcmp (hostname, "localhost") || !strcmp (hostname, "localhost.localdomain"))) {
			g_free (hostname);
			hostname = NULL;
		}
	}

	svCloseFile (network);
	return hostname;
}

static gboolean
plugin_set_hostname (SCPluginIfcfg *plugin, const char *hostname)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	shvarFile *network;

	network = svCreateFile (SC_NETWORK_FILE);
	if (!network) {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "Could not save hostname: failed to create/open " SC_NETWORK_FILE);
		return FALSE;
	}

	svSetValue (network, "HOSTNAME", hostname, FALSE);
	svWriteFile (network, 0644);
	svCloseFile (network);

	g_free (priv->hostname);
	priv->hostname = hostname ? g_strdup (hostname) : NULL;
	return TRUE;
}

static void
sc_network_changed_cb (NMInotifyHelper *ih,
                       struct inotify_event *evt,
                       const char *path,
                       gpointer user_data)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (user_data);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	char *new_hostname;

	if (evt->wd != priv->sc_network_wd)
		return;

	new_hostname = plugin_get_hostname (plugin);
	if (   (new_hostname && !priv->hostname)
	    || (!new_hostname && priv->hostname)
	    || (priv->hostname && new_hostname && strcmp (priv->hostname, new_hostname))) {
		g_free (priv->hostname);
		priv->hostname = new_hostname;
		g_object_notify (G_OBJECT (plugin), NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
	} else
		g_free (new_hostname);
}

static void
init (NMSystemConfigInterface *config)
{
}

static void
sc_plugin_ifcfg_init (SCPluginIfcfg *plugin)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	NMInotifyHelper *ih;

	ih = nm_inotify_helper_get ();
	priv->ih_event_id = g_signal_connect (ih, "event", G_CALLBACK (sc_network_changed_cb), plugin);
	priv->sc_network_wd = nm_inotify_helper_add_watch (ih, SC_NETWORK_FILE);

	priv->hostname = plugin_get_hostname (plugin);
}

static void
dispose (GObject *object)
{
	SCPluginIfcfg *plugin = SC_PLUGIN_IFCFG (object);
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	NMInotifyHelper *ih;

	ih = nm_inotify_helper_get ();

	g_signal_handler_disconnect (ih, priv->ih_event_id);

	if (priv->sc_network_wd >= 0)
		nm_inotify_helper_remove_watch (ih, priv->sc_network_wd);

	g_free (priv->hostname);

	if (priv->connections)
		g_hash_table_destroy (priv->connections);

	if (priv->ifcfg_monitor) {
		if (priv->ifcfg_monitor_id)
			g_signal_handler_disconnect (priv->ifcfg_monitor, priv->ifcfg_monitor_id);

		g_file_monitor_cancel (priv->ifcfg_monitor);
		g_object_unref (priv->ifcfg_monitor);
	}

	if (priv->wireless_d_monitor) {
		if (priv->wireless_d_monitor_id)
			g_signal_handler_disconnect (priv->wireless_d_monitor, priv->wireless_d_monitor_id);

		g_file_monitor_cancel (priv->wireless_d_monitor);
		g_object_unref (priv->wireless_d_monitor);
	}

	G_OBJECT_CLASS (sc_plugin_ifcfg_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	G_OBJECT_CLASS (sc_plugin_ifcfg_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (object);

	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME:
		g_value_set_string (value, IFCFG_PLUGIN_NAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO:
		g_value_set_string (value, IFCFG_PLUGIN_INFO);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES:
		g_value_set_uint (value, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS | NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		g_value_set_string (value, priv->hostname);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	const char *hostname;

	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		hostname = g_value_get_string (value);
		if (hostname && strlen (hostname) < 1)
			hostname = NULL;
		plugin_set_hostname (SC_PLUGIN_IFCFG (object), hostname);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
sc_plugin_ifcfg_class_init (SCPluginIfcfgClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (SCPluginIfcfgPrivate));

	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME,
	                                  NM_SYSTEM_CONFIG_INTERFACE_NAME);

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO,
	                                  NM_SYSTEM_CONFIG_INTERFACE_INFO);

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES,
	                                  NM_SYSTEM_CONFIG_INTERFACE_CAPABILITIES);

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME,
	                                  NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
}

static void
system_config_interface_init (NMSystemConfigInterface *system_config_interface_class)
{
	/* interface implementation */
	system_config_interface_class->get_connections = get_connections;
	system_config_interface_class->add_connection = add_connection;
	system_config_interface_class->get_unmanaged_specs = get_unmanaged_specs;
	system_config_interface_class->init = init;
}

G_MODULE_EXPORT GObject *
nm_system_config_factory (void)
{
	static SCPluginIfcfg *singleton = NULL;

	if (!singleton)
		singleton = SC_PLUGIN_IFCFG (g_object_new (SC_TYPE_PLUGIN_IFCFG, NULL));
	else
		g_object_ref (singleton);

	return G_OBJECT (singleton);
}
