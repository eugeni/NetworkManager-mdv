/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Mu Qiao <qiaomuf@gmail.com>
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
 * Copyright (C) 1999-2010 Gentoo Foundation, Inc.
 */

#ifndef _NET_PARSER_H
#define _NET_PARSER_H

#include <glib.h>

#define CONF_NET_FILE "/etc/conf.d/net"
#define IFNET_SYSTEM_SETTINGS_KEY_FILE "/etc/NetworkManager/nm-system-settings.conf"
#define IFNET_KEY_FILE_GROUP "ifnet"

gboolean ifnet_init (gchar * config_file);
void ifnet_destroy (void);

/* Reader functions */
GList *ifnet_get_connection_names (void);
gchar *ifnet_get_data (gchar * conn_name, const gchar * key);
gchar *ifnet_get_global_data (const gchar * key);
gchar *ifnet_get_global_setting (gchar * group, gchar * key);
gboolean ifnet_has_connection (gchar * conn_name);

/* Writer functions */
gboolean ifnet_flush_to_file (gchar * config_file);
void ifnet_set_data (gchar * conn_name, gchar * key, gchar * value);
gboolean ifnet_add_connection (gchar * name, gchar * type);
gboolean ifnet_delete_network (gchar * conn_name);
#endif
