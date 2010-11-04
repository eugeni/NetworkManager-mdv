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

#ifndef _CONNECTION_PARSER_H
#define _CONNECTION_PARSER_H
#include <nm-connection.h>
#include "net_parser.h"

NMConnection *ifnet_update_connection_from_config_block (gchar * conn_name,
							 GError ** error);

/* nm_conn_name is used to update nm_ifnet_connection's priv data */
gboolean ifnet_update_parsers_by_connection (NMConnection * connection,
					     gchar * conn_name,
					     gchar ** nm_conn_name,
					     gchar * config_file,
					     gchar * wpa_file, GError ** error);

gboolean ifnet_delete_connection_in_parsers (gchar * conn_name,
					     gchar * config_file,
					     gchar * wpa_file);
gboolean ifnet_add_new_connection (NMConnection * connection,
				   gchar * config_file, gchar * wpa_file,
				   GError ** error);
#endif
