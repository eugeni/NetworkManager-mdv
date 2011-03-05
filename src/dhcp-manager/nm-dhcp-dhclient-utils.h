/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifndef NM_DHCP_DHCLIENT_UTILS_H
#define NM_DHCP_DHCLIENT_UTILS_H

#include <glib.h>
#include <glib-object.h>

#include <nm-setting-ip4-config.h>

char *nm_dhcp_dhclient_create_config (const char *interface,
                                      NMSettingIP4Config *s_ip4,
                                      guint8 *anycast_addr,
                                      const char *hostname,
                                      const char *orig_path,
                                      const char *orig_contents);

#endif /* NM_DHCP_DHCLIENT_UTILS_H */

