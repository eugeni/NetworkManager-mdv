/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef NM_DHCP6_CONFIG_H
#define NM_DHCP6_CONFIG_H

#include <glib.h>
#include <glib-object.h>

#define NM_TYPE_DHCP6_CONFIG            (nm_dhcp6_config_get_type ())
#define NM_DHCP6_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP6_CONFIG, NMDHCP6Config))
#define NM_DHCP6_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP6_CONFIG, NMDHCP6ConfigClass))
#define NM_IS_DHCP6_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP6_CONFIG))
#define NM_IS_DHCP6_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DHCP6_CONFIG))
#define NM_DHCP6_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP6_CONFIG, NMDHCP6ConfigClass))

typedef struct {
	GObject parent;
} NMDHCP6Config;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*properties_changed) (NMDHCP6Config *config, GHashTable *properties);
} NMDHCP6ConfigClass;

#define NM_DHCP6_CONFIG_OPTIONS "options"

GType nm_dhcp6_config_get_type (void);

NMDHCP6Config *nm_dhcp6_config_new (void);

const char *nm_dhcp6_config_get_dbus_path (NMDHCP6Config *config);

void nm_dhcp6_config_add_option (NMDHCP6Config *config,
                                 const char *key,
                                 const char *option);

void nm_dhcp6_config_reset (NMDHCP6Config *config);

const char *nm_dhcp6_config_get_option (NMDHCP6Config *config, const char *option);

#endif /* NM_DHCP6_CONFIG_H */
