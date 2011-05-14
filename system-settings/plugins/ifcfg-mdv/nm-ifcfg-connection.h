/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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

#ifndef NM_IFCFG_CONNECTION_H
#define NM_IFCFG_CONNECTION_H

G_BEGIN_DECLS

#include <NetworkManager.h>
#include <nm-sysconfig-connection.h>

#define NM_TYPE_IFCFG_CONNECTION            (nm_ifcfg_connection_get_type ())
#define NM_IFCFG_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IFCFG_CONNECTION, NMIfcfgConnection))
#define NM_IFCFG_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_IFCFG_CONNECTION, NMIfcfgConnectionClass))
#define NM_IS_IFCFG_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_IFCFG_CONNECTION))
#define NM_IS_IFCFG_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_IFCFG_CONNECTION))
#define NM_IFCFG_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_IFCFG_CONNECTION, NMIfcfgConnectionClass))

#define NM_IFCFG_CONNECTION_FILENAME  "filename"
#define NM_IFCFG_CONNECTION_UNMANAGED "unmanaged"
#define NM_IFCFG_CONNECTION_UDI       "udi"

typedef struct {
	NMSysconfigConnection parent;
} NMIfcfgConnection;

typedef struct {
	NMSysconfigConnectionClass parent;
} NMIfcfgConnectionClass;

GType nm_ifcfg_connection_get_type (void);

NMIfcfgConnection *nm_ifcfg_connection_new (const char *filename,
                                            GError **error,
                                            gboolean *ignore_error);

const char *nm_ifcfg_connection_get_filename (NMIfcfgConnection *self);

const char *nm_ifcfg_connection_get_unmanaged_spec (NMIfcfgConnection *self);

gboolean nm_ifcfg_connection_update (NMIfcfgConnection *self,
                                     GHashTable *new_settings,
                                     GError **error);

G_END_DECLS

#endif /* NM_IFCFG_CONNECTION_H */
