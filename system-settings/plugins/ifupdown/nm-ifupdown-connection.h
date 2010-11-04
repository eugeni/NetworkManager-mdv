/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

/* NetworkManager system settings service (ifupdown)
 *
 * Alexander Sack <asac@ubuntu.com>
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
 * (C) Copyright 2008 Canonical Ltd.
 */

#ifndef NM_IFUPDOWN_CONNECTION_H
#define NM_IFUPDOWN_CONNECTION_H

#include <nm-sysconfig-connection.h>
#include "interface_parser.h"

G_BEGIN_DECLS

#define NM_TYPE_IFUPDOWN_CONNECTION            (nm_ifupdown_connection_get_type ())
#define NM_IFUPDOWN_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IFUPDOWN_CONNECTION, NMIfupdownConnection))
#define NM_IFUPDOWN_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_IFUPDOWN_CONNECTION, NMIfupdownConnectionClass))
#define NM_IS_IFUPDOWN_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_IFUPDOWN_CONNECTION))
#define NM_IS_IFUPDOWN_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_IFUPDOWN_CONNECTION))
#define NM_IFUPDOWN_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_IFUPDOWN_CONNECTION, NMIfupdownConnectionClass))

#define NM_IFUPDOWN_CONNECTION_IFBLOCK "ifblock"

typedef struct {
	NMSysconfigConnection parent;
} NMIfupdownConnection;

typedef struct {
	NMSysconfigConnectionClass parent;
} NMIfupdownConnectionClass;

GType nm_ifupdown_connection_get_type (void);

NMIfupdownConnection *nm_ifupdown_connection_new (if_block *block);

G_END_DECLS

#endif /* NM_IFUPDOWN_CONNECTION_H */
