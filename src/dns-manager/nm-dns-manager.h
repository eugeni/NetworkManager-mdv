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
 * Copyright (C) 2004 - 2005 Colin Walters <walters@redhat.com>
 * Copyright (C) 2004 - 2010 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 *   and others
 */

#ifndef NM_DNS_MANAGER_H
#define NM_DNS_MANAGER_H

#include "config.h"
#include <glib-object.h>
#include <dbus/dbus.h>
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"

typedef enum {
	NM_DNS_MANAGER_ERROR_SYSTEM,
	NM_DNS_MANAGER_ERROR_INVALID_NAMESERVER,
	NM_DNS_MANAGER_ERROR_INVALID_HOST,
	NM_DNS_MANAGER_ERROR_INVALID_ID
} NMDnsManagerError;

typedef enum {
	NM_DNS_IP_CONFIG_TYPE_DEFAULT = 0,
	NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE,
	NM_DNS_IP_CONFIG_TYPE_VPN
} NMDnsIPConfigType;

#define NM_DNS_MANAGER_ERROR nm_dns_manager_error_quark ()
GQuark nm_dns_manager_error_quark (void);

G_BEGIN_DECLS

#define NM_TYPE_DNS_MANAGER (nm_dns_manager_get_type ())
#define NM_DNS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_DNS_MANAGER, NMDnsManager))
#define NM_DNS_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_CAST((k), NM_TYPE_DNS_MANAGER, NMDnsManagerClass))
#define NM_IS_DNS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_DNS_MANAGER))
#define NM_IS_DNS_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NM_TYPE_DNS_MANAGER))
#define NM_DNS_MANAGER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NM_TYPE_DNS_MANAGER, NMDnsManagerClass)) 

typedef struct NMDnsManagerPrivate NMDnsManagerPrivate;

typedef struct {
	GObject parent;
} NMDnsManager;

typedef struct {
	GObjectClass parent;
} NMDnsManagerClass;

GType nm_dns_manager_get_type (void);

NMDnsManager * nm_dns_manager_get (const char **plugins);

gboolean nm_dns_manager_add_ip4_config (NMDnsManager *mgr,
                                        const char *iface,
                                        NMIP4Config *config,
                                        NMDnsIPConfigType cfg_type);

gboolean nm_dns_manager_remove_ip4_config (NMDnsManager *mgr,
                                           const char *iface,
                                           NMIP4Config *config);

gboolean nm_dns_manager_add_ip6_config (NMDnsManager *mgr,
                                        const char *iface,
                                        NMIP6Config *config,
                                        NMDnsIPConfigType cfg_type);

gboolean nm_dns_manager_remove_ip6_config (NMDnsManager *mgr,
                                           const char *iface,
                                           NMIP6Config *config);

void nm_dns_manager_set_hostname (NMDnsManager *mgr,
                                  const char *hostname);

G_END_DECLS

#endif /* NM_DNS_MANAGER_H */
