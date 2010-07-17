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
 * Copyright (C) 2004 - 2008 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef NM_ACCESS_POINT_H
#define NM_ACCESS_POINT_H

#include <glib.h>
#include <glib-object.h>
#include <time.h>
#include "NetworkManager.h"
#include "nm-connection.h"

#define NM_TYPE_AP            (nm_ap_get_type ())
#define NM_AP(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_AP, NMAccessPoint))
#define NM_AP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_AP, NMAccessPointClass))
#define NM_IS_AP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_AP))
#define NM_IS_AP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_AP))
#define NM_AP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_AP, NMAccessPointClass))

#define NM_AP_FLAGS "flags"
#define NM_AP_WPA_FLAGS "wpa-flags"
#define NM_AP_RSN_FLAGS "rsn-flags"
#define NM_AP_SSID "ssid"
#define NM_AP_FREQUENCY "frequency"
#define NM_AP_HW_ADDRESS "hw-address"
#define NM_AP_MODE "mode"
#define NM_AP_MAX_BITRATE "max-bitrate"
#define NM_AP_STRENGTH "strength"

typedef struct {
	GObject parent;
} NMAccessPoint;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*properties_changed) (NMAccessPoint *ap, GHashTable *properties);
} NMAccessPointClass;

GType nm_ap_get_type (void);

NMAccessPoint *	nm_ap_new				(void);
NMAccessPoint * nm_ap_new_from_properties (GHashTable *properties);
NMAccessPoint * nm_ap_new_fake_from_connection (NMConnection *connection);
void            nm_ap_export_to_dbus    (NMAccessPoint *ap);

const char *		nm_ap_get_dbus_path (NMAccessPoint *ap);
const GTimeVal *	nm_ap_get_timestamp				(const NMAccessPoint *ap);
void				nm_ap_set_timestamp				(NMAccessPoint *ap, glong sec, glong usec);
void				nm_ap_set_timestamp_via_timestamp	(NMAccessPoint *ap, const GTimeVal *timestamp);

const GByteArray *	nm_ap_get_ssid (const NMAccessPoint * ap);
void				nm_ap_set_ssid (NMAccessPoint * ap, const GByteArray * ssid);

guint32			nm_ap_get_flags	(NMAccessPoint *ap);
void				nm_ap_set_flags	(NMAccessPoint *ap, guint32 flags);

guint32			nm_ap_get_wpa_flags	(NMAccessPoint *ap);
void				nm_ap_set_wpa_flags	(NMAccessPoint *ap, guint32 flags);

guint32			nm_ap_get_rsn_flags	(NMAccessPoint *ap);
void				nm_ap_set_rsn_flags	(NMAccessPoint *ap, guint32 flags);

const struct ether_addr * nm_ap_get_address	(const NMAccessPoint *ap);
void				nm_ap_set_address		(NMAccessPoint *ap, const struct ether_addr *addr);

NM80211Mode			nm_ap_get_mode			(NMAccessPoint *ap);
void				nm_ap_set_mode			(NMAccessPoint *ap, const NM80211Mode mode);

gint8			nm_ap_get_strength		(NMAccessPoint *ap);
void				nm_ap_set_strength		(NMAccessPoint *ap, gint8 strength);

guint32			nm_ap_get_freq			(NMAccessPoint *ap);
void				nm_ap_set_freq			(NMAccessPoint *ap, guint32 freq);

guint32			nm_ap_get_max_bitrate			(NMAccessPoint *ap);
void				nm_ap_set_max_bitrate		(NMAccessPoint *ap, guint32 bitrate);

gboolean			nm_ap_get_fake	(const NMAccessPoint *ap);
void				nm_ap_set_fake	(NMAccessPoint *ap, gboolean fake);

gboolean			nm_ap_get_broadcast		(NMAccessPoint *ap);
void				nm_ap_set_broadcast		(NMAccessPoint *ap, gboolean broadcast);

glong			nm_ap_get_last_seen		(const NMAccessPoint *ap);
void				nm_ap_set_last_seen		(NMAccessPoint *ap, const glong last_seen);

gboolean			nm_ap_get_user_created	(const NMAccessPoint *ap);
void				nm_ap_set_user_created	(NMAccessPoint *ap, gboolean user_created);

GSList *			nm_ap_get_user_addresses	(const NMAccessPoint *ap);
void				nm_ap_set_user_addresses (NMAccessPoint *ap, GSList *list);

guint32				nm_ap_add_security_from_ie (guint32 flags,
                                                const guint8 *wpa_ie,
                                                guint32 length);

gboolean			nm_ap_check_compatible (NMAccessPoint *self,
                                            NMConnection *connection);

NMAccessPoint *     nm_ap_match_in_list (NMAccessPoint *find_ap,
                                         GSList *ap_list,
                                         gboolean strict_match);

void				nm_ap_print_self (NMAccessPoint *ap, const char * prefix);

guint32 freq_to_channel (guint32 freq);
guint32 channel_to_freq (guint32 channel, const char *band);

#endif /* NM_ACCESS_POINT_H */
