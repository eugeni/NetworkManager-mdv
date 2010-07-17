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
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifndef NM_DEVICE_MODEM_H
#define NM_DEVICE_MODEM_H

#include <glib.h>
#include <glib-object.h>

#include "nm-device.h"
#include "nm-modem.h"

#define NM_TYPE_DEVICE_MODEM            (nm_device_modem_get_type ())
#define NM_DEVICE_MODEM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_MODEM, NMDeviceModem))
#define NM_DEVICE_MODEM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_MODEM, NMDeviceModemClass))
#define NM_IS_DEVICE_MODEM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_MODEM))
#define NM_IS_DEVICE_MODEM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DEVICE_MODEM))
#define NM_DEVICE_MODEM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_MODEM, NMDeviceModemClass))

#define NM_DEVICE_MODEM_MODEM "modem"

#define NM_DEVICE_MODEM_ENABLE_CHANGED "enable-changed"

typedef struct {
	NMDevice parent;
} NMDeviceModem;

typedef struct {
	NMDeviceClass parent;

	void (*ppp_stats) (NMDeviceModem *self, guint32 in_bytes, guint32 out_bytes);
} NMDeviceModemClass;

GType nm_device_modem_get_type (void);

/* Private for subclases */
NMModem *nm_device_modem_get_modem (NMDeviceModem *self);

#endif /* NM_DEVICE_MODEM_H */
