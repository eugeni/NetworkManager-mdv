/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Bastien Nocera <hadess@hadess.net>
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2007 - 2009 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <ctype.h>
#include <net/ethernet.h>

#include "nm-param-spec-specialized.h"
#include "nm-dbus-glib-types.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-cdma.h"
#include "nm-setting-gsm.h"

GQuark
nm_setting_bluetooth_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-bluetooth-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_bluetooth_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			ENUM_ENTRY (NM_SETTING_BLUETOOTH_ERROR_UNKNOWN, "UnknownError"),
			ENUM_ENTRY (NM_SETTING_BLUETOOTH_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			ENUM_ENTRY (NM_SETTING_BLUETOOTH_ERROR_MISSING_PROPERTY, "MissingProperty"),
			ENUM_ENTRY (NM_SETTING_BLUETOOTH_ERROR_TYPE_SETTING_NOT_FOUND, "TypeSettingNotFound"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingBluetoothError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingBluetooth, nm_setting_bluetooth, NM_TYPE_SETTING)

#define NM_SETTING_BLUETOOTH_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_BLUETOOTH, NMSettingBluetoothPrivate))

typedef struct {
	GByteArray *bdaddr;
	char *type;
} NMSettingBluetoothPrivate;

enum {
	PROP_0,
	PROP_BDADDR,
	PROP_TYPE,

	LAST_PROP
};

NMSetting *nm_setting_bluetooth_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_BLUETOOTH, NULL);
}

const char *
nm_setting_bluetooth_get_connection_type (NMSettingBluetooth *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BLUETOOTH (setting), 0);

	return NM_SETTING_BLUETOOTH_GET_PRIVATE (setting)->type;
}

const GByteArray *
nm_setting_bluetooth_get_bdaddr (NMSettingBluetooth *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BLUETOOTH (setting), NULL);

	return NM_SETTING_BLUETOOTH_GET_PRIVATE (setting)->bdaddr;
}

static gint
find_setting_by_name (gconstpointer a, gconstpointer b)
{
	NMSetting *setting = NM_SETTING (a);
	const char *str = (const char *) b;

	return strcmp (nm_setting_get_name (setting), str);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingBluetoothPrivate *priv = NM_SETTING_BLUETOOTH_GET_PRIVATE (setting);

	if (!priv->bdaddr) {
		g_set_error (error,
		             NM_SETTING_BLUETOOTH_ERROR,
		             NM_SETTING_BLUETOOTH_ERROR_MISSING_PROPERTY,
		             NM_SETTING_BLUETOOTH_BDADDR);
		return FALSE;
	}

	if (priv->bdaddr && priv->bdaddr->len != ETH_ALEN) {
		g_set_error (error,
		             NM_SETTING_BLUETOOTH_ERROR,
		             NM_SETTING_BLUETOOTH_ERROR_INVALID_PROPERTY,
		             NM_SETTING_BLUETOOTH_BDADDR);
		return FALSE;
	}

	if (!priv->type) {
		g_set_error (error,
		             NM_SETTING_BLUETOOTH_ERROR,
		             NM_SETTING_BLUETOOTH_ERROR_MISSING_PROPERTY,
		             NM_SETTING_BLUETOOTH_TYPE);
		return FALSE;
	} else if (!g_str_equal (priv->type, NM_SETTING_BLUETOOTH_TYPE_DUN) &&
		   !g_str_equal (priv->type, NM_SETTING_BLUETOOTH_TYPE_PANU)) {
		g_set_error (error,
		             NM_SETTING_BLUETOOTH_ERROR,
		             NM_SETTING_BLUETOOTH_ERROR_INVALID_PROPERTY,
		             NM_SETTING_BLUETOOTH_TYPE);
		return FALSE;
	}

	/* Make sure the corresponding 'type' setting is present */
	if (   all_settings
	    && !strcmp (priv->type, NM_SETTING_BLUETOOTH_TYPE_DUN)) {
		gboolean gsm = FALSE, cdma = FALSE;

		gsm = !!g_slist_find_custom (all_settings,
		                             (gpointer) NM_SETTING_GSM_SETTING_NAME,
		                             find_setting_by_name);
		cdma = !!g_slist_find_custom (all_settings,
		                              (gpointer) NM_SETTING_CDMA_SETTING_NAME,
		                              find_setting_by_name);

		if (!gsm && !cdma) {
			g_set_error (error,
			             NM_SETTING_BLUETOOTH_ERROR,
			             NM_SETTING_BLUETOOTH_ERROR_TYPE_SETTING_NOT_FOUND,
			             NM_SETTING_BLUETOOTH_TYPE);
			return FALSE;
		}
	}
	/* PANU doesn't need a 'type' setting since no further configuration
	 * is required at the interface level.
	 */

	return TRUE;
}

static void
nm_setting_bluetooth_init (NMSettingBluetooth *setting)
{
	g_object_set (setting, NM_SETTING_NAME, NM_SETTING_BLUETOOTH_SETTING_NAME, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingBluetoothPrivate *priv = NM_SETTING_BLUETOOTH_GET_PRIVATE (object);

	if (priv->bdaddr)
		g_byte_array_free (priv->bdaddr, TRUE);

	G_OBJECT_CLASS (nm_setting_bluetooth_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingBluetoothPrivate *priv = NM_SETTING_BLUETOOTH_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_BDADDR:
		if (priv->bdaddr)
			g_byte_array_free (priv->bdaddr, TRUE);
		priv->bdaddr = g_value_dup_boxed (value);
		break;
	case PROP_TYPE:
		g_free (priv->type);
		priv->type = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMSettingBluetooth *setting = NM_SETTING_BLUETOOTH (object);

	switch (prop_id) {
	case PROP_BDADDR:
		g_value_set_boxed (value, nm_setting_bluetooth_get_bdaddr (setting));
		break;
	case PROP_TYPE:
		g_value_set_string (value, nm_setting_bluetooth_get_connection_type (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_bluetooth_class_init (NMSettingBluetoothClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingBluetoothPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */

	/**
	 * NMSettingBluetooth:bdaddr:
	 *
	 * The Bluetooth address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_BDADDR,
		 _nm_param_spec_specialized (NM_SETTING_BLUETOOTH_BDADDR,
		                             "Bluetooth address",
		                             "The Bluetooth address of the device",
		                             DBUS_TYPE_G_UCHAR_ARRAY,
		                             G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingBluetooth:type:
	 *
	 * Either 'dun' for Dial-Up Networking connections (not yet supported) or
	 * 'panu' for Personal Area Networking connections.
	 **/
	g_object_class_install_property
		(object_class, PROP_TYPE,
		 g_param_spec_string (NM_SETTING_BLUETOOTH_TYPE,
						  "Connection type",
						  "Either '" NM_SETTING_BLUETOOTH_TYPE_DUN "' for "
						  "Dial-Up Networking connections or "
						  "'" NM_SETTING_BLUETOOTH_TYPE_PANU "' for "
						  "Personal Area Networking connections.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));
}
