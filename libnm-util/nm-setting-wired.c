/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
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
 * (C) Copyright 2007 - 2010 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <ctype.h>
#include <net/ethernet.h>
#include <dbus/dbus-glib.h>

#include "nm-setting-wired.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-dbus-glib-types.h"

GQuark
nm_setting_wired_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-wired-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_wired_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_WIRED_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_WIRED_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_WIRED_ERROR_MISSING_PROPERTY, "MissingProperty"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingWiredError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingWired, nm_setting_wired, NM_TYPE_SETTING)

#define NM_SETTING_WIRED_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_WIRED, NMSettingWiredPrivate))

typedef struct {
	char *port;
	guint32 speed;
	char *duplex;
	gboolean auto_negotiate;
	GByteArray *device_mac_address;
	GByteArray *cloned_mac_address;
	guint32 mtu;
	GPtrArray *s390_subchannels;
	char *s390_nettype;
	GHashTable *s390_options;
} NMSettingWiredPrivate;

enum {
	PROP_0,
	PROP_PORT,
	PROP_SPEED,
	PROP_DUPLEX,
	PROP_AUTO_NEGOTIATE,
	PROP_MAC_ADDRESS,
	PROP_CLONED_MAC_ADDRESS,
	PROP_MTU,
	PROP_S390_SUBCHANNELS,
	PROP_S390_NETTYPE,
	PROP_S390_OPTIONS,

	LAST_PROP
};

static const char *valid_s390_opts[] = {
	"portno", "layer2", "portname", "protocol", "priority_queueing",
	"buffer_count", "isolation", "total", "inter", "inter_jumbo", "route4",
	"route6", "fake_broadcast", "broadcast_mode", "canonical_macaddr",
	"checksumming", "sniffer", "large_send", "ipato_enable", "ipato_invert4",
	"ipato_add4", "ipato_invert6", "ipato_add6", "vipa_add4", "vipa_add6",
	"rxip_add4", "rxip_add6", "lancmd_timeout",
	NULL
};

NMSetting *
nm_setting_wired_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_WIRED, NULL);
}

const char *
nm_setting_wired_get_port (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->port;
}

guint32
nm_setting_wired_get_speed (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), 0);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->speed;
}

const char *
nm_setting_wired_get_duplex (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->duplex;
}

gboolean
nm_setting_wired_get_auto_negotiate (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), FALSE);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->auto_negotiate;
}

const GByteArray *
nm_setting_wired_get_mac_address (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->device_mac_address;
}

const GByteArray *
nm_setting_wired_get_cloned_mac_address (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->cloned_mac_address;
}

guint32
nm_setting_wired_get_mtu (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), 0);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->mtu;
}

/**
 * nm_setting_wired_get_s390_subchannels:
 * @setting: the #NMSettingWired
 *
 * Return the list of s390 subchannels that identify the device that this
 * connection is applicable to.  The connection should only be used in
 * conjunction with that device.
 *
 * Returns: a #GPtrArray of strings, each specifying one subchannel the
 * s390 device uses to communicate to the host.
 **/
const GPtrArray *
nm_setting_wired_get_s390_subchannels (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_subchannels;
}

/**
 * nm_setting_wired_get_s390_nettype:
 * @setting: the #NMSettingWired
 *
 * Returns the s390 device type this connection should apply to.  Will be one
 * of 'qeth', 'lcs', or 'ctcm'.
 *
 * Returns: the s390 device type
 **/
const char *
nm_setting_wired_get_s390_nettype (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_nettype;
}

/**
 * nm_setting_wired_get_num_s390_options:
 * @setting: the #NMSettingWired
 *
 * Returns the number of s390-specific options that should be set for this
 * device when it is activated.  This can be used to retrieve each s390
 * option individually using nm_setting_wired_get_s390_option().
 *
 * Returns: the number of s390-specific device options
 **/
guint32
nm_setting_wired_get_num_s390_options (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), 0);

	return g_hash_table_size (NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_options);
}

/**
 * nm_setting_wired_get_s390_option:
 * @setting: the #NMSettingWired
 * @idx: index of the desired option, from 0 to
 * nm_setting_wired_get_num_s390_options() - 1
 * @out_key: on return, the key name of the s390 specific option; this value is
 * owned by the setting and should not be modified
 * @out_value: on return, the value of the key of the s390 specific option; this
 * value is owned by the setting and should not be modified
 *
 * Given an index, return the value of the s390 option at that index.  indexes
 * are *not* guaranteed to be static across modifications to options done by
 * nm_setting_wired_add_s390_option() and nm_setting_wired_remove_s390_option(),
 * and should not be used to refer to options except for short periods of time
 * such as during option iteration.
 *
 * Returns: %TRUE on success if the index was valid and an option was found,
 * %FALSE if the index was invalid (ie, greater than the number of options
 * currently held by the setting)
 **/
gboolean
nm_setting_wired_get_s390_option (NMSettingWired *setting,
                                  guint32 idx,
                                  const char **out_key,
                                  const char **out_value)
{
	NMSettingWiredPrivate *priv;
	guint32 num_keys;
	GList *keys;
	const char *_key = NULL, *_value = NULL;

	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), FALSE);

	priv = NM_SETTING_WIRED_GET_PRIVATE (setting);

	num_keys = nm_setting_wired_get_num_s390_options (setting);
	g_return_val_if_fail (idx < num_keys, FALSE);

	keys = g_hash_table_get_keys (priv->s390_options);
	_key = g_list_nth_data (keys, idx);
	_value = g_hash_table_lookup (priv->s390_options, _key);

	if (out_key)
		*out_key = _key;
	if (out_value)
		*out_value = _value;
	return TRUE;
}

/**
 * nm_setting_wired_get_s390_option_by_key:
 * @setting: the #NMSettingWired
 * @key: the key for which to retrieve the value
 *
 * Returns the value associated with the s390-specific option specified by
 * @key, if it exists.
 *
 * Returns: the value, or NULL if the key/value pair was never added to the
 * setting; the value is owned by the setting and must not be modified
 **/
const char *
nm_setting_wired_get_s390_option_by_key (NMSettingWired *setting,
                                         const char *key)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);
	g_return_val_if_fail (key != NULL, NULL);
	g_return_val_if_fail (strlen (key), NULL);

	return g_hash_table_lookup (NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_options, key);
}

/**
 * nm_setting_wired_add_s390_options:
 * @setting: the #NMSettingWired
 * @key: key name for the option
 * @value: value for the option
 *
 * Add an option to the table.  The option is compared to an internal list
 * of allowed options.  Key names may contain only alphanumeric characters
 * (ie [a-zA-Z0-9]).  Adding a new key replaces any existing key/value pair that
 * may already exist.
 *
 * Returns: %TRUE if the option was valid and was added to the internal option
 * list, %FALSE if it was not.
 **/
gboolean nm_setting_wired_add_s390_option (NMSettingWired *setting,
                                           const char *key,
                                           const char *value)
{
	size_t value_len;

	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (strlen (key), FALSE);
	g_return_val_if_fail (_nm_utils_string_in_list (key, valid_s390_opts), FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	value_len = strlen (value);
	g_return_val_if_fail (value_len > 0 && value_len < 200, FALSE);

	g_hash_table_insert (NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_options,
	                     g_strdup (key),
	                     g_strdup (value));
	return TRUE;
}

/**
 * nm_setting_wired_remove_s390_options:
 * @setting: the #NMSettingWired
 * @key: key name for the option to remove
 *
 * Remove the s390-specific option referenced by @key from the internal option
 * list.
 *
 * Returns: %TRUE if the option was found and removed from the internal option
 * list, %FALSE if it was not.
 **/
gboolean
nm_setting_wired_remove_s390_option (NMSettingWired *setting,
                                     const char *key)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (strlen (key), FALSE);

	return g_hash_table_remove (NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_options, key);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE (setting);
	const char *valid_ports[] = { "tp", "aui", "bnc", "mii", NULL };
	const char *valid_duplex[] = { "half", "full", NULL };
	const char *valid_nettype[] = { "qeth", "lcs", "ctcm", NULL };
	GHashTableIter iter;
	const char *key, *value;

	if (priv->port && !_nm_utils_string_in_list (priv->port, valid_ports)) {
		g_set_error (error,
		             NM_SETTING_WIRED_ERROR,
		             NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRED_PORT);
		return FALSE;
	}

	if (priv->duplex && !_nm_utils_string_in_list (priv->duplex, valid_duplex)) {
		g_set_error (error,
		             NM_SETTING_WIRED_ERROR,
		             NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRED_DUPLEX);
		return FALSE;
	}

	if (priv->device_mac_address && priv->device_mac_address->len != ETH_ALEN) {
		g_set_error (error,
		             NM_SETTING_WIRED_ERROR,
		             NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRED_MAC_ADDRESS);
		return FALSE;
	}

	if (   priv->s390_subchannels
	    && !(priv->s390_subchannels->len == 3 || priv->s390_subchannels->len == 2)) {
		g_set_error (error,
		             NM_SETTING_WIRED_ERROR,
		             NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRED_S390_SUBCHANNELS);
		return FALSE;
	}

	if (priv->s390_nettype && !_nm_utils_string_in_list (priv->s390_nettype, valid_nettype)) {
		g_set_error (error,
			         NM_SETTING_WIRED_ERROR,
			         NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
			         NM_SETTING_WIRED_S390_NETTYPE);
		return FALSE;
	}

	g_hash_table_iter_init (&iter, priv->s390_options);
	while (g_hash_table_iter_next (&iter, (gpointer) &key, (gpointer) &value)) {
		if (   !_nm_utils_string_in_list (key, valid_s390_opts)
		    || !strlen (value)
		    || (strlen (value) > 200)) {
			g_set_error (error,
				         NM_SETTING_WIRED_ERROR,
				         NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
				         NM_SETTING_WIRED_S390_OPTIONS);
			return FALSE;
		}
	}

	if (priv->cloned_mac_address && priv->cloned_mac_address->len != ETH_ALEN) {
		g_set_error (error,
		             NM_SETTING_WIRED_ERROR,
		             NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRED_CLONED_MAC_ADDRESS);
		return FALSE;
	}

	return TRUE;
}

static void
nm_setting_wired_init (NMSettingWired *setting)
{
	NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE (setting);

	g_object_set (setting, NM_SETTING_NAME, NM_SETTING_WIRED_SETTING_NAME, NULL);
	priv->s390_options = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
}

static void
finalize (GObject *object)
{
	NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE (object);

	g_free (priv->port);
	g_free (priv->duplex);
	g_free (priv->s390_nettype);

	g_hash_table_destroy (priv->s390_options);

	if (priv->device_mac_address)
		g_byte_array_free (priv->device_mac_address, TRUE);

	if (priv->cloned_mac_address)
		g_byte_array_free (priv->cloned_mac_address, TRUE);

	G_OBJECT_CLASS (nm_setting_wired_parent_class)->finalize (object);
}

static void
copy_hash (gpointer key, gpointer value, gpointer user_data)
{
	g_hash_table_insert ((GHashTable *) user_data, g_strdup (key), g_strdup (value));
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE (object);
	GHashTable *new_hash;

	switch (prop_id) {
	case PROP_PORT:
		g_free (priv->port);
		priv->port = g_value_dup_string (value);
		break;
	case PROP_SPEED:
		priv->speed = g_value_get_uint (value);
		break;
	case PROP_DUPLEX:
		g_free (priv->duplex);
		priv->duplex = g_value_dup_string (value);
		break;
	case PROP_AUTO_NEGOTIATE:
		priv->auto_negotiate = g_value_get_boolean (value);
		break;
	case PROP_MAC_ADDRESS:
		if (priv->device_mac_address)
			g_byte_array_free (priv->device_mac_address, TRUE);
		priv->device_mac_address = g_value_dup_boxed (value);
		break;
	case PROP_CLONED_MAC_ADDRESS:
		if (priv->cloned_mac_address)
			g_byte_array_free (priv->cloned_mac_address, TRUE);
		priv->cloned_mac_address = g_value_dup_boxed (value);
		break;
	case PROP_MTU:
		priv->mtu = g_value_get_uint (value);
		break;
	case PROP_S390_SUBCHANNELS:
		if (priv->s390_subchannels) {
			g_ptr_array_foreach (priv->s390_subchannels, (GFunc) g_free, NULL);
			g_ptr_array_free (priv->s390_subchannels, TRUE);
		}
		priv->s390_subchannels = g_value_dup_boxed (value);
		break;
	case PROP_S390_NETTYPE:
		g_free (priv->s390_nettype);
		priv->s390_nettype = g_value_dup_string (value);
		break;
	case PROP_S390_OPTIONS:
		/* Must make a deep copy of the hash table here... */
		g_hash_table_remove_all (priv->s390_options);
		new_hash = g_value_get_boxed (value);
		if (new_hash)
			g_hash_table_foreach (new_hash, copy_hash, priv->s390_options);
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
	NMSettingWired *setting = NM_SETTING_WIRED (object);
	NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_PORT:
		g_value_set_string (value, nm_setting_wired_get_port (setting));
		break;
	case PROP_SPEED:
		g_value_set_uint (value, nm_setting_wired_get_speed (setting));
		break;
	case PROP_DUPLEX:
		g_value_set_string (value, nm_setting_wired_get_duplex (setting));
		break;
	case PROP_AUTO_NEGOTIATE:
		g_value_set_boolean (value, nm_setting_wired_get_auto_negotiate (setting));
		break;
	case PROP_MAC_ADDRESS:
		g_value_set_boxed (value, nm_setting_wired_get_mac_address (setting));
		break;
	case PROP_CLONED_MAC_ADDRESS:
		g_value_set_boxed (value, nm_setting_wired_get_cloned_mac_address (setting));
		break;
	case PROP_MTU:
		g_value_set_uint (value, nm_setting_wired_get_mtu (setting));
		break;
	case PROP_S390_SUBCHANNELS:
		g_value_set_boxed (value, nm_setting_wired_get_s390_subchannels (setting));
		break;
	case PROP_S390_NETTYPE:
		g_value_set_string (value, nm_setting_wired_get_s390_nettype (setting));
		break;
	case PROP_S390_OPTIONS:
		g_value_set_boxed (value, priv->s390_options);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_wired_class_init (NMSettingWiredClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingWiredPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */
	/**
	 * NMSettingWired:port:
	 *
	 * Specific port type to use if multiple the device supports multiple
	 * attachment methods.  One of 'tp' (Twisted Pair), 'aui' (Attachment Unit
	 * Interface), 'bnc' (Thin Ethernet) or 'mii' (Media Independent Interface.
	 * If the device supports only one port type, this setting is ignored.
	 **/
	g_object_class_install_property
		(object_class, PROP_PORT,
		 g_param_spec_string (NM_SETTING_WIRED_PORT,
						  "Port",
						  "Specific port type to use if multiple the device "
						  "supports multiple attachment methods.  One of "
						  "'tp' (Twisted Pair), 'aui' (Attachment Unit Interface), "
						  "'bnc' (Thin Ethernet) or 'mii' (Media Independent "
						  "Interface.  If the device supports only one port "
						  "type, this setting is ignored.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:speed:
	 *
	 * If non-zero, request that the device use only the specified speed. 
	 * In Mbit/s, ie 100 == 100Mbit/s.
	 **/
	g_object_class_install_property
		(object_class, PROP_SPEED,
		 g_param_spec_uint (NM_SETTING_WIRED_SPEED,
						"Speed",
						"If non-zero, request that the device use only the "
						"specified speed.  In Mbit/s, ie 100 == 100Mbit/s.",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:duplex:
	 *
	 * If specified, request that the device only use the specified duplex mode.
	 * Either 'half' or 'full'.
	 **/
	g_object_class_install_property
		(object_class, PROP_DUPLEX,
		 g_param_spec_string (NM_SETTING_WIRED_DUPLEX,
						  "Duplex",
						  "If specified, request that the device only use the "
						  "specified duplex mode.  Either 'half' or 'full'.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingEthernet:auto-negotiate:
	 *
	 * If TRUE, allow auto-negotiation of port speed and duplex mode.  If FALSE,
	 * do not allow auto-negotiation, in which case the 'speed' and 'duplex'
	 * properties should be set.
	 **/
	g_object_class_install_property
		(object_class, PROP_AUTO_NEGOTIATE,
		 g_param_spec_boolean (NM_SETTING_WIRED_AUTO_NEGOTIATE,
						   "AutoNegotiate",
						   "If TRUE, allow auto-negotiation of port speed and "
						   "duplex mode.  If FALSE, do not allow auto-negotiation,"
						   "in which case the 'speed' and 'duplex' properties "
						   "should be set.",
						   TRUE,
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:mac-address:
	 *
	 * If specified, this connection will only apply to the ethernet device
	 * whose permanent MAC address matches. This property does not change the MAC address
	 * of the device (i.e. MAC spoofing).
	 **/
	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS,
		 _nm_param_spec_specialized (NM_SETTING_WIRED_MAC_ADDRESS,
							   "Device MAC Address",
							   "If specified, this connection will only apply to "
							   "the ethernet device whose permanent MAC address matches.  "
							   "This property does not change the MAC address "
							   "of the device (i.e. MAC spoofing).",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:cloned-mac-address:
	 *
	 * If specified, request that the device use this MAC address instead of its
	 * permanent MAC address.  This is known as MAC cloning or spoofing.
	 **/
	g_object_class_install_property
		(object_class, PROP_CLONED_MAC_ADDRESS,
		 _nm_param_spec_specialized (NM_SETTING_WIRED_CLONED_MAC_ADDRESS,
	                                     "Cloned MAC Address",
	                                     "If specified, request that the device use "
	                                     "this MAC address instead of its permanent MAC address.  "
	                                     "This is known as MAC cloning or spoofing.",
	                                     DBUS_TYPE_G_UCHAR_ARRAY,
	                                     G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:mtu:
	 *
	 * If non-zero, only transmit packets of the specified size or smaller,
	 * breaking larger packets up into multiple Ethernet frames.
	 **/
	g_object_class_install_property
		(object_class, PROP_MTU,
		 g_param_spec_uint (NM_SETTING_WIRED_MTU,
						"MTU",
						"If non-zero, only transmit packets of the specified "
						"size or smaller, breaking larger packets up into "
						"multiple Ethernet frames.",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	/**
	 * NMSettingWired:s390-subchannels:
	 *
	 * Identifies specific subchannels that this network device uses for
	 * communcation with z/VM or s390 host.  Like #NMSettingWired:mac-address
	 * for non-z/VM devices, this property can be used to ensure this connection
	 * only applies to the network device that uses these subchannels.  The
	 * list should contain exactly 3 strings, and each string may only be
	 * composed of hexadecimal characters and the period (.) character.
	 **/
	g_object_class_install_property
		(object_class, PROP_S390_SUBCHANNELS,
		 _nm_param_spec_specialized (NM_SETTING_WIRED_S390_SUBCHANNELS,
		                       "z/VM Subchannels",
		                       "Identifies specific subchannels that this "
		                       "network device uses for communcation with z/VM "
		                       "or s390 host.  Like the 'mac-address' property "
		                       "for non-z/VM devices, this property can be used "
		                       "to ensure this connection only applies to the "
		                       "network device that uses these subchannels. The "
		                       "list should contain exactly 3 strings, and each "
		                       "string may only be composed of hexadecimal "
		                       "characters and the period (.) character.",
		                       DBUS_TYPE_G_ARRAY_OF_STRING,
		                       G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:s390-nettype:
	 *
	 * s390 network device type; one of 'qeth', 'lcs', or 'ctc', representing
	 * the different types of virtual network devices available on s390 systems.
	 **/
	g_object_class_install_property
		(object_class, PROP_S390_NETTYPE,
		 g_param_spec_string (NM_SETTING_WIRED_S390_NETTYPE,
						  "s390 Net Type",
						  "s390 network device type; one of 'qeth', 'lcs', or "
						  "'ctc', representing the different types of virtual "
						  "network devices available on s390 systems.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:s390-options:
	 *
	 * Dictionary of key/value pairs of s390-specific device options.  Both keys
	 * and values must be strings.  Allowed keys include 'portno', 'layer2',
	 * 'portname', 'protocol', among others.  Key names must contain only
	 * alphanumeric characters (ie, [a-zA-Z0-9]).
	 **/
	g_object_class_install_property
		(object_class, PROP_S390_OPTIONS,
		 _nm_param_spec_specialized (NM_SETTING_WIRED_S390_OPTIONS,
							   "s390 Options",
							   "Dictionary of key/value pairs of s390-specific "
							   "device options.  Both keys and values must be "
							   "strings.  Allowed keys include 'portno', "
							   "'layer2', 'portname', 'protocol', among others.",
							   DBUS_TYPE_G_MAP_OF_STRING,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));
}

