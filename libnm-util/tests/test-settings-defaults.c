/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 *
 * This program is free software; you can redistribute it and/or modify
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
 * Copyright (C) 2008 Red Hat, Inc.
 *
 */

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <string.h>

#include "nm-test-helpers.h"
#include <nm-utils.h>

#include "nm-setting-8021x.h"
#include "nm-setting-cdma.h"
#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-serial.h"
#include "nm-setting-vpn.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"


static void
test_defaults (GType type, const char *name)
{
	GParamSpec **property_specs;
	guint n_property_specs;
	GObject *setting;
	int i;

	setting = g_object_new (type, NULL);

	property_specs = g_object_class_list_properties (G_OBJECT_GET_CLASS (setting), &n_property_specs);
	ASSERT (property_specs != NULL,
	        name, "couldn't find property specs for object of type '%s'",
	        g_type_name (G_OBJECT_TYPE (setting)));

	for (i = 0; i < n_property_specs; i++) {
		GParamSpec *prop_spec = property_specs[i];
		GValue value = { 0, };
		GValue defvalue = { 0, };
		char *actual, *expected;
		gboolean ok = FALSE;

		/* Ignore non-fundamental types since they won't really have
		 * defaults.
		 */
		if (!G_TYPE_IS_FUNDAMENTAL (prop_spec->value_type))
			continue;

		g_value_init (&value, prop_spec->value_type);
		g_object_get_property (G_OBJECT (setting), prop_spec->name, &value);

		g_value_init (&defvalue, prop_spec->value_type);
		g_param_value_set_default (prop_spec, &defvalue);

		actual = g_strdup_value_contents (&value);
		expected = g_strdup_value_contents (&defvalue);

		if (!strcmp (prop_spec->name, NM_SETTING_NAME)) {
			/* 'name' is always the setting name, not the default value */
			ok = !strcmp (nm_setting_get_name (NM_SETTING (setting)), name);
			g_free (expected);
			expected = g_strdup (name);
		} else
			ok = g_param_value_defaults (prop_spec, &value);

		ASSERT (ok,
		        name, "property '%s' value '%s' not the expected default value '%s'",
		        prop_spec->name, actual, expected);

		g_free (actual);
		g_free (expected);
		g_value_unset (&value);
		g_value_unset (&defvalue);
	}

	g_free (property_specs);
	g_object_unref (setting);
}

int main (int argc, char **argv)
{
	GError *error = NULL;
	DBusGConnection *bus;
	char *base;

	g_type_init ();
	bus = dbus_g_bus_get (DBUS_BUS_SESSION, NULL);

	if (!nm_utils_init (&error))
		FAIL ("nm-utils-init", "failed to initialize libnm-util: %s", error->message);

	/* The tests */
	test_defaults (NM_TYPE_SETTING_CONNECTION, NM_SETTING_CONNECTION_SETTING_NAME);
	test_defaults (NM_TYPE_SETTING_802_1X, NM_SETTING_802_1X_SETTING_NAME);
	test_defaults (NM_TYPE_SETTING_CDMA, NM_SETTING_CDMA_SETTING_NAME);
	test_defaults (NM_TYPE_SETTING_GSM, NM_SETTING_GSM_SETTING_NAME);
	test_defaults (NM_TYPE_SETTING_IP4_CONFIG, NM_SETTING_IP4_CONFIG_SETTING_NAME);
	test_defaults (NM_TYPE_SETTING_IP6_CONFIG, NM_SETTING_IP6_CONFIG_SETTING_NAME);
	test_defaults (NM_TYPE_SETTING_PPP, NM_SETTING_PPP_SETTING_NAME);
	test_defaults (NM_TYPE_SETTING_PPPOE, NM_SETTING_PPPOE_SETTING_NAME);
	test_defaults (NM_TYPE_SETTING_SERIAL, NM_SETTING_SERIAL_SETTING_NAME);
	test_defaults (NM_TYPE_SETTING_VPN, NM_SETTING_VPN_SETTING_NAME);
	test_defaults (NM_TYPE_SETTING_WIRED, NM_SETTING_WIRED_SETTING_NAME);
	test_defaults (NM_TYPE_SETTING_WIRELESS, NM_SETTING_WIRELESS_SETTING_NAME);
	test_defaults (NM_TYPE_SETTING_WIRELESS_SECURITY, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	base = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", base);
	g_free (base);
	return 0;
}

