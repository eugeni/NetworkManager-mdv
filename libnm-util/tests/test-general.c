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
 * Copyright (C) 2008 - 2010 Red Hat, Inc.
 *
 */

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <string.h>

#include "nm-test-helpers.h"
#include <nm-utils.h>

#include "nm-setting-connection.h"
#include "nm-setting-vpn.h"
#include "nm-setting-gsm.h"
#include "nm-setting-wired.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-pppoe.h"
#include "nm-dbus-glib-types.h"

static void
vpn_check_func (const char *key, const char *value, gpointer user_data)
{
	const char *test = user_data;

	if (!strcmp (key, "foobar1")) {
		ASSERT (strcmp (value, "blahblah1") == 0,
				test, "unexpected vpn item '%s' / '%s'", key, value);
		return;
	}

	if (!strcmp (key, "foobar2")) {
		ASSERT (strcmp (value, "blahblah2") == 0,
				test, "unexpected vpn item '%s' / '%s'", key, value);
		return;
	}

	if (!strcmp (key, "foobar3")) {
		ASSERT (strcmp (value, "blahblah3") == 0,
				test, "unexpected vpn item '%s' / '%s'", key, value);
		return;
	}

	if (!strcmp (key, "foobar4")) {
		ASSERT (strcmp (value, "blahblah4") == 0,
				test, "unexpected vpn item '%s' / '%s'", key, value);
		return;
	}

	ASSERT (FALSE, test, "unexpected vpn item '%s'", key);
}

static void
vpn_check_empty_func (const char *key, const char *value, gpointer user_data)
{
	const char *test = user_data;

	/* We don't expect any values */
	ASSERT (FALSE, test, "unexpected vpn item '%s'", key);
}

static void
test_setting_vpn_items (void)
{
	NMSettingVPN *s_vpn;

	s_vpn = (NMSettingVPN *) nm_setting_vpn_new ();
	ASSERT (s_vpn != NULL,
	        "vpn-items",
	        "error creating vpn setting");

	nm_setting_vpn_add_data_item (s_vpn, "foobar1", "blahblah1");
	nm_setting_vpn_add_data_item (s_vpn, "foobar2", "blahblah2");
	nm_setting_vpn_add_data_item (s_vpn, "foobar3", "blahblah3");
	nm_setting_vpn_add_data_item (s_vpn, "foobar4", "blahblah4");

	/* Ensure that added values are all present */
	nm_setting_vpn_foreach_data_item (s_vpn, vpn_check_func, "vpn-data");
	nm_setting_vpn_remove_data_item (s_vpn, "foobar1");
	nm_setting_vpn_remove_data_item (s_vpn, "foobar2");
	nm_setting_vpn_remove_data_item (s_vpn, "foobar3");
	nm_setting_vpn_remove_data_item (s_vpn, "foobar4");

	nm_setting_vpn_add_secret (s_vpn, "foobar1", "blahblah1");
	nm_setting_vpn_add_secret (s_vpn, "foobar2", "blahblah2");
	nm_setting_vpn_add_secret (s_vpn, "foobar3", "blahblah3");
	nm_setting_vpn_add_secret (s_vpn, "foobar4", "blahblah4");

	/* Ensure that added values are all present */
	nm_setting_vpn_foreach_secret (s_vpn, vpn_check_func, "vpn-secrets");
	nm_setting_vpn_remove_secret (s_vpn, "foobar1");
	nm_setting_vpn_remove_secret (s_vpn, "foobar2");
	nm_setting_vpn_remove_secret (s_vpn, "foobar3");
	nm_setting_vpn_remove_secret (s_vpn, "foobar4");

	/* Try to add some blank values and make sure they are rejected */
	nm_setting_vpn_add_data_item (s_vpn, NULL, NULL);
	nm_setting_vpn_add_data_item (s_vpn, "", "");
	nm_setting_vpn_add_data_item (s_vpn, "foobar1", NULL);
	nm_setting_vpn_add_data_item (s_vpn, "foobar1", "");
	nm_setting_vpn_add_data_item (s_vpn, NULL, "blahblah1");
	nm_setting_vpn_add_data_item (s_vpn, "", "blahblah1");

	nm_setting_vpn_foreach_data_item (s_vpn, vpn_check_empty_func, "vpn-data-empty");

	/* Try to add some blank secrets and make sure they are rejected */
	nm_setting_vpn_add_secret (s_vpn, NULL, NULL);
	nm_setting_vpn_add_secret (s_vpn, "", "");
	nm_setting_vpn_add_secret (s_vpn, "foobar1", NULL);
	nm_setting_vpn_add_secret (s_vpn, "foobar1", "");
	nm_setting_vpn_add_secret (s_vpn, NULL, "blahblah1");
	nm_setting_vpn_add_secret (s_vpn, "", "blahblah1");

	nm_setting_vpn_foreach_secret (s_vpn, vpn_check_empty_func, "vpn-secrets-empty");

	g_object_unref (s_vpn);
}

#define OLD_DBUS_TYPE_G_IP6_ADDRESS (dbus_g_type_get_struct ("GValueArray", DBUS_TYPE_G_UCHAR_ARRAY, G_TYPE_UINT, G_TYPE_INVALID))
#define OLD_DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS (dbus_g_type_get_collection ("GPtrArray", OLD_DBUS_TYPE_G_IP6_ADDRESS))

/* Test that setting the IPv6 setting's 'addresses' property using the old
 * IPv6 address format still works, i.e. that the GValue transformation function
 * from old->new is working correctly.
 */
static void
test_setting_ip6_config_old_address_array (void)
{
	NMSettingIP6Config *s_ip6;
	GPtrArray *addresses, *read_addresses;
	GValueArray *array, *read_array;
	GValue element = {0, }, written_value = {0, }, read_value = {0, };
	GByteArray *ba;
	const guint8 addr[16] = { 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
	                          0x11, 0x22, 0x33, 0x44, 0x66, 0x77, 0x88, 0x99 };
	const guint8 gw[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	guint32 prefix = 56;
	GValue *read_addr, *read_prefix, *read_gw;

	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        "ip6-old-addr", "error creating IP6 setting");

	g_value_init (&written_value, OLD_DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS);

	addresses = g_ptr_array_new ();
	array = g_value_array_new (3);

	/* IP address */
	g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
	ba = g_byte_array_new ();
	g_byte_array_append (ba, &addr[0], sizeof (addr));
	g_value_take_boxed (&element, ba);
	g_value_array_append (array, &element);
	g_value_unset (&element);

	/* Prefix */
	g_value_init (&element, G_TYPE_UINT);
	g_value_set_uint (&element, prefix);
	g_value_array_append (array, &element);
	g_value_unset (&element);

	g_ptr_array_add (addresses, array);
	g_value_set_boxed (&written_value, addresses);

	/* Set the address array on the object */
	g_object_set_property (G_OBJECT (s_ip6), NM_SETTING_IP6_CONFIG_ADDRESSES, &written_value);

	/* Get it back so we can compare it */
	g_value_init (&read_value, DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS);
	g_object_get_property (G_OBJECT (s_ip6), NM_SETTING_IP6_CONFIG_ADDRESSES, &read_value);

	ASSERT (G_VALUE_HOLDS (&read_value, DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS),
	        "ip6-old-addr", "wrong addresses property value type '%s'",
	        G_VALUE_TYPE_NAME (&read_value));

	read_addresses = (GPtrArray *) g_value_get_boxed (&read_value);
	ASSERT (read_addresses != NULL,
	        "ip6-old-addr", "missing addresses on readback");
	ASSERT (read_addresses->len == 1,
	        "ip6-old-addr", "expected one address on readback");

	read_array = (GValueArray *) g_ptr_array_index (read_addresses, 0);

	read_addr = g_value_array_get_nth (read_array, 0);
	ba = g_value_get_boxed (read_addr);
	ASSERT (ba->len == sizeof (addr),
	        "ip6-old-addr", "unexpected address item length %d", ba->len);
	ASSERT (memcmp (ba->data, &addr[0], sizeof (addr)) == 0,
	        "ip6-old-addr", "unexpected failure comparing addresses");

	read_prefix = g_value_array_get_nth (read_array, 1);
	ASSERT (g_value_get_uint (read_prefix) == prefix,
	        "ip6-old-addr", "unexpected failure comparing prefix");

	/* Ensure the gateway is all zeros, which is how the 2-item to 3-item
	 * conversion happens.
	 */
	read_gw = g_value_array_get_nth (read_array, 2);
	ba = g_value_get_boxed (read_gw);
	ASSERT (ba->len == sizeof (gw),
	        "ip6-old-addr", "unexpected gateway item length %d", ba->len);
	ASSERT (memcmp (ba->data, &gw[0], sizeof (gw)) == 0,
	        "ip6-old-addr", "unexpected failure comparing gateways");

	g_value_unset (&written_value);
	g_value_unset (&read_value);
	g_object_unref (s_ip6);
}

static void
test_setting_gsm_apn_spaces (void)
{
	NMSettingGsm *s_gsm;
	const char *tmp;

	s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
	ASSERT (s_gsm != NULL,
	        "gsm-apn-spaces",
	        "error creating GSM setting");

	/* Trailing space */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "foobar ", NULL);
	tmp = nm_setting_gsm_get_apn (s_gsm);
	ASSERT (tmp != NULL,
	        "gsm-apn-spaces", "empty APN");
	ASSERT (strcmp (tmp, "foobar") == 0,
	        "gsm-apn-spaces", "unexpected APN");

	/* Leading space */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, " foobar", NULL);
	tmp = nm_setting_gsm_get_apn (s_gsm);
	ASSERT (tmp != NULL,
	        "gsm-apn-spaces", "empty APN");
	ASSERT (strcmp (tmp, "foobar") == 0,
	        "gsm-apn-spaces", "unexpected APN");
}

static void
test_setting_gsm_apn_bad_chars (void)
{
	NMSettingGsm *s_gsm;

	s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
	ASSERT (s_gsm != NULL,
	        "gsm-apn-bad-chars",
	        "error creating GSM setting");

	g_object_set (s_gsm, NM_SETTING_GSM_NUMBER, "*99#", NULL);

	/* Make sure a valid APN works */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "foobar123.-baz", NULL);
	ASSERT (nm_setting_verify (NM_SETTING (s_gsm), NULL, NULL) == TRUE,
	        "gsm-apn-bad-chars", "unexpectedly invalid GSM setting");

	/* Random invalid chars */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "@#%$@#%@#%", NULL);
	ASSERT (nm_setting_verify (NM_SETTING (s_gsm), NULL, NULL) == FALSE,
	        "gsm-apn-bad-chars", "unexpectedly valid GSM setting");

	/* Spaces */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "foobar baz", NULL);
	ASSERT (nm_setting_verify (NM_SETTING (s_gsm), NULL, NULL) == FALSE,
	        "gsm-apn-bad-chars", "unexpectedly valid GSM setting");

	/* 0 characters long */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "", NULL);
	ASSERT (nm_setting_verify (NM_SETTING (s_gsm), NULL, NULL) == FALSE,
	        "gsm-apn-bad-chars", "unexpectedly valid GSM setting");

	/* 65-character long */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl1", NULL);
	ASSERT (nm_setting_verify (NM_SETTING (s_gsm), NULL, NULL) == FALSE,
	        "gsm-apn-bad-chars", "unexpectedly valid GSM setting");
}

static NMConnection *
new_test_connection (void)
{
	NMConnection *connection;
	NMSetting *setting;
	char *uuid;
	gulong timestamp = time (NULL);

	connection = nm_connection_new ();

	setting = nm_setting_connection_new ();
	uuid = nm_utils_uuid_generate ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_CONNECTION_ID, "foobar",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_TIMESTAMP, timestamp,
	              NULL);
	g_free (uuid);
	nm_connection_add_setting (connection, setting);

	setting = nm_setting_wired_new ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_WIRED_MTU, 1592,
	              NULL);
	nm_connection_add_setting (connection, setting);

	setting = nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME, "eyeofthetiger",
	              NULL);
	nm_connection_add_setting (connection, setting);

	return connection;
}

typedef struct {
	const char *key_name;
	guint32 result;
} DiffKey;

typedef struct {
	const char *name;
	DiffKey keys[30];
} DiffSetting;

#define ARRAY_LEN(a)  (sizeof (a) / sizeof (a[0]))

static void
ensure_diffs (GHashTable *diffs, const DiffSetting *check, gsize n_check)
{
	guint i;

	g_assert (g_hash_table_size (diffs) == n_check);

	/* Loop through the settings */
	for (i = 0; i < n_check; i++) {
		GHashTable *setting_hash;
		guint z = 0;

		setting_hash = g_hash_table_lookup (diffs, check[i].name);
		g_assert (setting_hash);

		/* Get the number of keys to check */
		while (check[i].keys[z].key_name)
			z++;
		g_assert (g_hash_table_size (setting_hash) == z);

		/* Now compare the actual keys */
		for (z = 0; check[i].keys[z].key_name; z++) {
			NMSettingDiffResult result;

			result = GPOINTER_TO_UINT (g_hash_table_lookup (setting_hash, check[i].keys[z].key_name));
			g_assert (result == check[i].keys[z].result);
		}
	}
}

static void
test_connection_diff_a_only (void)
{
	NMConnection *connection;
	GHashTable *out_diffs = NULL;
	gboolean same;
	const DiffSetting settings[] = {
		{ NM_SETTING_CONNECTION_SETTING_NAME, {
			{ NM_SETTING_CONNECTION_ID,          NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_UUID,        NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_TYPE,        NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_TIMESTAMP,   NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_AUTOCONNECT, NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_READ_ONLY,   NM_SETTING_DIFF_RESULT_IN_A },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN }
		} },
		{ NM_SETTING_WIRED_SETTING_NAME, {
			{ NM_SETTING_WIRED_PORT,               NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_SPEED,              NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_DUPLEX,             NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_AUTO_NEGOTIATE,     NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_MAC_ADDRESS,        NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_CLONED_MAC_ADDRESS, NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_MTU,                NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_S390_SUBCHANNELS,   NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_S390_NETTYPE,       NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_S390_OPTIONS,       NM_SETTING_DIFF_RESULT_IN_A },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN },
		} },
		{ NM_SETTING_IP4_CONFIG_SETTING_NAME, {
			{ NM_SETTING_IP4_CONFIG_METHOD,             NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_DNS,                NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_DNS_SEARCH,         NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_ADDRESSES,          NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_ROUTES,             NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_IGNORE_AUTO_ROUTES, NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS,    NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID,     NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_DHCP_SEND_HOSTNAME, NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME,      NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_NEVER_DEFAULT,      NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_MAY_FAIL,           NM_SETTING_DIFF_RESULT_IN_A },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN },
		} },
	};

	connection = new_test_connection ();

	same = nm_connection_diff (connection, NULL, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
	g_assert (same == FALSE);
	g_assert (out_diffs != NULL);
	g_assert (g_hash_table_size (out_diffs) > 0);

	ensure_diffs (out_diffs, settings, ARRAY_LEN (settings));

	g_object_unref (connection);
}

static void
test_connection_diff_same (void)
{
	NMConnection *a, *b;
	GHashTable *out_diffs = NULL;
	gboolean same;

	a = new_test_connection ();
	b = nm_connection_duplicate (a);

	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
	g_assert (same == TRUE);
	g_assert (out_diffs == NULL);
	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_diff_different (void)
{
	NMConnection *a, *b;
	GHashTable *out_diffs = NULL;
	NMSetting *s_ip4;
	gboolean same;
	const DiffSetting settings[] = {
		{ NM_SETTING_IP4_CONFIG_SETTING_NAME, {
			{ NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_DIFF_RESULT_IN_A | NM_SETTING_DIFF_RESULT_IN_B },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN },
		} },
	};

	a = new_test_connection ();
	b = nm_connection_duplicate (a);
	s_ip4 = nm_connection_get_setting (a, NM_TYPE_SETTING_IP4_CONFIG);
	g_assert (s_ip4);
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NULL);

	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
	g_assert (same == FALSE);
	g_assert (out_diffs != NULL);
	g_assert (g_hash_table_size (out_diffs) > 0);

	ensure_diffs (out_diffs, settings, ARRAY_LEN (settings));

	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_diff_no_secrets (void)
{
	NMConnection *a, *b;
	GHashTable *out_diffs = NULL;
	NMSetting *s_pppoe;
	gboolean same;
	const DiffSetting settings[] = {
		{ NM_SETTING_PPPOE_SETTING_NAME, {
			{ NM_SETTING_PPPOE_PASSWORD, NM_SETTING_DIFF_RESULT_IN_B },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN },
		} },
	};

	a = new_test_connection ();
	s_pppoe = nm_setting_pppoe_new ();
	g_object_set (G_OBJECT (s_pppoe),
	              NM_SETTING_PPPOE_USERNAME, "thomas",
	              NULL);
	nm_connection_add_setting (a, s_pppoe);

	b = nm_connection_duplicate (a);

	/* Add a secret to B */
	s_pppoe = nm_connection_get_setting (b, NM_TYPE_SETTING_PPPOE);
	g_assert (s_pppoe);
	g_object_set (G_OBJECT (s_pppoe),
	              NM_SETTING_PPPOE_PASSWORD, "secretpassword",
	              NULL);

	/* Make sure the diff returns no results as secrets are ignored */
	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS, &out_diffs);
	g_assert (same == TRUE);
	g_assert (out_diffs == NULL);

	/* Now make sure the diff returns results if secrets are not ignored */
	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
	g_assert (same == FALSE);
	g_assert (out_diffs != NULL);
	g_assert (g_hash_table_size (out_diffs) > 0);

	ensure_diffs (out_diffs, settings, ARRAY_LEN (settings));

	g_object_unref (a);
	g_object_unref (b);
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
	test_setting_vpn_items ();
	test_setting_ip6_config_old_address_array ();
	test_setting_gsm_apn_spaces ();
	test_setting_gsm_apn_bad_chars ();
	test_connection_diff_a_only ();
	test_connection_diff_same ();
	test_connection_diff_different ();
	test_connection_diff_no_secrets ();

	base = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", base);
	g_free (base);
	return 0;
}

