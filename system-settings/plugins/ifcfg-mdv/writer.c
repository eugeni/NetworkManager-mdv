/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service - keyfile plugin
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
 * Copyright (C) 2009 - 2010 Red Hat, Inc.
 * Mandriva-specific changes by Eugeni Dodonov <eugeni@mandriva.com>.
 */

#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-8021x.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-pppoe.h>
#include <nm-utils.h>

#include "common.h"
#include "shvar.h"
#include "reader.h"
#include "writer.h"
#include "utils.h"
#include "utils-mdv.h"
#include "crypto.h"

#include "parse_wpa_supplicant_conf.h"

#define PLUGIN_WARN(pname, fmt, args...) \
	{ g_warning ("   " pname ": " fmt, ##args); }


/*
 * ifcfg reader converts ASCII to HEX. This converts key back to ASCII
 * before writing
 */

static gchar *
wep4ifcfg(const gchar *value)
{
	gchar *s;
	gsize len;
	GString *str;

	if (!value)
		return NULL;

	len = strlen(value);
	str = g_string_new("");

	if (len == 5 || len == 13) {
		g_string_printf(str, "s:%s", value);
	} else if (len == 10 || len == 26) {
		gchar *p;
		s = utils_hexstr2bin (value, len);
		for (p = s; *p; p++) {
			if (!isascii (*p)) {
				g_free(s);
				g_string_free(str, TRUE);
				return g_strdup(value);
			}
		}
		g_string_printf(str, "s:%s", s);
		g_free(s);
	} else {
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: invalid WEP key length");
		g_string_free(str, TRUE);
		return NULL;
	}

	s = svEscape(str->str);
	g_string_free(str, TRUE);
	return s;
}
static void
set_wep_secret (shvarFile *ifcfg, const char *key, const char *value, gboolean verbatim)
{
	char *v = 0;
	
	/* Clear the secret from the actual ifcfg */
	svSetValue (ifcfg, key, NULL, FALSE);

	/* WEP -> WPA will set empty key */
	if (!value)
		return;

	v = wep4ifcfg(value);
	if (!v)
		return;

	/* Try setting the secret in the actual ifcfg */
	svSetValue (ifcfg, key, v, TRUE);
	g_free(v);
}

#if 0
static gboolean
write_secret_file (const char *path,
                   const char *data,
                   gsize len,
                   GError **error)
{
	char *tmppath;
	int fd = -1, written;
	gboolean success = FALSE;

	tmppath = g_malloc0 (strlen (path) + 10);
	if (!tmppath) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Could not allocate memory for temporary file for '%s'",
		             path);
		return FALSE;
	}

	memcpy (tmppath, path, strlen (path));
	strcat (tmppath, ".XXXXXX");

	errno = 0;
	fd = mkstemp (tmppath);
	if (fd < 0) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Could not create temporary file for '%s': %d",
		             path, errno);
		goto out;
	}

	/* Only readable by root */
	errno = 0;
	if (fchmod (fd, S_IRUSR | S_IWUSR)) {
		close (fd);
		unlink (tmppath);
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Could not set permissions for temporary file '%s': %d",
		             path, errno);
		goto out;
	}

	errno = 0;
	written = write (fd, data, len);
	if (written != len) {
		close (fd);
		unlink (tmppath);
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Could not write temporary file for '%s': %d",
		             path, errno);
		goto out;
	}
	close (fd);

	/* Try to rename */
	errno = 0;
	if (rename (tmppath, path)) {
		unlink (tmppath);
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Could not rename temporary file to '%s': %d",
		             path, errno);
		goto out;
	}
	success = TRUE;

out:
	return success;
}
#endif

typedef NMSetting8021xCKScheme (*SchemeFunc)(NMSetting8021x *setting);
typedef const char *           (*PathFunc)  (NMSetting8021x *setting);
typedef const GByteArray *     (*BlobFunc)  (NMSetting8021x *setting);

typedef struct ObjectType {
	const char *setting_key;
	SchemeFunc scheme_func;
	PathFunc path_func;
	BlobFunc blob_func;
	const char *ifcfg_key;
	const char *suffix;
} ObjectType;

static const ObjectType ca_type = {
	NM_SETTING_802_1X_CA_CERT,
	nm_setting_802_1x_get_ca_cert_scheme,
	nm_setting_802_1x_get_ca_cert_path,
	nm_setting_802_1x_get_ca_cert_blob,
	"ca_cert",
	"ca-cert.der"
};

static const ObjectType phase2_ca_type = {
	NM_SETTING_802_1X_PHASE2_CA_CERT,
	nm_setting_802_1x_get_phase2_ca_cert_scheme,
	nm_setting_802_1x_get_phase2_ca_cert_path,
	nm_setting_802_1x_get_phase2_ca_cert_blob,
	"ca_cert2",
	"inner-ca-cert.der"
};

static const ObjectType client_type = {
	NM_SETTING_802_1X_CLIENT_CERT,
	nm_setting_802_1x_get_client_cert_scheme,
	nm_setting_802_1x_get_client_cert_path,
	nm_setting_802_1x_get_client_cert_blob,
	"client_cert",
	"client-cert.der"
};

static const ObjectType phase2_client_type = {
	NM_SETTING_802_1X_PHASE2_CLIENT_CERT,
	nm_setting_802_1x_get_phase2_client_cert_scheme,
	nm_setting_802_1x_get_phase2_client_cert_path,
	nm_setting_802_1x_get_phase2_client_cert_blob,
	"client_cert2",
	"inner-client-cert.der"
};

static const ObjectType pk_type = {
	NM_SETTING_802_1X_PRIVATE_KEY,
	nm_setting_802_1x_get_private_key_scheme,
	nm_setting_802_1x_get_private_key_path,
	nm_setting_802_1x_get_private_key_blob,
	"private_key",
	"private-key.pem"
};

static const ObjectType phase2_pk_type = {
	NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
	nm_setting_802_1x_get_phase2_private_key_scheme,
	nm_setting_802_1x_get_phase2_private_key_path,
	nm_setting_802_1x_get_phase2_private_key_blob,
	"private_key2",
	"inner-private-key.pem"
};

static const ObjectType p12_type = {
	NM_SETTING_802_1X_PRIVATE_KEY,
	nm_setting_802_1x_get_private_key_scheme,
	nm_setting_802_1x_get_private_key_path,
	nm_setting_802_1x_get_private_key_blob,
	"private_key",
	"private-key.p12"
};

static const ObjectType phase2_p12_type = {
	NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
	nm_setting_802_1x_get_phase2_private_key_scheme,
	nm_setting_802_1x_get_phase2_private_key_path,
	nm_setting_802_1x_get_phase2_private_key_blob,
	"private_key2",
	"inner-private-key.p12"
};

/*
 * FIXME the name is misleading and should be changed
 * Mandriva does not use explicit certifcate store so we do nto either
 * If given BLOB - fail, informing user
 */
static gboolean
write_object (NMSetting8021x *s_8021x,
	      WPANetwork *wpan,
              shvarFile *ifcfg,
              const GByteArray *override_data,
              const ObjectType *objtype,
              GError **error)
{
	NMSetting8021xCKScheme scheme;
	const char *path = NULL;
	const GByteArray *blob = NULL;

	g_return_val_if_fail (ifcfg != NULL, FALSE);
	g_return_val_if_fail (objtype != NULL, FALSE);

	if (override_data) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			     "ifcfg-mdv does not support raw certificate data");
		return FALSE;
		/* if given explicit data to save, always use that instead of asking
		 * the setting what to do.
		 */
		// blob = override_data;
	} else {
		scheme = (*(objtype->scheme_func))(s_8021x);
		switch (scheme) {
		case NM_SETTING_802_1X_CK_SCHEME_BLOB:
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
				     "ifcfg-mdv does not support raw certificate data");
			return FALSE;
		// 	blob = (*(objtype->blob_func))(s_8021x);
		// 	break;
		case NM_SETTING_802_1X_CK_SCHEME_PATH:
			path = (*(objtype->path_func))(s_8021x);
			break;
		default:
			break;
		}
	}

	/* If certificate/private key wasn't sent, the connection may no longer be
	 * 802.1x and thus we clear out the paths and certs.
	 */
	if (!path && !blob) {
		// char *standard_file;
		// int ignored;

		/* Since no cert/private key is now being used, delete any standard file
		 * that was created for this connection, but leave other files alone.
		 * Thus, for example,
		 * /etc/sysconfig/network-scripts/ca-cert-Test_Write_Wifi_WPA_EAP-TLS.der
		 * will be deleted, but /etc/pki/tls/cert.pem will not.
		 */
#if 0
		standard_file = utils_cert_path (ifcfg->fileName, objtype->suffix);
		if (g_file_test (standard_file, G_FILE_TEST_EXISTS))
			ignored = unlink (standard_file);
		g_free (standard_file);
#endif

		ifcfg_mdv_wpa_network_unset(wpan, objtype->ifcfg_key);
		return TRUE;
	}

	/* If the object path was specified, prefer that over any raw cert data that
	 * may have been sent.
	 */
	if (path) {
		ifcfg_mdv_wpa_network_set_str(wpan, objtype->ifcfg_key, path);
		return TRUE;
	}

#if 0
	/* If it's raw certificate data, write the cert data out to the standard file */
	if (blob) {
		gboolean success;
		char *new_file;
		GError *write_error = NULL;

		new_file = utils_cert_path (ifcfg->fileName, objtype->suffix);
		if (!new_file) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Could not create file path for %s / %s",
			             NM_SETTING_802_1X_SETTING_NAME, objtype->setting_key);
			return FALSE;
		}

		/* Write the raw certificate data out to the standard file so that we
		 * can use paths from now on instead of pushing around the certificate
		 * data itself.
		 */
		success = write_secret_file (new_file, (const char *) blob->data, blob->len, &write_error);
		if (success) {
			svSetValue (ifcfg, objtype->ifcfg_key, new_file, FALSE);
			return TRUE;
		} else {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Could not write certificate/key for %s / %s: %s",
			             NM_SETTING_802_1X_SETTING_NAME, objtype->setting_key,
			             (write_error && write_error->message) ? write_error->message : "(unknown)");
			g_clear_error (&write_error);
		}
		g_free (new_file);
	}
#endif

	return FALSE;
}

static gboolean
write_8021x_certs (NMSetting8021x *s_8021x,
		   WPANetwork *wpan,
                   gboolean phase2,
                   shvarFile *ifcfg,
                   GError **error)
{
	GByteArray *enc_key = NULL;
	const char *password = NULL;
	// char *generated_pw = NULL;
	gboolean success = FALSE, is_pkcs12 = FALSE;
	const ObjectType *otype = NULL;
	const GByteArray *blob = NULL;

	/* CA certificate */
	if (phase2)
		otype = &phase2_ca_type;
	else
		otype = &ca_type;

	if (!write_object (s_8021x, wpan, ifcfg, NULL, otype, error))
		return FALSE;

	/* Private key */
	if (phase2) {
		if (nm_setting_802_1x_get_phase2_private_key_scheme (s_8021x) != NM_SETTING_802_1X_CK_SCHEME_UNKNOWN) {
			if (nm_setting_802_1x_get_phase2_private_key_format (s_8021x) == NM_SETTING_802_1X_CK_FORMAT_PKCS12)
				is_pkcs12 = TRUE;
		}
		password = nm_setting_802_1x_get_phase2_private_key_password (s_8021x);
	} else {
		if (nm_setting_802_1x_get_private_key_scheme (s_8021x) != NM_SETTING_802_1X_CK_SCHEME_UNKNOWN) {
			if (nm_setting_802_1x_get_private_key_format (s_8021x) == NM_SETTING_802_1X_CK_FORMAT_PKCS12)
				is_pkcs12 = TRUE;
		}
		password = nm_setting_802_1x_get_private_key_password (s_8021x);
	}

	if (is_pkcs12)
		otype = phase2 ? &phase2_p12_type : &p12_type;
	else
		otype = phase2 ? &phase2_pk_type : &pk_type;

	if ((*(otype->scheme_func))(s_8021x) == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			     "ifcfg-mdv does not support raw certificate data");
		return FALSE;
	//	blob = (*(otype->blob_func))(s_8021x);
	}

#if 0
	/* Only do the private key re-encrypt dance if we got the raw key data, which
	 * by definition will be unencrypted.  If we're given a direct path to the
	 * private key file, it'll be encrypted, so we don't need to re-encrypt.
	 */
	if (blob && !is_pkcs12) {
		/* Encrypt the unencrypted private key with the fake password */
		enc_key = nm_utils_rsa_key_encrypt (blob, password, &generated_pw, error);
		if (!enc_key)
			goto out;

		if (generated_pw)
			password = generated_pw;
	}
#endif

	/* Save the private key */
	if (!write_object (s_8021x, wpan, ifcfg, enc_key ? enc_key : blob, otype, error))
		goto out;

	/* Private key password */
	/* FIXME what about hash:XXX? */
	if (phase2)
		ifcfg_mdv_wpa_network_set_str(wpan, "private_key2_passwd", password);
	else
		ifcfg_mdv_wpa_network_set_str(wpan, "private_key_passwd", password);

	/* Client certificate */
	if (is_pkcs12) {
		ifcfg_mdv_wpa_network_unset(wpan,
		            phase2 ? "client_cert2" : "client_cert");
	} else {
		if (phase2)
			otype = &phase2_client_type;
		else
			otype = &client_type;

		/* Save the client certificate */
		if (!write_object (s_8021x, wpan, ifcfg, NULL, otype, error))
			goto out;
	}

	success = TRUE;

out:
#if 0
	if (generated_pw) {
		memset (generated_pw, 0, strlen (generated_pw));
		g_free (generated_pw);
	}
	if (enc_key) {
		memset (enc_key->data, 0, enc_key->len);
		g_byte_array_free (enc_key, TRUE);
	}
#endif
	return success;
}

static gboolean
write_8021x_setting (NMConnection *connection,
		     WPANetwork *wpan,
                     shvarFile *ifcfg,
                     gboolean wired,
                     GError **error)
{
	NMSetting8021x *s_8021x;
	const char *value;
	char *tmp = NULL;
	gboolean success = FALSE;
	GString *phase2_auth;
	GString *str;

	s_8021x = (NMSetting8021x *) nm_connection_get_setting (connection, NM_TYPE_SETTING_802_1X);
	if (!s_8021x) {
#if 0
		/* No wired security in Mandriva */
		/* If wired, clear KEY_MGMT */
		if (wired)
			svSetValue (ifcfg, "KEY_MGMT", NULL, FALSE);
#endif
		return TRUE;
	}

#if 0
		/* No wired security in Mandriva */
	/* If wired, write KEY_MGMT */
	if (wired)
		svSetValue (ifcfg, "KEY_MGMT", "IEEE8021X", FALSE);
#endif

	/* EAP method */
	if (nm_setting_802_1x_get_num_eap_methods (s_8021x)) {
		value = nm_setting_802_1x_get_eap_method (s_8021x, 0);
		if (value)
			tmp = g_ascii_strup (value, -1);
	}
	ifcfg_mdv_wpa_network_set_val(wpan, "eap", tmp ? tmp : NULL);
	g_free (tmp);

	ifcfg_mdv_wpa_network_set_str(wpan, "identity",
	            nm_setting_802_1x_get_identity (s_8021x));

	ifcfg_mdv_wpa_network_set_str(wpan, "anonymous_identity",
	            nm_setting_802_1x_get_anonymous_identity (s_8021x));

	ifcfg_mdv_wpa_network_set_str(wpan, "password", nm_setting_802_1x_get_password (s_8021x));

	str = g_string_new("");

	/* PEAP version */
	value = nm_setting_802_1x_get_phase1_peapver (s_8021x);
	if (value && (!strcmp (value, "0") || !strcmp (value, "1")))
		g_string_printf(str, "peapver=%s", value);

	/* Force new PEAP label */
	value = nm_setting_802_1x_get_phase1_peaplabel (s_8021x);
	if (value && !strcmp (value, "1")) {
		if (str->len)
			g_string_append_c(str, ' ');
		g_string_printf(str, "peaplabel=%s", value);
	}

	if (str->len)
		ifcfg_mdv_wpa_network_set_str(wpan, "phase1", str->str);
	g_string_free(str, TRUE);

	/* Phase2 auth methods */
	phase2_auth = g_string_new (NULL);

	value = nm_setting_802_1x_get_phase2_auth (s_8021x);
	if (value) {
		tmp = g_ascii_strup (value, -1);
		g_string_printf (phase2_auth, "auth=%s", tmp);
		g_free (tmp);
	}

	value = nm_setting_802_1x_get_phase2_autheap (s_8021x);
	if (value) {
		if (phase2_auth->len)
			g_string_append_c (phase2_auth, ' ');

		tmp = g_ascii_strup (value, -1);
		g_string_append_printf (phase2_auth, "autheap=%s", tmp);
		g_free (tmp);
	}

	if (phase2_auth->len)
		ifcfg_mdv_wpa_network_set_str(wpan, "phase2", phase2_auth->str);
	g_string_free (phase2_auth, TRUE);

	success = write_8021x_certs (s_8021x, wpan, FALSE, ifcfg, error);
	if (success) {
		/* phase2/inner certs */
		success = write_8021x_certs (s_8021x, wpan, TRUE, ifcfg, error);
	}

	return success;
}

static gboolean
write_wireless_security_setting (NMConnection *connection,
                                 shvarFile *ifcfg,
				 WPANetwork *wpan,
                                 gboolean adhoc,
                                 gboolean *no_8021x,
                                 GError **error)
{
	NMSettingWirelessSecurity *s_wsec;
	const char *key_mgmt, *auth_alg, *key, *proto, *cipher;
	gboolean wep = FALSE, wpa = FALSE;
	char *tmp;
	guint32 i, num;
	GString *str;

	s_wsec = (NMSettingWirelessSecurity *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY);
	if (!s_wsec) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing '%s' setting", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
		return FALSE;
	}

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	g_assert (key_mgmt);

	auth_alg = nm_setting_wireless_security_get_auth_alg (s_wsec);

	// svSetValue (ifcfg, "DEFAULTKEY", NULL, FALSE);

	if (!strcmp (key_mgmt, "none")) {
		wep = TRUE;
		*no_8021x = TRUE;
	} else if (!strcmp (key_mgmt, "wpa-none") || !strcmp (key_mgmt, "wpa-psk")) {
		ifcfg_mdv_wpa_network_set_val(wpan, "key_mgmt", "WPA-PSK");
		wpa = TRUE;
		*no_8021x = TRUE;
	} else if (!strcmp (key_mgmt, "ieee8021x")) {
		ifcfg_mdv_wpa_network_set_val(wpan, "key_mgmt", "IEEE8021X");
	} else if (!strcmp (key_mgmt, "wpa-eap")) {
		ifcfg_mdv_wpa_network_set_val(wpan, "key_mgmt", "WPA-EAP");
		wpa = TRUE;
	}

	/* TODO add additional fields to private object to store extra
	 * values during parsing configuration */
	if (strcmp(key_mgmt, "none"))
		ifcfg_mdv_wpa_network_set_val(wpan, "priority", "1");

	svSetValue (ifcfg, "WIRELESS_ENC_MODE", NULL, FALSE);
	if (auth_alg) {
		if (!strcmp (auth_alg, "shared")) {
			if (wep)
				svSetValue (ifcfg, "WIRELESS_ENC_MODE", "restricted", FALSE);
			ifcfg_mdv_wpa_network_set_val(wpan, "auth_alg", "SHARED");
		} else if (!strcmp (auth_alg, "open")) {
			if (wep)
				svSetValue (ifcfg, "WIRELESS_ENC_MODE", "open", FALSE);
			ifcfg_mdv_wpa_network_set_val(wpan, "auth_alg", "OPEN");
		} else if (!strcmp (auth_alg, "leap")) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
				     "ifcfg-mdv does not support LEAP authentication");
			return FALSE;
#if 0
			/* Not used by Mandriva */
			svSetValue (ifcfg, "WIRELESS_ENC_MODE", "leap", FALSE);
			svSetValue (ifcfg, "IEEE_8021X_IDENTITY",
			            nm_setting_wireless_security_get_leap_username (s_wsec),
			            FALSE);
				     "ifcfg-mdv does not support LEAP authentication");
			set_secret (ifcfg, "IEEE_8021X_PASSWORD",
			            nm_setting_wireless_security_get_leap_password (s_wsec),
			            FALSE);
			*no_8021x = TRUE;
#endif
		}
	}

	set_wep_secret (ifcfg, "WIRELESS_ENC_KEY", NULL, FALSE);
	if (wep) {
		/* Mandriva always sets key_idx == 0 and does not support passphrase */
		if (nm_setting_wireless_security_get_wep_key_type (s_wsec) == NM_WEP_KEY_TYPE_PASSPHRASE) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
				"ifcfg-mdv does not support WEP passphrase");
			return FALSE;
		}
		key = nm_setting_wireless_security_get_wep_key (s_wsec, 0);
		set_wep_secret (ifcfg, "WIRELESS_ENC_KEY", key, FALSE);
#if 0
		/* Default WEP TX key index */
		tmp = g_strdup_printf ("%d", nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec) + 1);
		svSetValue (ifcfg, "DEFAULTKEY", tmp, FALSE);
		g_free (tmp);
		for (i = 0; i < 4; i++) {
			NMWepKeyType key_type;

			key = nm_setting_wireless_security_get_wep_key (s_wsec, i);
			if (key) {
				char *ascii_key = NULL;

				/* Passphrase needs a different ifcfg key since with WEP, there
				 * are some passphrases that are indistinguishable from WEP hex
				 * keys.
				 */
				key_type = nm_setting_wireless_security_get_wep_key_type (s_wsec);
				if (key_type == NM_WEP_KEY_TYPE_PASSPHRASE)
					tmp = g_strdup_printf ("KEY_PASSPHRASE%d", i + 1);
				else {
					tmp = g_strdup_printf ("KEY%d", i + 1);

					/* Add 's:' prefix for ASCII keys */
					if (strlen (key) == 5 || strlen (key) == 13) {
						ascii_key = g_strdup_printf ("s:%s", key);
						key = ascii_key;
					}
				}

				set_secret (ifcfg, tmp, key, FALSE);
				g_free (tmp);
				g_free (ascii_key);
			}
		}
#endif
	}

	/* FIXME What about roaming mode? */
	if (wep) {
		/* remove WPA driver to indicate WEP mode */
		svSetValue (ifcfg, "WIRELESS_WPA_DRIVER", NULL, FALSE);

		/* remove network from wpa_suplicant.conf */
		ifcfg_mdv_wpa_network_set_val(wpan, "__DELETE__", "yes");

		return TRUE;
	}

	/* wpa_supplicant driver. NM always uses wext for wireless */
	svSetValue (ifcfg, "WIRELESS_WPA_DRIVER", "wext", FALSE);

	/* WPA protos */
	str = g_string_new (NULL);
	num = nm_setting_wireless_security_get_num_protos (s_wsec);
	for (i = 0; i < num; i++) {
		gchar *p = NULL;

		proto = nm_setting_wireless_security_get_proto (s_wsec, i);
		if (proto && !strcmp (proto, "wpa"))
			p = "WPA";
		else if (proto && !strcmp (proto, "rsn"))
			p = "RSN";
		if (p) {
			if (i > 0)
				g_string_append_c(str, ' ');
			g_string_append(str, p);
		}
	}
	if (strlen (str->str))
		ifcfg_mdv_wpa_network_set_val(wpan, "proto", str->str);

	/* WPA Pairwise ciphers */
	g_string_set_size (str, 0);
	num = nm_setting_wireless_security_get_num_pairwise (s_wsec);
	for (i = 0; i < num; i++) {
		if (i > 0)
			g_string_append_c (str, ' ');
		cipher = nm_setting_wireless_security_get_pairwise (s_wsec, i);
		tmp = g_ascii_strup (cipher, -1);
		g_string_append (str, tmp);
		g_free (tmp);
	}
	if (strlen (str->str))
		ifcfg_mdv_wpa_network_set_val(wpan, "pairwise", str->str);

	/* WPA Group ciphers */
	g_string_set_size (str, 0);
	num = nm_setting_wireless_security_get_num_groups (s_wsec);
	for (i = 0; i < num; i++) {
		if (i > 0)
			g_string_append_c (str, ' ');
		cipher = nm_setting_wireless_security_get_group (s_wsec, i);
		tmp = g_ascii_strup (cipher, -1);
		g_string_append (str, tmp);
		g_free (tmp);
	}
	if (strlen (str->str))
		ifcfg_mdv_wpa_network_set_val(wpan, "group", str->str);


	/* WPA Passphrase */
	if (wpa) {
		const char *psk = nm_setting_wireless_security_get_psk(s_wsec);
		if (psk) {
			g_string_assign(str, psk);
			if (str->len != 64) {
				/* Quote the PSK since it's a passphrase */
				g_string_prepend_c (str, '"');
				g_string_append_c (str, '"');
			}

			ifcfg_mdv_wpa_network_set_val(wpan, "psk", str->str);
		}
	}
	g_string_free (str, TRUE);

	return TRUE;
}

static gboolean
write_wireless_setting (NMConnection *connection,
                        shvarFile *ifcfg,
			WPANetwork *wpan,
                        gboolean *no_8021x,
                        GError **error)
{
	NMSettingWireless *s_wireless;
	char *tmp = NULL;
	const GByteArray *ssid, *device_mac, *cloned_mac, *bssid;
	GByteArray *old_ssid = NULL;
	const char *mode;
	guint32 mtu, chan, i;
	gboolean adhoc = FALSE;
	gchar buf[33];

	s_wireless = (NMSettingWireless *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS);
	if (!s_wireless) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing '%s' setting", NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}

	svSetValue (ifcfg, "HWADDR", NULL, FALSE);
	device_mac = nm_setting_wireless_get_mac_address (s_wireless);
	if (device_mac) {
		tmp = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
		                       device_mac->data[0], device_mac->data[1], device_mac->data[2],
		                       device_mac->data[3], device_mac->data[4], device_mac->data[5]);
		svSetValue (ifcfg, "HWADDR", tmp, FALSE);
		g_free (tmp);
	}

	svSetValue (ifcfg, "MACADDR", NULL, FALSE);
	cloned_mac = nm_setting_wireless_get_cloned_mac_address (s_wireless);
	if (cloned_mac) {
		tmp = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
		                       cloned_mac->data[0], cloned_mac->data[1], cloned_mac->data[2],
		                       cloned_mac->data[3], cloned_mac->data[4], cloned_mac->data[5]);
		svSetValue (ifcfg, "MACADDR", tmp, FALSE);
		g_free (tmp);
	}

	svSetValue (ifcfg, "MTU", NULL, FALSE);
	mtu = nm_setting_wireless_get_mtu (s_wireless);
	if (mtu) {
		tmp = g_strdup_printf ("%u", mtu);
		svSetValue (ifcfg, "MTU", tmp, FALSE);
		g_free (tmp);
	}

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	if (!ssid) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing SSID in '%s' setting", NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}
	if (!ssid->len || ssid->len > 32) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Invalid SSID in '%s' setting", NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}

	/*
	 * Mandriva is using SSID as part of file name; check for characters
	 * that cannot included */
	for (i = 0; i < ssid->len; i++)
		if (G_DIR_SEPARATOR == ssid->data[i] || ssid->data[i] == '\0') {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
				     "Invalid SSID in '%s' setting", NM_SETTING_WIRELESS_SETTING_NAME);
			return FALSE;
		}

	/*
	 * If SID changed we have to remove it from wpa_supplicant.conf
	 */
	tmp = svGetValue(ifcfg, "WIRELESS_ESSID", TRUE);
	if (!tmp) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		     "Missing WIRELESS_ESSID in '%s'", ifcfg->fileName);
		return FALSE;
	}
	old_ssid = ifcfg_mdv_parse_ssid(tmp, error);
	if (!old_ssid)
		goto free;

	if (ssid->len != old_ssid->len || !memcmp(ssid->data, old_ssid->data, ssid->len)) {
		WPANetwork *del = ifcfg_mdv_wpa_network_new(NULL);

		if (!del) {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: could not allocate WPANetwork to remove SSID '%s'",
		             tmp);
			goto free;
		}

		ifcfg_mdv_wpa_network_set_ssid(del, old_ssid);
		ifcfg_mdv_wpa_network_set_val(del, "__DELETE__", "yes");
		ifcfg_mdv_wpa_network_save(del, "/etc/wpa_supplicant.conf", error);
		ifcfg_mdv_wpa_network_free(del);
		if (*error) {
			goto free;
		}
	}
	g_free(tmp);
	g_byte_array_free(old_ssid, TRUE);

	/* we just verified that it does not contain '\0' and fits in buf */
	memcpy(buf, ssid->data, ssid->len);
	buf[ssid->len] = '\0';
	tmp = svEscape(buf);
	svSetValue (ifcfg, "WIRELESS_ESSID", tmp, TRUE);
	g_free(tmp);
	ifcfg_mdv_wpa_network_set_ssid(wpan, ssid);

	mode = nm_setting_wireless_get_mode (s_wireless);
	if (!mode || !strcmp (mode, "infrastructure")) {
		svSetValue (ifcfg, "WIRELESS_MODE", "Managed", FALSE);
	} else if (!strcmp (mode, "adhoc")) {
		svSetValue (ifcfg, "WIRELESS_MODE", "Ad-Hoc", FALSE);
		adhoc = TRUE;
	} else {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Invalid mode '%s' in '%s' setting",
		             mode, NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}

	svSetValue (ifcfg, "WIRELESS_CHANNEL", NULL, FALSE);
	chan = nm_setting_wireless_get_channel (s_wireless);
	if (chan) {
		tmp = g_strdup_printf ("%u", chan);
		svSetValue (ifcfg, "WIRELESS_CHANNEL", tmp, FALSE);
		g_free (tmp);
	}

	if (nm_setting_wireless_get_security (s_wireless)) {
		if (!write_wireless_security_setting (connection, ifcfg, wpan, adhoc, no_8021x, error))
			return FALSE;
	}

	// svSetValue (ifcfg, "BSSID", NULL, FALSE);
	bssid = nm_setting_wireless_get_bssid (s_wireless);
	if (bssid) {
		tmp = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
				       bssid->data[0], bssid->data[1], bssid->data[2],
				       bssid->data[3], bssid->data[4], bssid->data[5]);
		ifcfg_mdv_wpa_network_set_val(wpan, "bssid", tmp);
		// svSetValue (ifcfg, "BSSID", tmp, FALSE);
		g_free (tmp);
	}


	// svSetValue (ifcfg, "TYPE", TYPE_WIRELESS, FALSE);

	return TRUE;
free:
	g_free(tmp);
	if (old_ssid)
		g_byte_array_free(old_ssid, TRUE);

	return FALSE;
}

static gboolean
write_wired_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingWired *s_wired;
	const GByteArray *device_mac, *cloned_mac;
	char *tmp;
	guint32 mtu;

	s_wired = (NMSettingWired *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED);
	if (!s_wired) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing '%s' setting", NM_SETTING_WIRED_SETTING_NAME);
		return FALSE;
	}

	device_mac = nm_setting_wired_get_mac_address (s_wired);
	if (device_mac) {
		tmp = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
		                       device_mac->data[0], device_mac->data[1], device_mac->data[2],
		                       device_mac->data[3], device_mac->data[4], device_mac->data[5]);
		svSetValue (ifcfg, "HWADDR", tmp, FALSE);
		g_free (tmp);
	}

	cloned_mac = nm_setting_wired_get_cloned_mac_address (s_wired);
	if (cloned_mac) {
		tmp = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
		                       cloned_mac->data[0], cloned_mac->data[1], cloned_mac->data[2],
		                       cloned_mac->data[3], cloned_mac->data[4], cloned_mac->data[5]);
		svSetValue (ifcfg, "MACADDR", tmp, FALSE);
		g_free (tmp);
	}

	svSetValue (ifcfg, "MTU", NULL, FALSE);
	mtu = nm_setting_wired_get_mtu (s_wired);
	if (mtu) {
		tmp = g_strdup_printf ("%u", mtu);
		svSetValue (ifcfg, "MTU", tmp, FALSE);
		g_free (tmp);
	}

	// svSetValue (ifcfg, "TYPE", TYPE_ETHERNET, FALSE);

	return TRUE;
}

static void
write_connection_setting (NMSettingConnection *s_con, shvarFile *ifcfg)
{
	char *tmp;

	svSetValue (ifcfg, "NAME", nm_setting_connection_get_id (s_con), FALSE);
	svSetValue (ifcfg, "UUID", nm_setting_connection_get_uuid (s_con), FALSE);
	/* when converting from eralier ifcfg */
	svSetValue (ifcfg, "_NM_ONBOOT", NULL, FALSE);
	svSetValue (ifcfg, "ONBOOT",
	            nm_setting_connection_get_autoconnect (s_con) ? "yes" : "no",
	            FALSE);

	svSetValue (ifcfg, "LAST_CONNECT", NULL, FALSE);
	if (nm_setting_connection_get_timestamp (s_con)) {
		tmp = g_strdup_printf ("%" G_GUINT64_FORMAT, nm_setting_connection_get_timestamp (s_con));
		svSetValue (ifcfg, "LAST_CONNECT", tmp, FALSE);
		g_free (tmp);
	}
}

#if 0
No route file on Mandriva
static gboolean
write_route_file_legacy (const char *filename, NMSettingIP4Config *s_ip4, GError **error)
{
	char dest[INET_ADDRSTRLEN];
	char next_hop[INET_ADDRSTRLEN];
	char **route_items;
	char *route_contents;
	NMIP4Route *route;
	guint32 ip, prefix, metric;
	guint32 i, num;
	gboolean success = FALSE;

	g_return_val_if_fail (filename != NULL, FALSE);
	g_return_val_if_fail (s_ip4 != NULL, FALSE);
	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	num = nm_setting_ip4_config_get_num_routes (s_ip4);
	if (num == 0) {
		unlink (filename);
		return TRUE;
	}

	route_items = g_malloc0 (sizeof (char*) * (num + 1));
	for (i = 0; i < num; i++) {
		route = nm_setting_ip4_config_get_route (s_ip4, i);

		memset (dest, 0, sizeof (dest));
		ip = nm_ip4_route_get_dest (route);
		inet_ntop (AF_INET, (const void *) &ip, &dest[0], sizeof (dest));

		prefix = nm_ip4_route_get_prefix (route);

		memset (next_hop, 0, sizeof (next_hop));
		ip = nm_ip4_route_get_next_hop (route);
		inet_ntop (AF_INET, (const void *) &ip, &next_hop[0], sizeof (next_hop));

		metric = nm_ip4_route_get_metric (route);

		route_items[i] = g_strdup_printf ("%s/%u via %s metric %u\n", dest, prefix, next_hop, metric);
	}
	route_items[num] = NULL;
	route_contents = g_strjoinv (NULL, route_items);
	g_strfreev (route_items);

	if (!g_file_set_contents (filename, route_contents, -1, NULL)) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Writing route file '%s' failed", filename);
		goto error;
	}

	success = TRUE;

error:
	g_free (route_contents);

	return success;
}
#endif

static char *
ip4_address_as_string (guint32 ip)
{
	char *ip_string;
	struct in_addr tmp_addr;

	tmp_addr.s_addr = ip;
	ip_string = g_malloc0 (INET_ADDRSTRLEN + 1);
	if (!inet_ntop (AF_INET, &tmp_addr, ip_string, INET_ADDRSTRLEN))
	strcpy (ip_string, "(none)");
	return ip_string;
}

static gboolean
write_ip4_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingIP4Config *s_ip4;
	const char *value;
	char *addr_key, *prefix_key, *netmask_key, *gw_key, /**metric_key,*/ *tmp;
	// char *route_path = NULL;
	guint32 i, num;
	GString *searches;
	gboolean success = FALSE;
	gboolean fake_ip4 = FALSE;
	const char *method = NULL;

	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (s_ip4)
		method = nm_setting_ip4_config_get_method (s_ip4);

	/* Missing IP4 setting is assumed to be DHCP */
	if (!method)
		method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;

	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
		/* IPv4 disabled, clear IPv4 related parameters */
		svSetValue (ifcfg, "BOOTPROTO", NULL, FALSE);
		for (i = 0; i < 254; i++) {
			if (i == 0) {
				addr_key = g_strdup ("IPADDR");
				prefix_key = g_strdup ("PREFIX");
				gw_key = g_strdup ("GATEWAY");
			} else {
				addr_key = g_strdup_printf ("IPADDR%d", i + 1);
				prefix_key = g_strdup_printf ("PREFIX%d", i + 1);
				gw_key = g_strdup_printf ("GATEWAY%d", i + 1);
			}

			svSetValue (ifcfg, addr_key, NULL, FALSE);
			svSetValue (ifcfg, prefix_key, NULL, FALSE);
			svSetValue (ifcfg, gw_key, NULL, FALSE);
		}

#if 0
		/* no routes on Mandriva */
		route_path = utils_get_route_path (ifcfg->fileName);
		result = unlink (route_path);
		g_free (route_path);
#endif
		return TRUE;
	}

	/* Temporarily create fake IP4 setting if missing; method set to DHCP above */
	if (!s_ip4) {
		s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
		fake_ip4 = TRUE;
	}

	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO))
		svSetValue (ifcfg, "BOOTPROTO", "dhcp", FALSE);
	else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL))
		svSetValue (ifcfg, "BOOTPROTO", "static", FALSE);
#if 0
	else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL))
		svSetValue (ifcfg, "BOOTPROTO", "autoip", FALSE);
	else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED))
		svSetValue (ifcfg, "BOOTPROTO", "shared", FALSE);
#endif
	else {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "ifcfg-mdv: unsupported activation method '%s'", value);
		goto out;
	}

	num = nm_setting_ip4_config_get_num_addresses (s_ip4);
	if (num > 1) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		     "ifcfg-mdv: multiple IPADDRs per interface are not supported");
			goto out;
	}
	//for (i = 0; i < 254; i++) {
	{
		char buf[INET_ADDRSTRLEN + 1];
		NMIP4Address *addr;
		guint32 ip, netmask;

		// if (i == 0) {
			addr_key = g_strdup ("IPADDR");
			prefix_key = g_strdup ("PREFIX");
			netmask_key = g_strdup ("NETMASK");
			gw_key = g_strdup ("GATEWAY");
#if 0
		} else {
			addr_key = g_strdup_printf ("IPADDR%d", i + 1);
			prefix_key = g_strdup_printf ("PREFIX%d", i + 1);
			gw_key = g_strdup_printf ("GATEWAY%d", i + 1);
		}
#endif
		/* Clean PREFIX in case it was present, otherwise it
		 * will fool reader.c next time */
		svSetValue (ifcfg, prefix_key, NULL, FALSE);

		// if (i >= num) {
		if (num == 0) {
			svSetValue (ifcfg, addr_key, NULL, FALSE);
			svSetValue (ifcfg, netmask_key, NULL, FALSE);
			svSetValue (ifcfg, gw_key, NULL, FALSE);
		} else {
			addr = nm_setting_ip4_config_get_address (s_ip4, i);

			memset (buf, 0, sizeof (buf));
			ip = nm_ip4_address_get_address (addr);
			inet_ntop (AF_INET, (const void *) &ip, &buf[0], sizeof (buf));
			svSetValue (ifcfg, addr_key, &buf[0], FALSE);

			netmask = nm_utils_ip4_prefix_to_netmask (nm_ip4_address_get_prefix (addr));
			tmp = ip4_address_as_string(netmask);
			svSetValue (ifcfg, netmask_key, tmp, FALSE);
			g_free (tmp);

			if (nm_ip4_address_get_gateway (addr)) {
				memset (buf, 0, sizeof (buf));
				ip = nm_ip4_address_get_gateway (addr);
				inet_ntop (AF_INET, (const void *) &ip, &buf[0], sizeof (buf));
				svSetValue (ifcfg, gw_key, &buf[0], FALSE);
			} else
				svSetValue (ifcfg, gw_key, NULL, FALSE);
		}

		g_free (addr_key);
		g_free (prefix_key);
		g_free (netmask_key);
		g_free (gw_key);
	}

	num = nm_setting_ip4_config_get_num_dns (s_ip4);
	if (num > 2) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		     "ifcfg-mdv: max two DNS servers per interface are supported");
			goto out;
	}
	for (i = 0; i <= 2; i++) {
		char buf[INET_ADDRSTRLEN + 1];
		guint32 ip;

		addr_key = g_strdup_printf ("DNS%d", i + 1);

		if (i >= num)
			svSetValue (ifcfg, addr_key, NULL, FALSE);
		else {
			ip = nm_setting_ip4_config_get_dns (s_ip4, i);

			memset (buf, 0, sizeof (buf));
			inet_ntop (AF_INET, (const void *) &ip, &buf[0], sizeof (buf));
			svSetValue (ifcfg, addr_key, &buf[0], FALSE);
		}
		g_free (addr_key);
	}

	num = nm_setting_ip4_config_get_num_dns_searches (s_ip4);
	if (num > 0) {
		searches = g_string_new (NULL);
		for (i = 0; i < num; i++) {
			if (i > 0)
				g_string_append_c (searches, ' ');
			g_string_append (searches, nm_setting_ip4_config_get_dns_search (s_ip4, i));
		}
		svSetValue (ifcfg, "DOMAIN", searches->str, FALSE);
		g_string_free (searches, TRUE);
	} else
		svSetValue (ifcfg, "DOMAIN", NULL, FALSE);

	/*
	 * Mandriva supports DEFROUTE for PPP connections only, which are
	 * currently not implemented by ifcfg-mdv
	 */
	if (nm_setting_ip4_config_get_never_default (s_ip4)){
		PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: ignoring unsupported setting DEFROUTE=no");
	}
#if 0
	/* DEFROUTE; remember that it has the opposite meaning from never-default */
	svSetValue (ifcfg, "DEFROUTE",
	            nm_setting_ip4_config_get_never_default (s_ip4) ? "no" : "yes",
	            FALSE);
#endif

	/* Mandriva does not support PEERROUTES at all */
	svSetValue (ifcfg, "PEERDNS", NULL, FALSE);
	// svSetValue (ifcfg, "PEERROUTES", NULL, FALSE);
	svSetValue (ifcfg, "DHCP_HOSTNAME", NULL, FALSE);
	// svSetValue (ifcfg, "DHCP_CLIENT_ID", NULL, FALSE);
	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
		svSetValue (ifcfg, "PEERDNS",
		            nm_setting_ip4_config_get_ignore_auto_dns (s_ip4) ? "no" : "yes",
		            FALSE);

		if (nm_setting_ip4_config_get_ignore_auto_routes (s_ip4)) {
			PLUGIN_WARN (IFCFG_PLUGIN_NAME, "    warning: ignoring unsupported setting PEERROUTESno");
		}
#if 0
		svSetValue (ifcfg, "PEERROUTES",
		            nm_setting_ip4_config_get_ignore_auto_routes (s_ip4) ? "no" : "yes",
		            FALSE);
#endif

		value = nm_setting_ip4_config_get_dhcp_hostname (s_ip4);
		if (value)
			svSetValue (ifcfg, "DHCP_HOSTNAME", value, FALSE);

		/* Mandriva does not support client ID */
		value = nm_setting_ip4_config_get_dhcp_client_id (s_ip4);
		if (value) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			     "ifcfg-mdv: DHCP_CLIENT_ID is not supported");
				goto out;
			// svSetValue (ifcfg, "DHCP_CLIENT_ID", value, FALSE);
		}
	}

	svSetValue (ifcfg, "IPV4_FAILURE_FATAL",
	            nm_setting_ip4_config_get_may_fail (s_ip4) ? "no" : "yes",
	            FALSE);

#if 0
	No routes on Mandriva
	/* Static routes - route-<name> file */
	route_path = utils_get_route_path (ifcfg->fileName);
	if (!route_path) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Could not get route file path for '%s'", ifcfg->fileName);
		goto out;
	}
#endif

	num = nm_setting_ip4_config_get_num_routes (s_ip4);
	if (num > 0) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		     "ifcfg-mdv: static routes are not supported");
			goto out;
	}
#if 0
	if (utils_has_route_file_new_syntax (route_path)) {
		shvarFile *routefile;

		g_free (route_path);
		routefile = utils_get_route_ifcfg (ifcfg->fileName, TRUE);
		if (!routefile) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Could not create route file '%s'", routefile->fileName);
			goto out;
		}

		num = nm_setting_ip4_config_get_num_routes (s_ip4);
		for (i = 0; i < 256; i++) {
			char buf[INET_ADDRSTRLEN];
			NMIP4Route *route;
			guint32 ip, metric;

			addr_key = g_strdup_printf ("ADDRESS%d", i);
			netmask_key = g_strdup_printf ("NETMASK%d", i);
			gw_key = g_strdup_printf ("GATEWAY%d", i);
			metric_key = g_strdup_printf ("METRIC%d", i);

			if (i >= num) {
				svSetValue (routefile, addr_key, NULL, FALSE);
				svSetValue (routefile, netmask_key, NULL, FALSE);
				svSetValue (routefile, gw_key, NULL, FALSE);
				svSetValue (routefile, metric_key, NULL, FALSE);
			} else {
				route = nm_setting_ip4_config_get_route (s_ip4, i);

				memset (buf, 0, sizeof (buf));
				ip = nm_ip4_route_get_dest (route);
				inet_ntop (AF_INET, (const void *) &ip, &buf[0], sizeof (buf));
				svSetValue (routefile, addr_key, &buf[0], FALSE);

				memset (buf, 0, sizeof (buf));
				ip = nm_utils_ip4_prefix_to_netmask (nm_ip4_route_get_prefix (route));
				inet_ntop (AF_INET, (const void *) &ip, &buf[0], sizeof (buf));
				svSetValue (routefile, netmask_key, &buf[0], FALSE);

				memset (buf, 0, sizeof (buf));
				ip = nm_ip4_route_get_next_hop (route);
				inet_ntop (AF_INET, (const void *) &ip, &buf[0], sizeof (buf));
				svSetValue (routefile, gw_key, &buf[0], FALSE);

				memset (buf, 0, sizeof (buf));
				metric = nm_ip4_route_get_metric (route);
				if (metric == 0)
					svSetValue (routefile, metric_key, NULL, FALSE);
				else {
					tmp = g_strdup_printf ("%u", metric);
					svSetValue (routefile, metric_key, tmp, FALSE);
					g_free (tmp);
				}
			}

			g_free (addr_key);
			g_free (netmask_key);
			g_free (gw_key);
			g_free (metric_key);
		}
		if (svWriteFile (routefile, 0644)) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Could not update route file '%s'", routefile->fileName);
			svCloseFile (routefile);
			goto out;
		}
		svCloseFile (routefile);
	} else {
		write_route_file_legacy (route_path, s_ip4, error);
		g_free (route_path);
		if (error && *error)
			goto out;
	}
#endif

	success = TRUE;

out:
	if (fake_ip4)
		g_object_unref (s_ip4);

	return success;
}

#if 0
No IPv6 on Mandriva
static gboolean
write_route6_file (const char *filename, NMSettingIP6Config *s_ip6, GError **error)
{
	char dest[INET6_ADDRSTRLEN];
	char next_hop[INET6_ADDRSTRLEN];
	char **route_items;
	char *route_contents;
	NMIP6Route *route;
	const struct in6_addr *ip;
	guint32 prefix, metric;
	guint32 i, num;
	gboolean success = FALSE;

	g_return_val_if_fail (filename != NULL, FALSE);
	g_return_val_if_fail (s_ip6 != NULL, FALSE);
	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	num = nm_setting_ip6_config_get_num_routes (s_ip6);
	if (num == 0) {
		unlink (filename);
		return TRUE;
	}

	route_items = g_malloc0 (sizeof (char*) * (num + 1));
	for (i = 0; i < num; i++) {
		route = nm_setting_ip6_config_get_route (s_ip6, i);

		memset (dest, 0, sizeof (dest));
		ip = nm_ip6_route_get_dest (route);
		inet_ntop (AF_INET6, (const void *) ip, &dest[0], sizeof (dest));

		prefix = nm_ip6_route_get_prefix (route);

		memset (next_hop, 0, sizeof (next_hop));
		ip = nm_ip6_route_get_next_hop (route);
		inet_ntop (AF_INET6, (const void *) ip, &next_hop[0], sizeof (next_hop));

		metric = nm_ip6_route_get_metric (route);

		route_items[i] = g_strdup_printf ("%s/%u via %s metric %u\n", dest, prefix, next_hop, metric);
	}
	route_items[num] = NULL;
	route_contents = g_strjoinv (NULL, route_items);
	g_strfreev (route_items);

	if (!g_file_set_contents (filename, route_contents, -1, NULL)) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Writing route6 file '%s' failed", filename);
		goto error;
	}

	success = TRUE;

error:
	g_free (route_contents);
	return success;
}
#endif

static gboolean
write_ip6_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingIP6Config *s_ip6;
	// NMSettingIP4Config *s_ip4;
	const char *value;
#if 0
	char *addr_key, *prefix;
	guint32 i, num, num4;
	GString *searches;
	char buf[INET6_ADDRSTRLEN];
	NMIP6Address *addr;
	const struct in6_addr *ip;
	GString *ip_str1, *ip_str2, *ip_ptr;
	char *route6_path;
#endif

	s_ip6 = (NMSettingIP6Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP6_CONFIG);
	if (!s_ip6) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing '%s' setting", NM_SETTING_IP6_CONFIG_SETTING_NAME);
		return FALSE;
	}

	value = nm_setting_ip6_config_get_method (s_ip6);
	g_assert (value);
	if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)) {
#if 0
		svSetValue (ifcfg, "IPV6INIT", "no", FALSE);
		svSetValue (ifcfg, "DHCPV6C", NULL, FALSE);
#endif
		return TRUE;
#if 0
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_AUTO)) {
		svSetValue (ifcfg, "IPV6INIT", "yes", FALSE);
		svSetValue (ifcfg, "IPV6_AUTOCONF", "yes", FALSE);
		svSetValue (ifcfg, "DHCPV6C", NULL, FALSE);
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_DHCP)) {
		svSetValue (ifcfg, "IPV6INIT", "yes", FALSE);
		svSetValue (ifcfg, "IPV6_AUTOCONF", "no", FALSE);
		svSetValue (ifcfg, "DHCPV6C", "yes", FALSE);
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		svSetValue (ifcfg, "IPV6INIT", "yes", FALSE);
		svSetValue (ifcfg, "IPV6_AUTOCONF", "no", FALSE);
		svSetValue (ifcfg, "DHCPV6C", NULL, FALSE);
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL)) {
		svSetValue (ifcfg, "IPV6INIT", "yes", FALSE);
		svSetValue (ifcfg, "IPV6_AUTOCONF", "no", FALSE);
		svSetValue (ifcfg, "DHCPV6C", NULL, FALSE);
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_SHARED)) {
		svSetValue (ifcfg, "IPV6INIT", "yes", FALSE);
		svSetValue (ifcfg, "DHCPV6C", NULL, FALSE);
		/* TODO */
#endif
	}
	g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		     "IPv6 settings not supported");
	return FALSE;

#if 0
	if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		/* Write out IP addresses */
		num = nm_setting_ip6_config_get_num_addresses (s_ip6);

		ip_str1 = g_string_new (NULL);
		ip_str2 = g_string_new (NULL);
		for (i = 0; i < num; i++) {
			if (i == 0)
				ip_ptr = ip_str1;
			else
				ip_ptr = ip_str2;

			addr = nm_setting_ip6_config_get_address (s_ip6, i);
			ip = nm_ip6_address_get_address (addr);
			prefix = g_strdup_printf ("%u", nm_ip6_address_get_prefix (addr));
			memset (buf, 0, sizeof (buf));
			inet_ntop (AF_INET6, (const void *) ip, buf, sizeof (buf));
			if (i > 1)
				g_string_append_c (ip_ptr, ' ');  /* separate addresses in IPV6ADDR_SECONDARIES */
			g_string_append (ip_ptr, buf);
			g_string_append_c (ip_ptr, '/');
			g_string_append (ip_ptr, prefix);
			g_free (prefix);
		}

		svSetValue (ifcfg, "IPV6ADDR", ip_str1->str, FALSE);
		svSetValue (ifcfg, "IPV6ADDR_SECONDARIES", ip_str2->str, FALSE);
		g_string_free (ip_str1, TRUE);
		g_string_free (ip_str2, TRUE);
	} else {
		svSetValue (ifcfg, "IPV6ADDR", NULL, FALSE);
		svSetValue (ifcfg, "IPV6ADDR_SECONDARIES", NULL, FALSE);
	}

	/* Write out DNS - 'DNS' key is used both for IPv4 and IPv6 */
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	num4 = s_ip4 ? nm_setting_ip4_config_get_num_dns (s_ip4) : 0; /* from where to start with IPv6 entries */
	num = nm_setting_ip6_config_get_num_dns (s_ip6);
	for (i = 0; i < 254; i++) {
		addr_key = g_strdup_printf ("DNS%d", i + num4 + 1);

		if (i >= num)
			svSetValue (ifcfg, addr_key, NULL, FALSE);
		else {
			ip = nm_setting_ip6_config_get_dns (s_ip6, i);

			memset (buf, 0, sizeof (buf));
			inet_ntop (AF_INET6, (const void *) ip, buf, sizeof (buf));
			svSetValue (ifcfg, addr_key, buf, FALSE);
		}
		g_free (addr_key);
	}

	/* Write out DNS domains - 'DOMAIN' key is shared for both IPv4 and IPv6 domains */
	num = nm_setting_ip6_config_get_num_dns_searches (s_ip6);
	if (num > 0) {
		char *ip4_domains;
		ip4_domains = svGetValue (ifcfg, "DOMAIN", FALSE);
		searches = g_string_new (ip4_domains);
		for (i = 0; i < num; i++) {
			if (searches->len > 0)
				g_string_append_c (searches, ' ');
			g_string_append (searches, nm_setting_ip6_config_get_dns_search (s_ip6, i));
		}
		svSetValue (ifcfg, "DOMAIN", searches->str, FALSE);
		g_string_free (searches, TRUE);
		g_free (ip4_domains);
	}

	/* handle IPV6_DEFROUTE */
	/* IPV6_DEFROUTE has the opposite meaning from 'never-default' */
	if (nm_setting_ip6_config_get_never_default(s_ip6))
		svSetValue (ifcfg, "IPV6_DEFROUTE", "no", FALSE);
	else
		svSetValue (ifcfg, "IPV6_DEFROUTE", "yes", FALSE);

	svSetValue (ifcfg, "IPV6_PEERDNS", NULL, FALSE);
	svSetValue (ifcfg, "IPV6_PEERROUTES", NULL, FALSE);
	if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_AUTO)) {
		svSetValue (ifcfg, "IPV6_PEERDNS",
		            nm_setting_ip6_config_get_ignore_auto_dns (s_ip6) ? "no" : "yes",
		            FALSE);

		svSetValue (ifcfg, "IPV6_PEERROUTES",
		            nm_setting_ip6_config_get_ignore_auto_routes (s_ip6) ? "no" : "yes",
		            FALSE);
	}

	svSetValue (ifcfg, "IPV6_FAILURE_FATAL",
	            nm_setting_ip6_config_get_may_fail (s_ip6) ? "no" : "yes",
	            FALSE);

	/* Static routes go to route6-<dev> file */
	route6_path = utils_get_route6_path (ifcfg->fileName);
	if (!route6_path) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Could not get route6 file path for '%s'", ifcfg->fileName);
		goto error;
	}
	write_route6_file (route6_path, s_ip6, error);
	g_free (route6_path);
	if (error && *error)
		goto error;

	return TRUE;

error:
	return FALSE;
#endif
}

static char *
escape_id (const char *id)
{
	char *escaped = g_strdup (id);
	char *p = escaped;

	/* Escape random stuff */
	while (*p) {
		if (*p == ' ')
			*p = '_';
		else if (*p == '/')
			*p = '-';
		else if (*p == '\\')
			*p = '-';
		p++;
	}

	return escaped;
}

static gboolean
write_connection (NMConnection *connection,
                  const char *ifcfg_dir,
                  const char *filename,
                  const char *keyfile,
                  char **out_filename,
                  GError **error)
{
	NMSettingConnection *s_con;
	NMSettingIP6Config *s_ip6;
	gboolean success = FALSE;
	shvarFile *ifcfg = NULL;
	char *ifcfg_name = NULL;
	const char *type;
	gboolean no_8021x = FALSE;
	gboolean wired = FALSE;
	WPANetwork *wpan = NULL;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	if (!s_con) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing '%s' setting", NM_SETTING_CONNECTION_SETTING_NAME);
		return FALSE;
	}

	if (filename) {
		/* For existing connections, 'filename' should be full path to ifcfg file */
		ifcfg = svNewFile (filename);
		ifcfg_name = g_strdup (filename);
	} else {
		char *escaped;

		escaped = escape_id (nm_setting_connection_get_id (s_con));
		ifcfg_name = g_strdup_printf ("%s/ifcfg-%s", ifcfg_dir, escaped);
		ifcfg = svCreateFile (ifcfg_name);
		g_free (escaped);
	}

	if (!ifcfg) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Failed to open/create ifcfg file '%s'", ifcfg_name);
		goto out;
	}

	type = nm_setting_connection_get_connection_type (s_con);
	if (!type) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Missing connection type!");
		goto out;
	}

	/* Indicate that NM will manage this connection */
	svSetValue (ifcfg, "NM_CONTROLLED", "yes", FALSE);

	if (!strcmp (type, NM_SETTING_WIRED_SETTING_NAME)) {
		// FIXME: can't write PPPoE at this time
		if (nm_connection_get_setting (connection, NM_TYPE_SETTING_PPPOE)) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
			             "Can't write connection type '%s'",
			             NM_SETTING_PPPOE_SETTING_NAME);
			goto out;
		}

		if (!write_wired_setting (connection, ifcfg, error))
			goto out;
		wired = TRUE;
	} else if (!strcmp (type, NM_SETTING_WIRELESS_SETTING_NAME)) {
		wpan = ifcfg_mdv_wpa_network_new(NULL);
		if (!wpan) {
			g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
				     "Unable to allocate WPA network");
			goto out;
		}

		if (!write_wireless_setting (connection, ifcfg, wpan, &no_8021x, error))
			goto out;
	} else {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Can't write connection type '%s'", type);
		goto out;
	}

	if (!no_8021x) {
		if (!write_8021x_setting (connection, wpan, ifcfg, wired, error))
			goto out;
	}

	if (!write_ip4_setting (connection, ifcfg, error))
		goto out;

	s_ip6 = (NMSettingIP6Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP6_CONFIG);
	if (s_ip6) {
		if (!write_ip6_setting (connection, ifcfg, error))
			goto out;
	}

	write_connection_setting (s_con, ifcfg);

	if (svWriteFile (ifcfg, 0600)) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Can't write connection '%s'", ifcfg->fileName);
		goto out;
	}
	if (wpan)
		if (!ifcfg_mdv_wpa_network_save(wpan, "/etc/wpa_supplicant.conf", error)) {
		goto out;
		}


	/* Only return the filename if this was a newly written ifcfg */
	if (out_filename && !filename)
		*out_filename = g_strdup (ifcfg_name);

	success = TRUE;

out:
	if (ifcfg)
		svCloseFile (ifcfg);
	g_free (ifcfg_name);
	ifcfg_mdv_wpa_network_free(wpan);
	return success;
}

gboolean
writer_new_connection (NMConnection *connection,
                       const char *ifcfg_dir,
                       char **out_filename,
                       GError **error)
{
	// return write_connection (connection, ifcfg_dir, NULL, NULL, out_filename, error);
	/* For now, disable creation of system connection on Mandriva */
	g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
	     "Creation of system connection not yet implemented in ifcfg-mdv");
	return FALSE;
}

gboolean
writer_update_connection (NMConnection *connection,
                          const char *ifcfg_dir,
                          const char *filename,
                          const char *keyfile,
                          GError **error)
{
	/* Temporary disable updating of roaming connection */
	if (mdv_get_ifcfg_type(filename) != MdvIfcfgTypeInterface) {
		g_set_error (error, IFCFG_PLUGIN_ERROR, 0,
		             "Not yet implemented");
		return FALSE;
	}
	return write_connection (connection, ifcfg_dir, filename, keyfile, NULL, error);
}

