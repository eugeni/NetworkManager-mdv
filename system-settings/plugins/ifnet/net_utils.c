/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Mu Qiao <qiaomuf@gmail.com>
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
 * Copyright (C) 1999-2010 Gentoo Foundation, Inc.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <nm-utils.h>
#include <nm-system-config-interface.h>
#include "net_utils.h"
#include "wpa_parser.h"
#include "net_parser.h"

/* emit heading and tailing blank space, tab, character t */
gchar *
strip_string (gchar * str, gchar t)
{
	gchar *ret = str;
	gint length = 0;
	guint i = 0;

	while (ret[i] != '\0'
	       && (ret[i] == '\t' || ret[i] == ' ' || ret[i] == t)) {
		length++;
		i++;
	}
	i = 0;
	while (ret[i + length] != '\0') {
		ret[i] = ret[i + length];
		i++;
	}
	ret[i] = '\0';
	length = strlen (ret);
	while ((length - 1) >= 0
	       && (ret[length - 1] == ' ' || ret[length - 1] == '\n'
		   || ret[length - 1] == '\t' || ret[length - 1] == t))
		length--;
	ret[length] = '\0';
	return ret;
}

gboolean
is_hex (gchar * value)
{
	gchar *p;

	if (!value)
		return FALSE;
	p = value;
	while (*p) {
		if (!isxdigit (*p)) {
			return FALSE;
		}
		p++;
	}
	return TRUE;
}

gboolean
is_ascii (gchar * value)
{
	gchar *p;

	p = value;
	while (*p) {
		if (!isascii (*p)) {
			return FALSE;
		}
		p++;
	}
	return TRUE;

}

gboolean
is_true (char *str)
{
	if (!g_ascii_strcasecmp (str, "yes")
	    || !g_ascii_strcasecmp (str, "true"))
		return TRUE;
	return FALSE;
}

static int
hex2num (char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int
hex2byte (const char *hex)
{
	int a, b;

	a = hex2num (*hex++);
	if (a < 0)
		return -1;
	b = hex2num (*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

/* free return value by caller */
gchar *
utils_hexstr2bin (const gchar * hex, size_t len)
{
	size_t i;
	int a;
	const gchar *ipos = hex;
	gchar *buf = NULL;
	gchar *opos;

	/* Length must be a multiple of 2 */
	if ((len % 2) != 0)
		return NULL;

	opos = buf = g_malloc0 ((len / 2) + 1);
	for (i = 0; i < len; i += 2) {
		a = hex2byte (ipos);
		if (a < 0) {
			g_free (buf);
			return NULL;
		}
		*opos++ = a;
		ipos += 2;
	}
	return buf;
}

/* free return value by caller */
gchar *
utils_bin2hexstr (const gchar * bytes, int len, int final_len)
{
	static gchar hex_digits[] = "0123456789abcdef";
	gchar *result;
	int i;
	gsize buflen = (len * 2) + 1;

	g_return_val_if_fail (bytes != NULL, NULL);
	g_return_val_if_fail (len > 0, NULL);
	g_return_val_if_fail (len < 4096, NULL);	/* Arbitrary limit */
	if (final_len > -1)
		g_return_val_if_fail (final_len < buflen, NULL);

	result = g_malloc0 (buflen);
	for (i = 0; i < len; i++) {
		result[2 * i] = hex_digits[(bytes[i] >> 4) & 0xf];
		result[2 * i + 1] = hex_digits[bytes[i] & 0xf];
	}
	/* Cut converted key off at the correct length for this cipher type */
	if (final_len > -1)
		result[final_len] = '\0';
	else
		result[buflen - 1] = '\0';

	return result;
}

GQuark
ifnet_plugin_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark =
		    g_quark_from_static_string ("ifnet-plugin-error-quark");
	return error_quark;
}

static char *
find_default_gateway_str (char *str)
{
	char *tmp;

	if ((tmp = strstr (str, "default via ")) != NULL) {
		return tmp + strlen ("default via ");
	} else if ((tmp = strstr (str, "default gw ")) != NULL) {
		return tmp + strlen ("default gw ");
	}
	return NULL;
}

static char *
find_gateway_str (char *str)
{
	char *tmp;

	if ((tmp = strstr (str, "via ")) != NULL) {
		return tmp + strlen ("via ");
	} else if ((tmp = strstr (str, "gw ")) != NULL) {
		return tmp + strlen ("gw ");
	}
	return NULL;
}

gboolean
reload_parsers ()
{
	ifnet_destroy ();
	wpa_parser_destroy ();
	if (!ifnet_init (CONF_NET_FILE))
		return FALSE;
	wpa_parser_init (WPA_SUPPLICANT_CONF);
	return TRUE;
}

gchar *
read_hostname (gchar * path)
{
	gchar *contents = NULL, *result = NULL, *tmp;
	gchar **all_lines = NULL;
	guint line_num, i;

	if (!g_file_get_contents (path, &contents, NULL, NULL))
		return NULL;
	all_lines = g_strsplit (contents, "\n", 0);
	line_num = g_strv_length (all_lines);
	for (i = 0; i < line_num; i++) {
		g_strstrip (all_lines[i]);
		if (all_lines[i][0] == '#' || all_lines[i][0] == '\0')
			continue;
		if (g_str_has_prefix (all_lines[i], "hostname")) {
			tmp = strstr (all_lines[i], "=");
			tmp++;
			tmp = strip_string (tmp, '"');
			result = g_strdup (tmp);
			break;
		}

	}
	g_strfreev (all_lines);
	g_free (contents);
	return result;
}

gboolean
write_hostname (const gchar * hostname, gchar * path)
{
	gchar *contents = g_strdup_printf ("#Generated by NetworkManager\n"
					   "hostname=\"%s\"\n", hostname);
	gboolean result = g_file_set_contents (path, contents, -1, NULL);

	g_free (contents);
	return result;
}

gboolean
is_static_ip4 (gchar * conn_name)
{
	gchar *data = ifnet_get_data (conn_name, "config");
	gchar *dhcp6;

	if (!data)
		return FALSE;
	dhcp6 = strstr (data, "dhcp6");
	if (dhcp6) {
		gchar *dhcp4;

		if (strstr (data, "dhcp "))
			return FALSE;
		dhcp4 = strstr (data, "dhcp");
		if (!dhcp4)
			return TRUE;
		if (dhcp4[4] == '\0')
			return FALSE;
		return TRUE;
	}
	return strstr (data, "dhcp") == NULL ? TRUE : FALSE;
}

gboolean
is_static_ip6 (gchar * conn_name)
{
	gchar *data = ifnet_get_data (conn_name, "config");

	if (!data)
		return TRUE;
	return strstr (data, "dhcp6") == NULL ? TRUE : FALSE;
}

gboolean
is_ip4_address (gchar * in_address)
{
	gchar *pattern =
	    "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.((\\{\\d{1,3}\\.\\.\\d{1,3}\\})|\\d{1,3})$";
	gchar *address = g_strdup (in_address);
	gboolean result = FALSE;
	gchar *tmp;
	GRegex *regex = g_regex_new (pattern, 0, 0, NULL);
	GMatchInfo *match_info;

	if (!address)
		goto done;
	g_strstrip (address);
	if ((tmp = strstr (address, "/")) != NULL)
		*tmp = '\0';
	if ((tmp = strstr (address, " ")) != NULL)
		*tmp = '\0';
	g_regex_match (regex, address, 0, &match_info);
	result = g_match_info_matches (match_info);
      done:
	if (match_info)
		g_match_info_free (match_info);
	g_regex_unref (regex);
	g_free (address);
	return result;
}

gboolean
is_ip6_address (gchar * in_address)
{
	struct in6_addr tmp_ip6_addr;
	gchar *tmp;
	gchar *address = g_strdup (in_address);
	gboolean result = FALSE;

	if (!address) {
		g_free (address);
		return FALSE;
	}
	g_strstrip (address);
	if ((tmp = strchr (address, '/')) != NULL)
		*tmp = '\0';
	if (inet_pton (AF_INET6, address, &tmp_ip6_addr))
		result = TRUE;
	g_free (address);
	return result;

}

gboolean
has_ip6_address (gchar * conn_name)
{
	gchar **ipset;
	guint length;
	guint i;

	g_return_val_if_fail (conn_name != NULL, FALSE);
	ipset = g_strsplit (ifnet_get_data (conn_name, "config"), "\" \"", 0);
	length = g_strv_length (ipset);
	for (i = 0; i < length; i++) {
		if (!is_ip6_address (ipset[i]))
			continue;
		else {
			g_strfreev (ipset);
			return TRUE;
		}

	}
	g_strfreev (ipset);
	return FALSE;
}

gboolean
has_default_route (gchar * conn_name, gboolean (*check_fn) (gchar *))
{
	gchar *routes = NULL, *tmp, *end;

	g_return_val_if_fail (conn_name != NULL, FALSE);
	tmp = ifnet_get_data (conn_name, "routes");
	if (!tmp)
		return FALSE;
	routes = g_strdup (tmp);
	tmp = find_default_gateway_str (routes);
	if (!tmp) {
		goto error;
	}
	g_strstrip (tmp);
	if ((end = strstr (tmp, "\"")) != NULL)
		*end = '\0';
	if (check_fn (tmp)) {
		g_free (routes);
		return TRUE;
	}
      error:
	g_free (routes);
	return FALSE;
}

static ip_block *
create_ip4_block (gchar * ip)
{
	ip_block *iblock = g_slice_new0 (ip_block);
	struct in_addr tmp_ip4_addr;
	int i;
	guint length;
	gchar **ip_mask;

	/* prefix format */
	if (strstr (ip, "/")) {
		gchar *prefix;

		ip_mask = g_strsplit (ip, "/", 0);
		length = g_strv_length (ip_mask);
		if (!inet_pton (AF_INET, ip_mask[0], &tmp_ip4_addr))
			goto error;
		iblock->ip = tmp_ip4_addr.s_addr;
		prefix = ip_mask[1];
		i = 0;
		while (i < length && isdigit (prefix[i]))
			i++;
		prefix[i] = '\0';
		iblock->netmask = nm_utils_ip4_prefix_to_netmask ((guint32)
								  atoi (ip_mask
									[1]));
	} else if (strstr (ip, "netmask")) {
		ip_mask = g_strsplit (ip, " ", 0);
		length = g_strv_length (ip_mask);
		if (!inet_pton (AF_INET, ip_mask[0], &tmp_ip4_addr))
			goto error;
		iblock->ip = tmp_ip4_addr.s_addr;
		i = 0;
		while (i < length && !strstr (ip_mask[++i], "netmask")) ;
		while (i < length && ip_mask[++i][0] == '\0') ;
		if (i >= length)
			goto error;
		if (!inet_pton (AF_INET, ip_mask[i], &tmp_ip4_addr))
			goto error;
		iblock->netmask = tmp_ip4_addr.s_addr;
	} else {
		g_slice_free (ip_block, iblock);
		if (!is_ip6_address (ip) && !strstr (ip, "dhcp"))
			PLUGIN_WARN (IFNET_PLUGIN_NAME,
				     "Can't handle ipv4 address: %s, missing netmask or prefix",
				     ip);
		return NULL;
	}
	g_strfreev (ip_mask);
	return iblock;
      error:
	if (!is_ip6_address (ip))
		PLUGIN_WARN (IFNET_PLUGIN_NAME, "Can't handle IPv4 address: %s",
			     ip);
	g_strfreev (ip_mask);
	g_slice_free (ip_block, iblock);
	return NULL;
}

static ip6_block *
create_ip6_block (gchar * ip)
{
	ip6_block *iblock = g_slice_new0 (ip6_block);
	gchar *dup_ip = g_strdup (ip);
	struct in6_addr *tmp_ip6_addr = g_slice_new0 (struct in6_addr);
	gchar *prefix = NULL;

	if ((prefix = strstr (dup_ip, "/")) != NULL) {
		*prefix = '\0';
		prefix++;
	}
	if (!inet_pton (AF_INET6, dup_ip, tmp_ip6_addr)) {
		goto error;
	}
	iblock->ip = tmp_ip6_addr;
	if (prefix) {
		errno = 0;
		iblock->prefix = strtol (prefix, NULL, 10);
		if (errno || iblock->prefix <= 0 || iblock->prefix > 128) {
			goto error;
		}
	} else
		iblock->prefix = 64;
	g_free (dup_ip);
	return iblock;
      error:
	if (!is_ip4_address (ip))
		PLUGIN_WARN (IFNET_PLUGIN_NAME, "Can't handle IPv6 address: %s",
			     ip);
	g_slice_free (ip6_block, iblock);
	g_slice_free (struct in6_addr, tmp_ip6_addr);

	g_free (dup_ip);
	return NULL;
}

static guint32
get_ip4_gateway (gchar * gateway)
{
	gchar *tmp, *split;
	struct in_addr tmp_ip4_addr;

	if (!gateway)
		return 0;
	tmp = find_gateway_str (gateway);
	if (!tmp) {
		PLUGIN_WARN (IFNET_PLUGIN_NAME,
			     "Couldn't obtain gateway in \"%s\"", gateway);
		return 0;
	}
	tmp = g_strdup (tmp);
	strip_string (tmp, ' ');
	strip_string (tmp, '"');
	if ((split = strstr (tmp, "\"")) != NULL)
		*split = '\0';
	if (!inet_pton (AF_INET, tmp, &tmp_ip4_addr))
		goto error;
	g_free (tmp);
	return tmp_ip4_addr.s_addr;
      error:
	if (!is_ip6_address (tmp))
		PLUGIN_WARN (IFNET_PLUGIN_NAME, "Can't handle IPv4 gateway: %s",
			     tmp);
	g_free (tmp);
	return 0;
}

static struct in6_addr *
get_ip6_next_hop (gchar * next_hop)
{
	gchar *tmp;
	struct in6_addr *tmp_ip6_addr = g_slice_new0 (struct in6_addr);

	if (!next_hop)
		return 0;
	tmp = find_gateway_str (next_hop);
	if (!tmp) {
		PLUGIN_WARN (IFNET_PLUGIN_NAME,
			     "Couldn't obtain next_hop in \"%s\"", next_hop);
		return 0;
	}
	tmp = g_strdup (tmp);
	strip_string (tmp, ' ');
	strip_string (tmp, '"');
	g_strstrip (tmp);
	if (!inet_pton (AF_INET6, tmp, tmp_ip6_addr))
		goto error;
	g_free (tmp);
	return tmp_ip6_addr;
      error:
	if (!is_ip4_address (tmp))
		PLUGIN_WARN (IFNET_PLUGIN_NAME,
			     "Can't handle IPv6 next_hop: %s", tmp);
	g_free (tmp);
	g_slice_free (struct in6_addr, tmp_ip6_addr);

	return NULL;
}

ip_block *
convert_ip4_config_block (gchar * conn_name)
{
	gchar **ipset;
	guint length;
	guint i;
	gchar *ip;
	guint32 def_gateway;
	gchar *routes;
	gchar *pos;
	ip_block *start = NULL, *current = NULL, *iblock = NULL;
	gchar *pattern =
	    "((\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.)\\{(\\d{1,3})\\.\\.(\\d{1,3})\\}(/\\d{1,2}))";
	GRegex *regex = g_regex_new (pattern, 0, 0, NULL);

	g_return_val_if_fail (conn_name != NULL, NULL);
	ipset = g_strsplit (ifnet_get_data (conn_name, "config"), "\" \"", 0);
	length = g_strv_length (ipset);
	routes = ifnet_get_data (conn_name, "routes");
	if (routes)
		def_gateway = get_ip4_gateway (strstr (routes, "default"));
	else
		def_gateway = 0;
	for (i = 0; i < length; i++) {
		ip = ipset[i];
		ip = strip_string (ip, '"');
		//Handle ip like 192.168.4.{1..3}
		if ((pos = strchr (ip, '{')) != NULL) {
			gchar *ip_start, *ip_prefix;
			gchar *begin_str, *end_str;
			int begin, end, j;
			GMatchInfo *match_info;

			g_regex_match (regex, ip, 0, &match_info);
			if (!g_match_info_matches (match_info)) {
				g_match_info_free (match_info);
				continue;
			}
			begin_str = g_match_info_fetch (match_info, 3);
			end_str = g_match_info_fetch (match_info, 4);
			begin = atoi (begin_str);
			end = atoi (end_str);
			ip_start = g_match_info_fetch (match_info, 2);
			ip_prefix = g_match_info_fetch (match_info, 5);
			if (end < begin || begin < 1 || end > 254) {
				g_match_info_free (match_info);
				continue;
			}

			for (j = begin; j <= end; j++) {
				char suf[4];
				gchar *newip;

				sprintf (suf, "%d", j);
				newip =
				    g_strconcat (ip_start, suf, ip_prefix,
						 NULL);
				iblock = create_ip4_block (newip);
				if (iblock == NULL) {
					g_free (newip);
					continue;
				}
				if (!iblock->gateway && def_gateway != 0)
					iblock->gateway = def_gateway;
				if (start == NULL)
					start = current = iblock;
				else {
					current->next = iblock;
					current = iblock;
				}
				g_free (newip);
			}
			g_free (begin_str);
			g_free (end_str);
			g_free (ip_start);
			g_free (ip_prefix);
			g_match_info_free (match_info);
		} else {
			iblock = create_ip4_block (ip);
			if (iblock == NULL)
				continue;
			if (!iblock->gateway && def_gateway != 0)
				iblock->gateway = def_gateway;
			if (start == NULL)
				start = current = iblock;
			else {
				current->next = iblock;
				current = iblock;
			}
		}
	}
	g_strfreev (ipset);
	g_regex_unref (regex);
	return start;
}

ip6_block *
convert_ip6_config_block (gchar * conn_name)
{
	gchar **ipset;
	guint length;
	guint i;
	gchar *ip;
	ip6_block *start = NULL, *current = NULL, *iblock = NULL;

	g_return_val_if_fail (conn_name != NULL, NULL);
	ipset = g_strsplit (ifnet_get_data (conn_name, "config"), "\" \"", 0);
	length = g_strv_length (ipset);
	for (i = 0; i < length; i++) {
		ip = ipset[i];
		ip = strip_string (ip, '"');
		iblock = create_ip6_block (ip);
		if (iblock == NULL)
			continue;
		if (start == NULL)
			start = current = iblock;
		else {
			current->next = iblock;
			current = iblock;
		}
	}
	g_strfreev (ipset);
	return start;
}

ip_block *
convert_ip4_routes_block (gchar * conn_name)
{
	gchar **ipset;
	guint length;
	guint i;
	gchar *ip;
	gchar *routes;
	ip_block *start = NULL, *current = NULL, *iblock = NULL;

	g_return_val_if_fail (conn_name != NULL, NULL);
	routes = ifnet_get_data (conn_name, "routes");
	if (!routes)
		return NULL;
	ipset = g_strsplit (routes, "\" \"", 0);
	length = g_strv_length (ipset);
	for (i = 0; i < length; i++) {
		ip = ipset[i];
		if (find_default_gateway_str (ip) || strstr (ip, "::")
		    || !find_gateway_str (ip))
			continue;
		ip = strip_string (ip, '"');
		iblock = create_ip4_block (ip);
		if (iblock == NULL)
			continue;
		iblock->gateway = get_ip4_gateway (ip);
		if (start == NULL)
			start = current = iblock;
		else {
			current->next = iblock;
			current = iblock;
		}
	}
	g_strfreev (ipset);
	return start;
}

ip6_block *
convert_ip6_routes_block (gchar * conn_name)
{
	gchar **ipset;
	guint length;
	guint i;
	gchar *ip, *tmp_addr;
	gchar *routes;
	ip6_block *start = NULL, *current = NULL, *iblock = NULL;
	struct in6_addr *tmp_ip6_addr;

	g_return_val_if_fail (conn_name != NULL, NULL);
	routes = ifnet_get_data (conn_name, "routes");
	if (!routes)
		return NULL;
	ipset = g_strsplit (routes, "\" \"", 0);
	length = g_strv_length (ipset);
	for (i = 0; i < length; i++) {
		ip = ipset[i];
		ip = strip_string (ip, '"');
		if (ip[0] == '\0')
			continue;
		if ((tmp_addr = find_default_gateway_str (ip)) != NULL) {
			if (!is_ip6_address (tmp_addr))
				continue;
			else {
				tmp_ip6_addr = g_slice_new0 (struct in6_addr);

				if (inet_pton (AF_INET6, "::", tmp_ip6_addr)) {
					iblock = g_slice_new0 (ip6_block);
					iblock->ip = tmp_ip6_addr;
					iblock->prefix = 128;
				} else {
					g_slice_free (struct in6_addr,
						      tmp_ip6_addr);
					continue;
				}
			}
		} else
			iblock = create_ip6_block (ip);
		if (iblock == NULL)
			continue;
		iblock->next_hop = get_ip6_next_hop (ip);
		if (iblock->next_hop == NULL) {
			destroy_ip6_block (iblock);
			continue;
		}
		if (start == NULL)
			start = current = iblock;
		else {
			current->next = iblock;
			current = iblock;
		}
	}
	g_strfreev (ipset);
	return start;
}

void
destroy_ip_block (ip_block * iblock)
{
	g_slice_free (ip_block, iblock);
}

void
destroy_ip6_block (ip6_block * iblock)
{
	g_slice_free (struct in6_addr, iblock->ip);
	g_slice_free (struct in6_addr, iblock->next_hop);

	g_slice_free (ip6_block, iblock);
}

void
set_ip4_dns_servers (NMSettingIP4Config * s_ip4, gchar * conn_name)
{
	gchar *dns_servers = ifnet_get_data (conn_name, "dns_servers");
	gchar **server_list;
	guint length, i;
	struct in_addr tmp_ip4_addr;
	guint32 new_dns;

	if (!dns_servers)
		return;
	strip_string (dns_servers, '"');
	server_list = g_strsplit (dns_servers, " ", 0);
	length = g_strv_length (server_list);
	if (length)
		g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS,
			      TRUE, NULL);
	for (i = 0; i < length; i++) {
		g_strstrip (server_list[i]);
		if (server_list[i][0] == '\0')
			continue;
		if (!inet_pton (AF_INET, server_list[i], &tmp_ip4_addr)) {
			if (!is_ip6_address (server_list[i]))
				PLUGIN_WARN (IFNET_PLUGIN_NAME,
					     "ignored dns: %s\n",
					     server_list[i]);
			continue;
		}
		new_dns = tmp_ip4_addr.s_addr;
		if (new_dns && !nm_setting_ip4_config_add_dns (s_ip4, new_dns))
			PLUGIN_WARN (IFNET_PLUGIN_NAME,
				     "warning: duplicate DNS server %s",
				     server_list[i]);
	}
	g_strfreev (server_list);
}

void
set_ip6_dns_servers (NMSettingIP6Config * s_ip6, gchar * conn_name)
{
	gchar *dns_servers = ifnet_get_data (conn_name, "dns_servers");
	gchar **server_list;
	guint length, i;
	struct in6_addr tmp_ip6_addr;

	if (!dns_servers)
		return;
	strip_string (dns_servers, '"');
	server_list = g_strsplit (dns_servers, " ", 0);
	length = g_strv_length (server_list);
	if (length)
		g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_IGNORE_AUTO_DNS,
			      TRUE, NULL);
	for (i = 0; i < length; i++) {
		g_strstrip (server_list[i]);
		if (server_list[i][0] == '\0')
			continue;
		if (!inet_pton (AF_INET6, server_list[i], &tmp_ip6_addr)) {
			if (is_ip6_address (server_list[i]))
				PLUGIN_WARN (IFNET_PLUGIN_NAME,
					     "ignored dns: %s\n",
					     server_list[i]);
			continue;
		}
		if (!IN6_IS_ADDR_UNSPECIFIED (&tmp_ip6_addr)
		    && !nm_setting_ip6_config_add_dns (s_ip6, &tmp_ip6_addr))
			PLUGIN_WARN (IFNET_PLUGIN_NAME,
				     "warning: duplicate DNS server %s",
				     server_list[i]);
	}
	g_strfreev (server_list);
}

gboolean
is_managed (gchar * conn_name)
{
	gchar *config;

	g_return_val_if_fail (conn_name != NULL, FALSE);
	config = (gchar *) ifnet_get_data (conn_name, "managed");
	if (!config)
		return TRUE;
	if (strcmp (config, "false") == 0)
		return FALSE;
	return TRUE;
}

void
get_dhcp_hostname_and_client_id (char **hostname, char **client_id)
{
	gchar *dhcp_client = NULL;
	const gchar *dhcpcd_conf = "/etc/dhcpcd.conf";
	const gchar *dhclient_conf = "/etc/dhcp/dhclient.conf";
	gchar *line = NULL, *tmp = NULL, *contents = NULL;
	gchar **all_lines;
	guint line_num, i;

	*hostname = NULL;
	*client_id = NULL;
	dhcp_client = ifnet_get_global_setting ("main", "dhcp");
	if (dhcp_client) {
		if (!strcmp (dhcp_client, "dhclient"))
			g_file_get_contents (dhclient_conf, &contents, NULL,
					     NULL);
		else if (!strcmp (dhcp_client, "dhcpcd"))
			g_file_get_contents (dhcpcd_conf, &contents, NULL,
					     NULL);
		g_free (dhcp_client);
	} else {
		if (g_file_test (dhclient_conf, G_FILE_TEST_IS_REGULAR))
			g_file_get_contents (dhclient_conf, &contents, NULL,
					     NULL);
		else if (g_file_test (dhcpcd_conf, G_FILE_TEST_IS_REGULAR))
			g_file_get_contents (dhcpcd_conf, &contents, NULL,
					     NULL);
	}
	if (!contents)
		return;
	all_lines = g_strsplit (contents, "\n", 0);
	line_num = g_strv_length (all_lines);
	for (i = 0; i < line_num; i++) {
		line = all_lines[i];
		// dhcpcd.conf
		g_strstrip (line);
		if (g_str_has_prefix (line, "hostname")) {
			tmp = line + strlen ("hostname");
			g_strstrip (tmp);
			if (tmp[0] != '\0')
				*hostname = g_strdup (tmp);
			else
				PLUGIN_PRINT (IFNET_PLUGIN_NAME,
					      "dhcpcd hostname not defined, ignoring");
		} else if (g_str_has_prefix (line, "clientid")) {
			tmp = line + strlen ("clientid");
			g_strstrip (tmp);
			if (tmp[0] != '\0')
				*client_id = g_strdup (tmp);
			else
				PLUGIN_PRINT (IFNET_PLUGIN_NAME,
					      "dhcpcd clientid not defined, ignoring");
		}
		// dhclient.conf
		else if ((tmp = strstr (line, "send host-name")) != NULL) {
			tmp += strlen ("send host-name");
			g_strstrip (tmp);
			strip_string (tmp, '"');
			strip_string (tmp, ';');
			if (tmp[0] != '\0')
				*hostname = g_strdup (tmp);
			else
				PLUGIN_PRINT (IFNET_PLUGIN_NAME,
					      "dhclient hostname not defined, ignoring");
		} else if ((tmp = strstr (line, "send dhcp-client-identifier"))
			   != NULL) {
			tmp += strlen ("send dhcp-client-identifier");
			g_strstrip (tmp);
			strip_string (tmp, ';');
			if (tmp[0] != '\0')
				*client_id = g_strdup (tmp);
			else
				PLUGIN_PRINT (IFNET_PLUGIN_NAME,
					      "dhclient clientid not defined, ignoring");
		}
	}
	g_strfreev (all_lines);
	g_free (contents);
}
