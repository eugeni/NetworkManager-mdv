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
 * Copyright (C) 2004 - 2010 Red Hat, Inc.
 */

#include <config.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "nm-policy-hosts.h"
#include "nm-logging.h"

#define IP4_LH "127.0.0.1"
#define IP6_LH "::1"

gboolean
nm_policy_hosts_find_token (const char *line, const char *token)
{
	const char *start = line, *p = line;

	g_return_val_if_fail (line != NULL, FALSE);
	g_return_val_if_fail (token != NULL, FALSE);
	g_return_val_if_fail (strlen (token) > 0, FALSE);

	/* Walk through the line to find the next whitespace character */
	while (p <= line + strlen (line)) {
		if (isblank (*p) || (*p == '\0')) {
			/* Token starts with 'start' and ends with 'end' */
			if ((p > start) && *start && (p - start == strlen (token)) && !strncmp (start, token, (p - start)))
				return TRUE; /* found */

			/* not found; advance start and continue looking */
			start = p + 1;
		}
		p++;
	}

	return FALSE;
}

static gboolean
is_local_mapping (const char *str, gboolean ip6, const char *hostname)
{
	const char *addr = ip6 ? IP6_LH : IP4_LH;
	const char *fallback = ip6 ? "localhost6" : "localhost";

	return (   !strncmp (str, addr, strlen (addr))
	        && nm_policy_hosts_find_token (str, hostname ? hostname : fallback));
}

static gboolean
is_ip4_addr (const char *str)
{
	struct in_addr found;
	char buf[INET_ADDRSTRLEN + 2];
	const char *p = str;
	guint32 i = 0;

	memset (buf, 0, sizeof (buf));
	while (*p && !isblank (*p) && (i < sizeof (buf)))
		buf[i++] = *p++;

	return inet_pton (AF_INET, buf, &found) == 1 ? TRUE : FALSE;
}

static gboolean
ip4_addr_matches (const char *str, const char *ip4_addr)
{
	struct in_addr found, given;
	char buf[INET_ADDRSTRLEN + 2];
	const char *p = str;
	guint32 i = 0;

	g_return_val_if_fail (ip4_addr != NULL, FALSE);

	memset (buf, 0, sizeof (buf));
	while (*p && !isblank (*p) && (i < sizeof (buf)))
		buf[i++] = *p++;

	if (inet_pton (AF_INET, buf, &found) != 1)
		return FALSE;
	if (inet_pton (AF_INET, ip4_addr, &given) != 1)
		return FALSE;

	return memcmp (&found, &given, sizeof (found)) == 0;
}

static gboolean
is_ip6_addr (const char *str)
{
	struct in6_addr found;
	char buf[INET6_ADDRSTRLEN + 2];
	const char *p = str;
	guint32 i = 0;

	memset (buf, 0, sizeof (buf));
	while (*p && !isblank (*p) && (i < sizeof (buf)))
		buf[i++] = *p++;

	return inet_pton (AF_INET6, buf, &found) == 1 ? TRUE : FALSE;
}

static gboolean
ip6_addr_matches (const char *str, const char *ip6_addr)
{
	struct in6_addr found, given;
	char buf[INET6_ADDRSTRLEN + 2];
	const char *p = str;
	guint32 i = 0;

	g_return_val_if_fail (ip6_addr != NULL, FALSE);

	memset (buf, 0, sizeof (buf));
	while (*p && !isblank (*p) && (i < sizeof (buf)))
		buf[i++] = *p++;

	if (inet_pton (AF_INET6, buf, &found) != 1)
		return FALSE;
	if (inet_pton (AF_INET6, ip6_addr, &given) != 1)
		return FALSE;

	return memcmp (&found, &given, sizeof (found)) == 0;
}

static char *
get_custom_hostnames (const char *line,
                      const char *hostname,
                      const char *old_hostname,
                      const char *short_hostname,
                      const char *fallback_hostname)
{
	char **items = NULL, **iter;
	guint start = 0;
	GString *str = NULL;
	char *custom = NULL;

	g_return_val_if_fail (line != NULL, NULL);

	if (!strncmp (line, IP4_LH, strlen (IP4_LH)))
		start = strlen (IP4_LH);
	else if (!strncmp (line, IP6_LH, strlen (IP6_LH)))
		start = strlen (IP6_LH);

	g_return_val_if_fail (start > 0, NULL);

	/* Split the line into tokens */
	items = g_strsplit_set (line + start, " \t", -1);
	if (!items)
		return NULL;

	str = g_string_sized_new (50);
	/* Ignore current & old hostnames, and localhost-anything */
	for (iter = items; iter && *iter; iter++) {
		if (*iter[0] == '\0')
			continue;
		if (hostname && !strcmp (*iter, hostname))
			continue;
		if (old_hostname && !strcmp (*iter, old_hostname))
			continue;
		if (short_hostname && !strcmp (*iter, short_hostname))
			continue;
		if (fallback_hostname && !strcmp (*iter, fallback_hostname))
			continue;
		if (!strcmp (*iter, "localhost"))
			continue;
		if (!strcmp (*iter, "localhost6"))
			continue;
		if (!strcmp (*iter, "localhost.localdomain"))
			continue;
		if (!strcmp (*iter, "localhost4.localdomain4"))
			continue;
		if (!strcmp (*iter, "localhost6.localdomain6"))
			continue;

		/* Found a custom hostname */
		g_string_append_c (str, '\t');
		g_string_append (str, *iter);
	}

	if (str->len)
		custom = g_string_free (str, FALSE);
	else
		g_string_free (str, TRUE);

	g_strfreev (items);
	return custom;
}

#define ADDED_TAG "# Added by NetworkManager"

GString *
nm_policy_get_etc_hosts (const char **lines,
                         gsize existing_len,
                         const char *hostname,
                         const char *old_hostname,
                         const char *fallback_hostname4,
                         const char *fallback_hostname6,
                         const char *ip4_addr,
                         const char *ip6_addr,
                         GError **error)
{
	GString *contents = NULL;
	const char **line;
	gboolean found_localhost4 = FALSE;
	gboolean found_localhost6 = FALSE;
	gboolean found_host4 = FALSE;
	gboolean found_host6 = FALSE;
	gboolean found_user_host4 = FALSE;
	gboolean found_user_host6 = FALSE;
	gboolean initial_comments = TRUE;
	gboolean added = FALSE;
	gboolean hostname4_is_fallback;
	gboolean hostname6_is_fallback;
	gboolean host4_before = FALSE;
	gboolean host6_before = FALSE;
	gboolean no_stale = TRUE;
	char *short_hostname = NULL;
	char *custom4 = NULL;
	char *custom6 = NULL;

	g_return_val_if_fail (lines != NULL, FALSE);
	g_return_val_if_fail (hostname != NULL, FALSE);

	hostname4_is_fallback = !strcmp (hostname, fallback_hostname4);
	hostname6_is_fallback = !strcmp (hostname, fallback_hostname6);

	/* Find the short hostname, like 'foo' from 'foo.bar.baz'; we want to
	 * make sure that the entries we add for this host also include the short
	 * hostname too so that if the resolver does not answer queries for the
	 * machine's actual hostname/domain, that stuff like 'ping foo' still works.
	 */
	if (!hostname4_is_fallback || !hostname6_is_fallback) {
		char *dot;

		short_hostname = g_strdup (hostname);
		dot = strchr (short_hostname, '.');
		if (dot && *(dot+1))
			*dot = '\0';
		else {
			g_free (short_hostname);
			short_hostname = NULL;
		}
	}

	/* We need the following in /etc/hosts:
	 *
	 * 1) current hostname mapped to current IPv4 addresses if IPv4 is active
	 * 2) current hostname mapped to current IPv6 addresses if IPv6 is active
	 * 3) 'localhost' mapped to 127.0.0.1
	 * 4) 'localhost6' mapped to ::1
	 *
	 * If all these things exist we don't need to bother updating the file.
	 */

	if (!ip4_addr)
		host4_before = TRUE;
	if (!ip6_addr)
		host6_before = TRUE;

	/* Look for the four cases from above */
	for (line = lines; lines && *line; line++) {
		gboolean found_hostname = FALSE;

		if ((*line[0] == '\0') || (*line[0] == '#'))
			continue;

		found_hostname = nm_policy_hosts_find_token (*line, hostname);
		if (found_hostname) {
			/* Found the current hostname on this line */
			if (ip4_addr && ip4_addr_matches (*line, ip4_addr)) {
				found_host4 = TRUE;
				if (strstr (*line, ADDED_TAG)) {
					if (!host4_before)
						host4_before = !found_localhost4;
				} else {
					found_user_host4 = TRUE;
					host4_before = TRUE;  /* Ignore if user added mapping manually */
				}
			} else if (!ip4_addr && strstr (*line, ADDED_TAG)) {
				/* If this is a stale NM-added IPv4 entry we need to remove it,
				 * so make sure we update /etc/hosts.
				 */
				if (is_ip4_addr (*line))
					no_stale = FALSE;
			}

			if (ip6_addr && ip6_addr_matches (*line, ip6_addr)) {
				found_host6 = TRUE;
				if (strstr (*line, ADDED_TAG)) {
					if (!host6_before)
						host6_before = !found_localhost6;
				} else {
					found_user_host6 = TRUE;
					host6_before = TRUE;  /* Ignore if user added mapping manually */
				}
			} else if (!ip6_addr && strstr (*line, ADDED_TAG)) {
				/* If this is a stale NM-added IPv6 entry we need to remove it,
				 * so make sure we update /etc/hosts.
				 */
				if (is_ip6_addr (*line))
					no_stale = FALSE;
			}
		}

		if (is_local_mapping (*line, FALSE, "localhost")) {
			/* a 127.0.0.1 line containing 'localhost' */
			found_localhost4 = TRUE;
			custom4 = get_custom_hostnames (*line, hostname, old_hostname, short_hostname, fallback_hostname4);
			if (!ip4_addr) {
				/* If there's no IP-specific mapping for the current hostname
				 * but that hostname is present on in the local mapping line,
				 * we've found our IPv4 hostname mapping.  If the hostname is
				 * the fallback *IPv6* hostname it's not going to show up in
				 * the IPv4 local mapping though, so fake it.
				 */
				if (hostname6_is_fallback || found_hostname)
					found_host4 = TRUE;
			}
		} else if (is_local_mapping (*line, TRUE, "localhost6")) {
			/* a ::1 line containing 'localhost6' */
			found_localhost6 = TRUE;
			custom6 = get_custom_hostnames (*line, hostname, old_hostname, short_hostname, fallback_hostname6);
			if (!ip6_addr) {
				/* If there's no IP-specific mapping for the current hostname
				 * but that hostname is present on in the local mapping line,
				 * we've found our IPv6 hostname mapping.  If the hostname is
				 * the fallback *IPv4* hostname it's not going to show up in
				 * the IPv6 local mapping though, so fake it.
				 */
				if (hostname4_is_fallback || found_hostname)
					found_host6 = TRUE;
			}
		}

		if (   found_localhost4
		    && found_host4
		    && found_localhost6
		    && found_host6
		    && host4_before
		    && host6_before
		    && no_stale)
			goto out;  /* No update required */
	}

	contents = g_string_sized_new (existing_len ? existing_len + 100 : 200);
	if (!contents) {
		g_set_error_literal (error, 0, 0, "not enough memory");
		goto out;
	}

	/* Construct the new hosts file; replace any 127.0.0.1/::1 entry that is
	 * at the beginning of the file or right after initial comments and contains
	 * the string 'localhost' (for IPv4) or 'localhost6' (for IPv6).  If there
	 * is no 127.0.0.1 or ::1 entry at the beginning or after initial comments
	 * that contains 'localhost' or 'localhost6', add one there
	 * and ignore any other 127.0.0.1/::1 entries that contain 'localhost' or
	 * 'localhost6'.
	 */
	for (line = lines, initial_comments = TRUE; lines && *line; line++) {
		/* This is the first line after the initial comments */
		if (strlen (*line) && initial_comments && (*line[0] != '#')) {
			initial_comments = FALSE;

			/* If the user added their own mapping for the hostname, just make
			 * a simple 'localhost' mapping and assume the user knows what they
			 * are doing with their manual hostname entry.  Otherwise if the
			 * hostname wasn't found somewhere else, add it to the localhost
			 * mapping line to make sure it's mapped to something.
			 */

			/* Add the address mappings first so they take precedence */
			if (!hostname4_is_fallback && ip4_addr && !found_user_host4) {
				g_string_append_printf (contents, "%s\t%s", ip4_addr, hostname);
				if (short_hostname)
					g_string_append_printf (contents, "\t%s", short_hostname);
				g_string_append_printf (contents, "\t%s\n", ADDED_TAG);
			}
			if (!hostname6_is_fallback && ip6_addr && !found_user_host6) {
				g_string_append_printf (contents, "%s\t%s", ip6_addr, hostname);
				if (short_hostname)
					g_string_append_printf (contents, "\t%s", short_hostname);
				g_string_append_printf (contents, "\t%s\n", ADDED_TAG);
			}

			/* IPv4 localhost line */
			g_string_append (contents, "127.0.0.1");
			if (!hostname4_is_fallback && !ip4_addr && !found_user_host4) {
				g_string_append_printf (contents, "\t%s", hostname);
				if (short_hostname)
					g_string_append_printf (contents, "\t%s", short_hostname);
			}
			g_string_append_printf (contents, "\t%s\tlocalhost", fallback_hostname4);
			if (custom4)
				g_string_append (contents, custom4);
			g_string_append_c (contents, '\n');

			/* IPv6 localhost line */
			g_string_append (contents, "::1");
			if (!hostname6_is_fallback && !hostname4_is_fallback && !ip6_addr && !found_user_host6) {
				g_string_append_printf (contents, "\t%s", hostname);
				if (short_hostname)
					g_string_append_printf (contents, "\t%s", short_hostname);
			}
			g_string_append_printf (contents, "\t%s\tlocalhost6", fallback_hostname6);
			if (custom6)
				g_string_append (contents, custom6);
			g_string_append_c (contents, '\n');

			added = TRUE;
		}

		/* Don't add the original line if it is a localhost mapping */
		if (   !is_local_mapping (*line, FALSE, "localhost")
		    && !is_local_mapping (*line, FALSE, fallback_hostname4)
		    && !is_local_mapping (*line, FALSE, hostname)
		    && !is_local_mapping (*line, TRUE, "localhost6")
		    && !is_local_mapping (*line, TRUE, fallback_hostname6)
		    && !is_local_mapping (*line, TRUE, hostname)
			&& !strstr (*line, ADDED_TAG)) {

			g_string_append (contents, *line);
			/* Only append the new line if this isn't the last line in the file */
			if (*(line+1))
				g_string_append_c (contents, '\n');
		}
	}

	/* Hmm, /etc/hosts was empty for some reason */
	if (!added) {
		g_string_append (contents, "# Do not remove the following lines, or various programs\n");
		g_string_append (contents, "# that require network functionality will fail.\n");

		/* Add the address mappings first so they take precedence */
		if (!hostname4_is_fallback && ip4_addr) {
			g_string_append_printf (contents, "%s\t%s", ip4_addr, hostname);
			if (short_hostname)
				g_string_append_printf (contents, "\t%s", short_hostname);
			g_string_append_printf (contents, "\t%s\n", ADDED_TAG);
		}
		if (!hostname6_is_fallback && ip6_addr) {
			g_string_append_printf (contents, "%s\t%s", ip6_addr, hostname);
			if (short_hostname)
				g_string_append_printf (contents, "\t%s", short_hostname);
			g_string_append_printf (contents, "\t%s\n", ADDED_TAG);
		}

		g_string_append_printf (contents, "127.0.0.1\t%s\tlocalhost\n", fallback_hostname4);
		g_string_append_printf (contents, "::1\t%s\tlocalhost6\n", fallback_hostname6);
	}

out:
	g_free (custom4);
	g_free (custom6);
	g_free (short_hostname);
	return contents;
}

gboolean
nm_policy_hosts_update_etc_hosts (const char *hostname,
                                  const char *old_hostname,
                                  const char *fallback_hostname4,
                                  const char *fallback_hostname6,
                                  const char *ip4_addr,
                                  const char *ip6_addr,
                                  gboolean *out_changed)
{
	char *contents = NULL;
	char **lines = NULL;
	GError *error = NULL;
	GString *new_contents = NULL;
	gsize contents_len = 0;
	gboolean success = FALSE;

	g_return_val_if_fail (hostname != NULL, FALSE);
	g_return_val_if_fail (out_changed != NULL, FALSE);

	if (!g_file_get_contents (SYSCONFDIR "/hosts", &contents, &contents_len, &error)) {
		nm_log_warn (LOGD_DNS, "couldn't read " SYSCONFDIR "/hosts: (%d) %s",
		             error ? error->code : 0,
		             (error && error->message) ? error->message : "(unknown)");
		g_clear_error (&error);
		return FALSE;
	}

	/* Get the new /etc/hosts contents */
	lines = g_strsplit_set (contents, "\n\r", 0);
	new_contents = nm_policy_get_etc_hosts ((const char **) lines,
	                                        contents_len,
	                                        hostname,
	                                        old_hostname,
	                                        fallback_hostname4,
	                                        fallback_hostname6,
	                                        ip4_addr,
	                                        ip6_addr,
	                                        &error);
	g_strfreev (lines);
	g_free (contents);

	if (new_contents) {
		nm_log_info (LOGD_DNS, "Updating /etc/hosts with new system hostname");

		g_clear_error (&error);
		/* And actually update /etc/hosts */
		if (!g_file_set_contents (SYSCONFDIR "/hosts", new_contents->str, -1, &error)) {
			nm_log_warn (LOGD_DNS, "couldn't update " SYSCONFDIR "/hosts: (%d) %s",
			             error ? error->code : 0,
			             (error && error->message) ? error->message : "(unknown)");
			g_clear_error (&error);
		} else {
			success = TRUE;
			*out_changed = TRUE;
		}

		g_string_free (new_contents, TRUE);
	} else if (!error) {
		/* No change required */
		success = TRUE;
	} else {
		nm_log_warn (LOGD_DNS, "couldn't read " SYSCONFDIR "/hosts: (%d) %s",
		             error->code, error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}

	return success;
}

