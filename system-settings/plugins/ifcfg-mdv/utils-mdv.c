/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * (C) Copyright 2008 - 2009 Red Hat, Inc.
 * (C) Copyright 2010 Andrey Borzenkov <arvidjaar@mail.ru>
 */

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "utils-mdv.h"
#include "shvar.h"

/*
 * split_ifcfg_name
 *
 *   split full path name in last component (ifcfg-XXX or wireless SSID)
 *   and previous (which may be name of .../wireless.d subdir
 */
static void
split_ifcfg_name(const gchar *path, gchar **wireless_d, gchar **name)
{
	gchar *tmp;

	g_assert(wireless_d);
	g_assert(name);

	*wireless_d = *name = NULL;
	g_return_if_fail(path != NULL);

	*name = g_path_get_basename(path);
	tmp = g_path_get_dirname(path);
	*wireless_d = g_path_get_basename(tmp);
	g_free(tmp);
}

/*
 * mdv_should_ignore_file
 *
 *   Check whether file name may be valid connection definition file
 *
 */
gboolean
mdv_should_ignore_file(const gchar *path)
{
	gchar *file = NULL, *wireless_d = NULL;
	gboolean result = FALSE;

	g_return_val_if_fail(path != NULL, TRUE);

	split_ifcfg_name(path, &wireless_d, &file);
	if (!wireless_d || !file)
		goto out;

	if (strcmp(wireless_d, "wireless.d")) {
		/* Standard RH-style ifcfg-XXX */
		result = utils_should_ignore_file(file, TRUE);
	} else {
		/* We really can check only name length */
		if (strlen(file) > 32)
			result = TRUE;
	}

out:
	g_free(wireless_d);
	g_free(file);

	return result;
}

/*
 * mdv_get_ifcfg_type
 * 
 *   return possible type of connecion definition file. If filename
 *   looks like valid connection, return suggested connection name
 *   additionally
 */
MdvIfcfgType
mdv_get_ifcfg_type(const gchar *path)
{
	gchar *wireless_d = NULL, *file = NULL;
	const gchar *tmp;
	static GRegex *bssid_regex;
	MdvIfcfgType ret = MdvIfcfgTypeUnknown;

	g_return_val_if_fail(path != NULL, MdvIfcfgTypeUnknown);

	split_ifcfg_name(path, &wireless_d, &file);
	if (!wireless_d || !file)
		goto out;

	/* Plugin is never unloaded */
	if (!bssid_regex)
		bssid_regex = g_regex_new("[[:xdigit:]]{2}(:[[:xdigit:]]{2}){5}", 0, 0, NULL);
	g_assert(bssid_regex);

	if (strcmp(wireless_d, "wireless.d")) {
		/* Plain ifcfg */
		 tmp = utils_get_ifcfg_name(file, TRUE);
		 if (tmp)
			 ret = MdvIfcfgTypeInterface;
	} else {
		/*
		 * SSID can really be everything, so just try to check
		 * whether file name _looks_ like BSSID
		 */
		if (g_regex_match(bssid_regex, file, 0, NULL))
			ret = MdvIfcfgTypeBSSID;
		else
			ret = MdvIfcfgTypeSSID;
	}

out:
	g_free(wireless_d);
	g_free(file);

	return ret;
}

/*
 * mdv_get_ifcfg_path
 * 
 *   return ifcfg name. For plain ifcfg-XXX this is XXX;
 *   for a file under .../wireless.d this is simply file name
 */
const gchar *
mdv_get_ifcfg_name(const gchar *path)
{
	switch (mdv_get_ifcfg_type(path)) {
		case MdvIfcfgTypeInterface:
			/* RH function return pointer into path */
			return g_strdup(utils_get_ifcfg_name(path, TRUE));
			break;
		case MdvIfcfgTypeSSID:
		case MdvIfcfgTypeBSSID:
			return g_path_get_basename(path);
			break;
		default:
			return NULL;
			break;
	}
}
