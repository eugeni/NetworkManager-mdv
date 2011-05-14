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
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#include <glib.h>
#include "shvar.h"
#include "common.h"

char *utils_bin2hexstr (const char *bytes, int len, int final_len);

char *utils_hexstr2bin (const char *hex, size_t len);

char *utils_cert_path (const char *parent, const char *suffix);

const char *utils_get_ifcfg_name (const char *file, gboolean only_ifcfg);

gboolean utils_should_ignore_file (const char *filename, gboolean only_ifcfg);

char *utils_get_ifcfg_path (const char *parent);
char *utils_get_keys_path (const char *parent);
char *utils_get_route_path (const char *parent);
char *utils_get_route6_path (const char *parent);

shvarFile *utils_get_extra_ifcfg (const char *parent, const char *tag, gboolean should_create);
shvarFile *utils_get_keys_ifcfg (const char *parent, gboolean should_create);
shvarFile *utils_get_route_ifcfg (const char *parent, gboolean should_create);
shvarFile *utils_get_route6_ifcfg (const char *parent, gboolean should_create);

gboolean utils_has_route_file_new_syntax (const char *filename);

gchar *utils_ssid4ifcfg(const GByteArray *ssid);
gchar *utils_wep4ifcfg(const gchar *value);

#endif  /* _UTILS_H_ */

