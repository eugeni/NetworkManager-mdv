#include <errno.h>
#include <string.h>
#include <glib.h>
#include <glib/gstdio.h>

#include "utils.h"
#include "common.h"

#include "parse_wpa_supplicant_conf.h"

struct _WPAConfig {
	gchar		*file;	/* wpa_supplicant.conf file name */
	GString		*line;	/* Input buffer */
	GRegex		*skip;	/* Filter for comments */
	GRegex		*network;	/* Start of network definition */
	GRegex		*fini;		/* Closing curly bracket */
	GRegex		*keyval;	/* (key, val) pair in network def */
	GSList		*list;		/* list of networks */
	GSList		*next;		/* list iterator */
};

struct _WPANetwork {
	WPAConfig	*parent;	/* IO channel etc */
	GHashTable	*keyvals;	/* content */
};

WPAConfig *
ifcfg_mdv_wpa_config_new(gchar *file)
{
	WPAConfig *wpac;

	g_return_val_if_fail(file != NULL, NULL);

	wpac = g_new(WPAConfig, 1);
	if (!wpac)
		return NULL;

	wpac->file = g_strdup(file);
	wpac->line = g_string_new("");

	wpac->skip = g_regex_new("^\\s*(#.*)?$", 0, 0, NULL);
	wpac->network = g_regex_new("^\\s*network\\s*=\\s*{\\s*$", 0, 0, NULL);
	wpac->fini = g_regex_new("^\\s*}\\s*$", 0, 0, NULL);
	wpac->keyval = g_regex_new("^\\s*([\\w\\d]+)\\s*=\\s*(\\S+.*\\S*)\\s*$", 0, 0, NULL);
	wpac->list = NULL;
	wpac->next = NULL;

	if (!wpac->file || !wpac->line || !wpac->skip ||
	    !wpac->network || !wpac->fini || !wpac->keyval) {
		ifcfg_mdv_wpa_config_free(wpac);
		return NULL;
	}

	return wpac;
}

void
ifcfg_mdv_wpa_config_free(WPAConfig *wpac)
{
	GSList *l;

	if (!wpac)
		return;

	for (l = wpac->list; l; l = g_slist_next(l))
		ifcfg_mdv_wpa_network_free(l->data);

	g_slist_free(wpac->list);

	g_regex_unref(wpac->skip);
	g_regex_unref(wpac->network);
	g_regex_unref(wpac->fini);
	g_regex_unref(wpac->keyval);

	g_string_free(wpac->line, TRUE);
	g_free(wpac->file);

	g_free(wpac);
}

WPANetwork *
ifcfg_mdv_wpa_network_new(WPAConfig *wpac)
{
	WPANetwork *wpan;

	// g_return_val_if_fail(wpac != NULL, NULL);

	wpan = g_new(WPANetwork, 1);
	if (!wpan)
		return NULL;

	wpan->keyvals = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	if (!wpan->keyvals) {
		g_free(wpan);
		return NULL;
	}
	wpan->parent = wpac;

	return wpan;
}

void
ifcfg_mdv_wpa_network_free(WPANetwork *wpan)
{
	if (!wpan)
		return;

	g_hash_table_destroy(wpan->keyvals);
	g_free(wpan);
}

static void
free_list(GSList **list)
{
	GSList *n;

	for (n = *list; n; n = g_slist_next(n))
		g_free(n->data);
	if (*list)
		g_slist_free(*list);
	*list = NULL;
}

gboolean
ifcfg_mdv_wpa_config_parse(WPAConfig *wpac)
{
	WPANetwork *wpan = NULL;
	GIOChannel *ioc;
	GMatchInfo *mi;
	GError *error = NULL;

	g_return_val_if_fail(wpac != NULL, FALSE);

	ioc = g_io_channel_new_file(wpac->file, "r", &error);
	if (!ioc) {
		if (error->code == G_FILE_ERROR_NOENT) {
			g_error_free(error);
			return TRUE;
		}
		return FALSE;
	}

	while (g_io_channel_read_line_string(ioc, wpac->line, NULL, NULL) == G_IO_STATUS_NORMAL) {

		if (g_regex_match(wpac->skip, wpac->line->str, 0, NULL))
			continue;

		if (!wpan && g_regex_match(wpac->network, wpac->line->str, 0, NULL)) {
			wpan = ifcfg_mdv_wpa_network_new(wpac);
			if (!wpan)
				return FALSE;
			continue;
		}

		if (wpan && g_regex_match(wpac->keyval, wpac->line->str, 0, &mi)) {
			gchar *key = g_match_info_fetch(mi, 1);
			gchar *val = g_match_info_fetch(mi, 2);
			ifcfg_mdv_wpa_network_set_val(wpan, key, val);
			g_free(key);
			g_free(val);
			continue;
		}

		if (wpan && g_regex_match(wpac->fini, wpac->line->str, 0, NULL)) {
			wpac->list = g_slist_prepend(wpac->list, wpan);
			wpac->next = wpac->list;
			wpan = NULL;
		}
	}

	g_match_info_free(mi);
	g_io_channel_unref(ioc);

	return TRUE;
}

WPANetwork *
ifcfg_mdv_wpa_config_next(WPAConfig *wpac)
{
	GSList *l = wpac->next;

	if (l)
		wpac->next = g_slist_next(l);
	else
		wpac->next = wpac->list;

	return l == NULL ? NULL : l->data;
}

void
ifcfg_mdv_wpa_config_rewind(WPAConfig *wpac)
{
		wpac->next = wpac->list;
}

gpointer
ifcfg_mdv_wpa_network_get_val(WPANetwork *wpan, const gchar *key)
{
	g_return_val_if_fail(wpan != NULL, NULL);

	return g_hash_table_lookup(wpan->keyvals, key);
}

void
ifcfg_mdv_wpa_network_set_val(WPANetwork *wpan, const gchar *key, const gchar *val)
{
	gchar *k, *v;

	g_return_if_fail(wpan != NULL);
	g_return_if_fail(key != NULL);
	g_return_if_fail(val != NULL);

	k = g_strdup(key);
	v = g_strdup(val);
	g_hash_table_replace(wpan->keyvals, k, v);
}

gchar *
ifcfg_mdv_wpa_network_get_str(WPANetwork *wpan, const gchar *key)
{
	gchar *value, *str = NULL;

	g_return_val_if_fail(wpan != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);

	value = ifcfg_mdv_wpa_network_get_val(wpan, key);
	if (!value)
		return NULL;

	if (*value == '"') {
		const char *pos;
		size_t len;
		value++;
		pos = strrchr(value, '"');
		if (pos == NULL || pos[1] != '\0')
			return NULL;
		len = pos - value;
		str = g_malloc(len + 1);
		if (str == NULL)
			return NULL;
		memcpy(str, value, len);
		str[len] = '\0';
	} else {
		size_t hlen = strlen(value);
		str = utils_hexstr2bin(value, hlen);
		if (str == NULL)
			return NULL;
	}

	return str;
}

void
ifcfg_mdv_wpa_network_set_str(WPANetwork *wpan, const gchar *key, const gchar *val)
{
	const gchar *p;
	gchar *str;
	gboolean need_hex = FALSE;

	/* We may get NULL for non-existing values */
	if (!val) {
		ifcfg_mdv_wpa_network_unset(wpan, key);
		return;
	}

	for (p = val; *p; p++)
		if (!g_ascii_isprint(*p)) {
			need_hex = TRUE;
			break;
		}

	if (need_hex)
		str = utils_bin2hexstr(val, strlen(val), -1);
	else
		str = g_strdup_printf("\"%s\"", val);

	if (str)
		ifcfg_mdv_wpa_network_set_val(wpan, key, str);
#if 0
	else
		PLUGIN_WARN(IFCFG_PLUGIN_NAME, "    warning: could not set value for wpa key %s", key);
#endif
	g_free(str);
}

void
ifcfg_mdv_wpa_network_unset(WPANetwork *wpan, const gchar *key)
{
	g_return_if_fail(wpan != NULL);
	g_return_if_fail(key != NULL);

	g_hash_table_remove(wpan->keyvals, key);
}

static gboolean
add_line(GSList **list, gchar *s)
{
	gchar *n;

	g_return_val_if_fail(list != NULL, FALSE);
	g_return_val_if_fail(s != NULL, FALSE);

	n = g_strdup(s);
	if (!n)
		return FALSE;

	*list = g_slist_append(*list, n);
	if (!*list)
		return FALSE;

	return TRUE;
}

static gboolean
dump_network(GSList **list, WPANetwork *wpan, GError **error)
{
	GHashTableIter iter;
	gpointer key, val;
	gchar *s;

	g_return_val_if_fail(list != NULL, FALSE);
	g_return_val_if_fail(wpan != NULL, FALSE);

	if (!add_line(list, "network={\n"))
		return FALSE;

	g_hash_table_iter_init(&iter, wpan->keyvals);
	while (g_hash_table_iter_next(&iter, &key, &val)) {

		s = g_strdup_printf("\t%s=%s\n", (gchar *)key, (gchar *)val);
		if (!s) {
			g_set_error(error, ifcfg_plugin_error_quark(), 0,
				"Out of memory");
			return FALSE;
		}
		*list = g_slist_append(*list, s);
		if (!*list)
			return FALSE;
	}

	if (!add_line(list, "}\n"))
		return FALSE;

	return TRUE;
}

gboolean
ifcfg_mdv_wpa_network_save(WPANetwork *wpan, gchar *file, GError **error)
{
	WPAConfig *wpac = NULL;
	WPANetwork *o_wpan = NULL;
	GIOStatus ret;
	GSList *network = NULL, *wpa_rest = NULL, *l;
	GIOChannel *ioc = NULL;
	gsize written;
	gchar *ssid;
	gboolean result = FALSE, found = FALSE, delete = FALSE;
	GMatchInfo *mi = NULL;

	g_return_val_if_fail(wpan != NULL, FALSE);
	g_return_val_if_fail(file != NULL, FALSE);

	ssid = ifcfg_mdv_wpa_network_get_val(wpan, "ssid");
	if (!ssid || !*ssid) {
		g_set_error(error, ifcfg_plugin_error_quark(), 0,
				"SSID is missing, unable to store wpa_supplicant configuration");
		goto error;
	}

	/* Looks like a hack but it probably is not worth extra function */
	if (ifcfg_mdv_wpa_network_get_val(wpan, "__DELETE__"))
			delete = TRUE;

	ioc = g_io_channel_new_file(file, "r", error);
	if (!ioc) {
		if ((*error)->code == G_FILE_ERROR_NOENT) {
			g_error_free(*error);
			*error = NULL;
			goto no_input;
		}
		goto error;
	}

	wpac = ifcfg_mdv_wpa_config_new("");
	if (!wpac)
		goto error;

	/* Read original file skipping network in wpan */
	while ((ret = g_io_channel_read_line_string(ioc, wpac->line, NULL, error)) == G_IO_STATUS_NORMAL) {

		/* shortcut */
		if (found) {
			if (!add_line(&wpa_rest, wpac->line->str))
				goto error;
			continue;
		}

		if (!o_wpan && g_regex_match(wpac->network, wpac->line->str, 0, NULL)) {
			if (!add_line(&network, wpac->line->str))
				goto error;
			o_wpan = ifcfg_mdv_wpa_network_new(wpac);
			if (!o_wpan)
				goto error;
			continue;
		}

		if (o_wpan && g_regex_match(wpac->keyval, wpac->line->str, 0, &mi)) {
			gchar *key = g_match_info_fetch(mi, 1);
			gchar *val = g_match_info_fetch(mi, 2);
			ifcfg_mdv_wpa_network_set_val(o_wpan, key, val);
			g_free(key);
			g_free(val);

			if (!add_line(&network, wpac->line->str))
				goto error;
			continue;
		}

		if (o_wpan && g_regex_match(wpac->fini, wpac->line->str, 0, NULL)) {
			gchar *o_ssid;

			if (!add_line(&network, wpac->line->str))
				goto error;
			o_ssid = ifcfg_mdv_wpa_network_get_val(o_wpan, "ssid");
			if (!o_ssid || g_strcmp0(ssid, o_ssid)) {
				wpa_rest = g_slist_concat(wpa_rest, network);
				ifcfg_mdv_wpa_network_free(o_wpan);
				o_wpan = NULL;
				network = NULL;
			} else {
				ifcfg_mdv_wpa_network_free(o_wpan);
				o_wpan = NULL;
				found = TRUE;
			}
			continue;
		}

		if (!add_line(&wpa_rest, wpac->line->str))
			goto error;
	}

	if (ret != G_IO_STATUS_EOF)
		goto error;

	g_io_channel_unref(ioc);
	ioc = NULL;

no_input:
	if (!delete && !dump_network(&wpa_rest, wpan, error))
		goto error;


	ioc = g_io_channel_new_file(file, "w", error);
	if (!ioc)
		goto error;
	g_chmod(file, 0600);

	for (l = wpa_rest; l; l = g_slist_next(l))
		if (g_io_channel_write_chars(ioc, l->data, -1, &written, error) != G_IO_STATUS_NORMAL)
			goto error;
	if (g_io_channel_flush(ioc, error) != G_IO_STATUS_NORMAL)
		goto error;

	result = TRUE;

error:
	ifcfg_mdv_wpa_config_free(wpac);
	ifcfg_mdv_wpa_network_free(o_wpan);
	free_list(&wpa_rest);
	free_list(&network);
	if (ioc)
		g_io_channel_unref(ioc);
	if (mi)
		g_match_info_free(mi);

	return result;
}
