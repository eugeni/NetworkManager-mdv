#include <glib.h>
#include "parse_wpa_supplicant_conf.h"

struct _WPAConfig {
	GIOChannel *ioc;	/* wpa_supplicant.conf channel */
	GString		*line;	/* Input buffer */
	GRegex		*comment;	/* Filter for comments */
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

void
ifcfg_mdv_wpa_config_free(WPAConfig *wpac)
{
	GSList *l;

	if (!wpac)
		return;

	for (l = wpac->list; l; l = g_slist_next(l)) {
		WPANetwork *n = l->data;

		g_hash_table_destroy(n->keyvals);
		g_free(n);
	}

	g_slist_free(wpac->list);

	g_regex_unref(wpac->comment);
	g_regex_unref(wpac->network);
	g_regex_unref(wpac->fini);
	g_regex_unref(wpac->keyval);

	g_string_free(wpac->line, TRUE);

	g_io_channel_close(wpac->ioc);

	g_free(wpac);
}

static GIOStatus
get_line(WPAConfig *wpac)
{
	GIOStatus ret;
	gsize nlpos;

	while ((ret = g_io_channel_read_line_string(wpac->ioc, wpac->line, &nlpos, NULL)) == G_IO_STATUS_NORMAL) {
		if (nlpos == 0)
			continue;
		g_string_set_size(wpac->line, nlpos);

		if (g_regex_match(wpac->comment, wpac->line->str, 0, NULL))
			continue;

		break;
	}

	return ret;
}

static WPANetwork *
parse_network(WPAConfig *wpac)
{
	WPANetwork *wpan = g_new(WPANetwork, 1);

	if (!wpan)
		return NULL;

	wpan->keyvals= g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	if (!wpan->keyvals) {
		g_free(wpan);
		return NULL;
	}
	wpan->parent = wpac;

	while (get_line(wpac) == G_IO_STATUS_NORMAL) {
		GMatchInfo *mi;

		if (g_regex_match(wpac->fini, wpac->line->str, 0, NULL))
			break;

		if (g_regex_match(wpac->keyval, wpac->line->str, 0, &mi)) {
			gchar *key = g_match_info_fetch(mi, 1);
			gchar *val = g_match_info_fetch(mi, 2);

			g_hash_table_insert(wpan->keyvals, key, val);
		}

		g_match_info_free(mi);
	}

	return wpan;
}

WPAConfig *
ifcfg_mdv_wpa_config(gchar *file)
{
	WPAConfig *wpac = g_new(WPAConfig, 1);
	WPANetwork *wpan;

	if (!wpac)
		return NULL;

	wpac->line = g_string_new("");

	wpac->ioc = g_io_channel_new_file(file, "r", NULL);
	wpac->comment = g_regex_new("^\\s*#", 0, 0, NULL);
	wpac->network = g_regex_new("^\\s*network\\s*=\\s*{\\s*$", 0, 0, NULL);
	wpac->fini = g_regex_new("^\\s*}\\s*$", 0, 0, NULL);
	wpac->keyval = g_regex_new("^\\s*(\\S+)\\s*=\\s*\"?([^\"]+)\"?\\s*$", 0, 0, NULL);
	wpac->list = NULL;
	wpac->next = NULL;

	if (!wpac->ioc || !wpac->comment || !wpac->network ||
	    !wpac->fini || !wpac->keyval) {
		ifcfg_mdv_wpa_config_free(wpac);
		return NULL;
	}

	while (get_line(wpac) == G_IO_STATUS_NORMAL) {
		if (g_regex_match(wpac->network, wpac->line->str, 0, NULL)) {
			wpan = parse_network(wpac);
			if (wpan != NULL) {
				wpac->list = g_slist_prepend(wpac->list, wpan);
				wpac->next = wpac->list;
			} else {
				/* TODO what should we do? */
			}
		}
	}

	return wpac;
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
ifcfg_mdv_wpa_network_get_val(WPANetwork *wpan, gconstpointer key)
{
	return g_hash_table_lookup(wpan->keyvals, key);
}
