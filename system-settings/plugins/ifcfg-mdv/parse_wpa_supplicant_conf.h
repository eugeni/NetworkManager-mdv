#ifndef PARSE_WPA_SUPPLICANT_CONF_H
#define PARSE_WPA_SUPPLICANT_CONF_H

typedef struct _WPAConfig WPAConfig;
typedef struct _WPANetwork WPANetwork;

gboolean ifcfg_mdv_wpa_config_parse(WPAConfig *);
void ifcfg_mdv_wpa_config_free(WPAConfig *);
WPAConfig *ifcfg_mdv_wpa_config_new(gchar *);

WPANetwork *ifcfg_mdv_wpa_config_next(WPAConfig *);
void ifcfg_mdv_wpa_config_rewind(WPAConfig *);

WPANetwork *ifcfg_mdv_wpa_network_new(WPAConfig *);
void ifcfg_mdv_wpa_network_free(WPANetwork *);

gpointer ifcfg_mdv_wpa_network_get_val(WPANetwork *, const gchar *);
void ifcfg_mdv_wpa_network_set_val(WPANetwork *, const gchar *, const gchar *);
gchar *ifcfg_mdv_wpa_network_get_str(WPANetwork *, const gchar *);
void ifcfg_mdv_wpa_network_unset(WPANetwork *, const gchar *);

gboolean ifcfg_mdv_wpa_network_save(WPANetwork *, gchar *, GError **);

#endif /* PARSE_WPA_SUPPLICANT_CONF_H */
