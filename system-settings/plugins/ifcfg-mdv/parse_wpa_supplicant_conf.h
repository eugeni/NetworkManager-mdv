typedef struct _WPAConfig WPAConfig;
typedef struct _WPANetwork WPANetwork;

WPAConfig *ifcfg_mdv_wpa_config(gchar *);
void ifcfg_mdv_wpa_config_free(WPAConfig *);
WPANetwork *ifcfg_mdv_wpa_config_next(WPAConfig *);
void ifcfg_mdv_wpa_config_rewind(WPAConfig *);
gpointer ifcfg_mdv_wpa_network_get_val(WPANetwork *, gconstpointer);
