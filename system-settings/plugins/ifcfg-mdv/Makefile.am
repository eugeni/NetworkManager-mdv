SUBDIRS=.

pkglib_LTLIBRARIES = libnm-settings-plugin-ifcfg-mdv.la

noinst_LTLIBRARIES = libifcfg-mdv-io.la

libifcfg_mdv_io_la_SOURCES = \
	reader.c \
	reader.h \
	writer.c \
	writer.h \
	common.h \
	../ifcfg-rh/shvar.c \
	../ifcfg-rh/shvar.h \
	../ifcfg-rh/errors.c \
	../ifcfg-rh/utils.c \
	../ifcfg-rh/utils.h

INCLUDES = \
	-I$(top_srcdir)/src/system-settings \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/marshallers

libifcfg_mdv_io_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(NSS_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DSBINDIR=\"$(sbindir)\"

libifcfg_mdv_io_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS) \
	$(NSS_LIBS)

libnm_settings_plugin_ifcfg_mdv_la_SOURCES = \
	plugin.c \
	plugin.h \
	nm-ifcfg-connection.c \
	nm-ifcfg-connection.h

libnm_settings_plugin_ifcfg_mdv_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GMODULE_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DSYSCONFDIR=\"$(sysconfdir)\"

libnm_settings_plugin_ifcfg_mdv_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_ifcfg_mdv_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(top_builddir)/marshallers/libmarshallers.la \
	libifcfg-mdv-io.la \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(GIO_LIBS)

