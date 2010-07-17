#!/bin/env python
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2010 Red Hat, Inc.
#

import dbus

bus = dbus.SystemBus()

proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
manager = dbus.Interface(proxy, "org.freedesktop.NetworkManager")

# Get device-specific state
devices = manager.GetDevices()
for d in devices:
    dev_proxy = bus.get_object("org.freedesktop.NetworkManager", d)
    prop_iface = dbus.Interface(dev_proxy, "org.freedesktop.DBus.Properties")

    # Get the device's current state and interface name
    state = prop_iface.Get("org.freedesktop.NetworkManager.Device", "State")
    name = prop_iface.Get("org.freedesktop.NetworkManager.Device", "Interface")

    # and print them out
    if state == 8:   # activated
        print "Device %s is activated" % name
    else:
        print "Device %s is not activated" % name


# Get active connection state
manager_prop_iface = dbus.Interface(proxy, "org.freedesktop.DBus.Properties")
active = manager_prop_iface.Get("org.freedesktop.NetworkManager", "ActiveConnections")
for a in active:
    ac_proxy = bus.get_object("org.freedesktop.NetworkManager", a)
    prop_iface = dbus.Interface(ac_proxy, "org.freedesktop.DBus.Properties")
    state = prop_iface.Get("org.freedesktop.NetworkManager.ActiveConnection", "State")

    # Connections in NM are a collection of settings that describe everything
    # needed to connect to a specific network.  Lets get those details so we
    # can find the user-readable name of the connection.
    con_path = prop_iface.Get("org.freedesktop.NetworkManager.ActiveConnection", "Connection")
    con_service = prop_iface.Get("org.freedesktop.NetworkManager.ActiveConnection", "ServiceName")

    # ask the provider of the connection for its details
    service_proxy = bus.get_object(con_service, con_path)
    con_iface = dbus.Interface(service_proxy, "org.freedesktop.NetworkManagerSettings.Connection")
    con_details = con_iface.GetSettings()
    con_name = con_details['connection']['id']

    if state == 2:   # activated
        print "Connection '%s' is activated" % con_name
    else:
        print "Connection '%s' is activating" % con_name


