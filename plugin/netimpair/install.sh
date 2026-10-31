#!/bin/sh
# Install (or update) the Network Impairment add-in on an OPNsense box.
#   fetch -o - https://.../netimpair.tar.gz | tar xzf - && sh netimpair/install.sh
#   sh install.sh --remove      # uninstall
set -e
cd "$(dirname "$0")"

SCRIPTS=/usr/local/opnsense/scripts/OPNsense/NetImpair

if [ "$1" = "--remove" ]; then
    rm -rf /usr/local/opnsense/mvc/app/models/OPNsense/NetImpair \
           /usr/local/opnsense/mvc/app/controllers/OPNsense/NetImpair \
           /usr/local/opnsense/mvc/app/views/OPNsense/NetImpair \
           /usr/local/opnsense/service/templates/OPNsense/NetImpair \
           "$SCRIPTS" \
           /usr/local/etc/rc.conf.d/dnctl /usr/local/etc/netimpair.conf
    rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json
    service configd restart
    configctl shaper reload
    echo "Network Impairment removed."
    exit 0
fi

[ -d /usr/local/opnsense/mvc ] || { echo "This is not an OPNsense system." >&2; exit 1; }

cp -R src/opnsense/ /usr/local/opnsense/
chmod 0755 "$SCRIPTS"/dnctl.sh
mkdir -p /usr/local/etc/rc.conf.d
# Menu and ACL are cached; drop the caches so the new page shows up.
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json
service configd restart
configctl template reload OPNsense/NetImpair
echo "Network Impairment installed: Firewall > Shaper > Impairment"
