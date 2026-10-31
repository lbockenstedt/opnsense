#!/bin/sh
# Build the os-netimpair package and a pkg repository holding it. Runs on
# FreeBSD (needs pkg); CI runs it in a FreeBSD VM.
#   sh build-pkg.sh <repo dir> <version>
set -e
[ -n "$2" ] || { echo "usage: $0 <repo dir> <version>" >&2; exit 1; }
mkdir -p "$1"
REPO=$(realpath "$1")
cd "$(dirname "$0")"
VERSION=$2
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Files, laid out as they land on the firewall.
mkdir -p "$WORK/root/usr/local" "$WORK/meta"
cp -R src/opnsense "$WORK/root/usr/local/"
chmod 0755 "$WORK/root/usr/local/opnsense/scripts/OPNsense/NetImpair/dnctl.sh"
(cd "$WORK/root" && find usr -type f | sort | sed 's|^|/|') > "$WORK/plist"

comment=$(sed -n 's/^PLUGIN_COMMENT=[[:space:]]*//p' Makefile)
maintainer=$(sed -n 's/^PLUGIN_MAINTAINER=[[:space:]]*//p' Makefile)
cat > "$WORK/meta/+MANIFEST" <<MANIFEST
name: os-netimpair
version: "$VERSION"
origin: opnsense/os-netimpair
comment: "$comment"
maintainer: "$maintainer"
www: "https://github.com/lbockenstedt/opnsense/tree/main/plugin/netimpair"
prefix: /usr/local
abi: "FreeBSD:*:*"
categories: [net]
licenselogic: single
licenses: [BSD2CLAUSE]
desc: <<EOD
$(cat pkg-descr)
EOD
MANIFEST

# Show the new page (menu / ACL are cached) and write the config files.
cat > "$WORK/meta/+POST_INSTALL" <<'SCRIPT'
mkdir -p /usr/local/etc/rc.conf.d
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json
if [ -x /usr/local/sbin/configctl ]; then
    /usr/local/sbin/configctl template reload OPNsense/NetImpair
fi
SCRIPT
cat > "$WORK/meta/+POST_DEINSTALL" <<'SCRIPT'
rm -f /usr/local/etc/rc.conf.d/dnctl /usr/local/etc/netimpair.conf
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json
if [ -x /usr/local/sbin/configctl ]; then
    /usr/local/sbin/configctl shaper reload
fi
SCRIPT

pkg create -m "$WORK/meta" -r "$WORK/root" -p "$WORK/plist" -o "$REPO"
pkg repo "$REPO"
ls -l "$REPO"
