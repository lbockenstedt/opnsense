{# Read by /etc/rc.d/dnctl after OPNsense's own /etc/rc.conf.d/dnctl: load the
   shaper pipes through our wrapper so it can add latency/loss. The file test
   keeps the shaper working if the plugin is removed but this file is left. #}
[ -f /usr/local/opnsense/scripts/OPNsense/NetImpair/dnctl.sh ] && dnctl_program="/bin/sh /usr/local/opnsense/scripts/OPNsense/NetImpair/dnctl.sh"
