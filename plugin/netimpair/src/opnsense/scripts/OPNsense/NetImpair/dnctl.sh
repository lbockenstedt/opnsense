#!/bin/sh
# dnctl_program for /etc/rc.d/dnctl (see templates/OPNsense/NetImpair/rc.conf.d).
# Copies the Traffic Shaper's pipe rules ($1), adds the latency ("delay") and
# packet loss ("plr") set in /usr/local/etc/netimpair.conf to the matching
# "pipe N config ..." lines, and loads the result with the real dnctl.

RULES="$1"
CONF=/usr/local/etc/netimpair.conf

if [ ! -s "$CONF" ]; then
    exec /sbin/dnctl "$RULES"
fi

OUT=$(mktemp /tmp/dnctl.netimpair.XXXXXX) || exit 1
awk -f "$(dirname "$0")/impair.awk" "$CONF" "$RULES" > "$OUT"
/sbin/dnctl "$OUT"
RC=$?
rm -f "$OUT"
exit $RC
