#!/bin/sh
# Run as root on FreeBSD with os-netimpair installed (CI does this in a VM).
# Loads OPNsense-style pipe lines through /etc/rc.d/dnctl with the plugin's
# override, the way "configctl shaper reload" does, and checks what the
# kernel ended up with.
set -e
fail() { echo "FAIL: $*"; dnctl pipe show; dnctl queue show; exit 1; }
has() { dnctl "$1" show "$2" | grep -q -- "$3" || fail "$1 $2: expected '$3'"; }
hasnt() { ! dnctl "$1" show "$2" | grep -q -- "$3" || fail "$1 $2: unexpected '$3'"; }

# Keep the VM reachable if dummynet pulls in ipfw.
kenv net.inet.ip.fw.default_to_accept=1 >/dev/null
kldload -n dummynet

# Lines as OPNsense's Shaper/dnctl.conf template writes them.
cat > /usr/local/etc/dnctl.conf <<'CONF'
pipe 10000 config bw 100Mbit/s delay 20  type  wf2q+ 
pipe 10001 config bw 50Mbit/s mask src-ip /32  type  fq_codel  target 5ms  interval 100ms  noecn   quantum 1514  limit 10240  flows 1024 
pipe 10002 config bw 10Mbit/s queue 100 type  wf2q+  codel  target 5ms  noecn  
pipe 10003 config bw 1Gbit/s type  wf2q+ 
queue 10000 config pipe 10002 weight 100 codel  noecn 
queue 10001 config pipe 10003 weight 100
CONF
cat > /etc/rc.conf.d/dnctl <<'CONF'
dnctl_enable="YES"
dnctl_rules="/usr/local/etc/dnctl.conf"
CONF
# The plugin's rc.conf.d template, minus its comment.
mkdir -p /usr/local/etc/rc.conf.d
grep '^\[' /usr/local/opnsense/service/templates/OPNsense/NetImpair/rc.conf.d \
    > /usr/local/etc/rc.conf.d/dnctl

printf '10000 100 0.0500\n10001 50 0.1000\n10002 - 0.2000\n' > /usr/local/etc/netimpair.conf
/etc/rc.d/dnctl start
dnctl pipe show; dnctl queue show
has pipe 10000 ' 100 ms'
has pipe 10000 'plr 0.05'
has pipe 10001 ' 50 ms'
has pipe 10001 'plr 0.1'
has pipe 10002 'plr 0.2'
hasnt pipe 10003 'plr'
has queue 10000 'plr 0.2'
hasnt queue 10001 'plr'

# Removing the impairments puts the pipes back as the shaper defines them.
: > /usr/local/etc/netimpair.conf
/etc/rc.d/dnctl start
has pipe 10000 ' 20 ms'
hasnt pipe 10000 'plr'
hasnt pipe 10001 'plr'
hasnt queue 10000 'plr'
echo "engine test passed"
