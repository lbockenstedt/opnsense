# os-netimpair — packet loss and latency for OPNsense

pfSense limiters have **Delay** and **Packet Loss Rate** fields. OPNsense uses the
same FreeBSD engine (dummynet) for its Traffic Shaper, but only exposes Delay and
has no packet loss at all. This add-in fills that gap, so OPNsense can simulate a
bad WAN link in the lab.

It adds **Firewall > Shaper > Impairment**: pick a shaper pipe, set a latency (ms)
and a packet loss (%), Apply.

## Install

Copy this folder to the OPNsense box and run, as root:

```sh
sh install.sh            # install or update
sh install.sh --remove   # uninstall
```

It can also be built as a real package from an
[opnsense/plugins](https://github.com/opnsense/plugins) checkout (put it at
`net/netimpair`, then `make package`).

## Use

1. **Firewall > Shaper > Pipes**: add a pipe, e.g. bandwidth 1000 Mbit/s
   (high, so only the impairment limits traffic), description `wan-lossy`.
2. **Firewall > Shaper > Rules**: add a rule that sends the traffic you want to
   impair (an interface, a host, a subnet...) to that pipe. Use two pipes and
   two rules (in and out) to impair both directions.
3. **Firewall > Shaper > Impairment**: add an entry for the pipe with
   e.g. latency `100` and packet loss `5`, then **Apply**.
4. Check from a shell: `dnctl pipe show` lists `100 ms` and `plr 0.050000`
   for the pipe; `ping` through it shows the loss and extra round-trip time.

To stop impairing, disable or delete the entry and Apply. The pipe and rule stay
as they are.

## How it works

The Traffic Shaper writes its pipes to `/usr/local/etc/dnctl.conf`, and
`/etc/rc.d/dnctl` loads that file with `$dnctl_program` (normally `/sbin/dnctl`).
The plugin:

- writes `/usr/local/etc/rc.conf.d/dnctl`, which rc reads after OPNsense's own
  `/etc/rc.conf.d/dnctl`, to set `dnctl_program` to
  `scripts/OPNsense/NetImpair/dnctl.sh`;
- writes `/usr/local/etc/netimpair.conf`: one line per enabled impairment,
  `<pipe number> <delay ms or -> <loss fraction>`;
- `dnctl.sh` copies `dnctl.conf`, adds ` delay N` / ` plr X` to the matching
  `pipe N config` lines (`impair.awk`), and loads the copy with `/sbin/dnctl`.

No OPNsense files are changed, so firmware updates keep working. With nothing
configured, `dnctl.sh` simply runs `/sbin/dnctl` on the original file.

## Limits

- dummynet has no jitter, so latency is a fixed delay.
- Loss is random per packet (no burst loss).
- An impairment only acts on a pipe that is enabled and that a shaper rule sends
  traffic to.
