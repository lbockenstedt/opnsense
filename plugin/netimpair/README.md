# os-netimpair — packet loss and latency for OPNsense

pfSense limiters have **Delay** and **Packet Loss Rate** fields. OPNsense uses the
same FreeBSD engine (dummynet) for its Traffic Shaper, but only exposes Delay and
has no packet loss at all. This add-in fills that gap, so OPNsense can simulate a
bad WAN link in the lab.

It adds **Firewall > Shaper > Impairment**: pick a shaper pipe, set a latency (ms)
and a packet loss (%), Apply.

Requires **OPNsense 25.1 or newer** (older releases load the shaper pipes from
`ipfw.rules`, which this plugin does not patch). Tested against FreeBSD 14
and 15 dummynet in CI (`tests/engine-test.sh`).

## Install

### From the OPNsense GUI (recommended)

Once per firewall, add this plugin's package repository (as root, from the
console or **System > Diagnostics > Command Prompt** / SSH):

```sh
fetch -o /usr/local/etc/pkg/repos/netimpair.conf \
  https://github.com/lbockenstedt/opnsense/releases/download/netimpair-repo/netimpair.conf
```

Then go to **System > Firmware > Plugins**, click **Check for updates**, find
**os-netimpair** and click **+** to install. Updates and removal work from the
same page like any other plugin. The page shows up under
**Firewall > Shaper > Impairment** (reload the browser once).

If the plugin shows as **os-netimpair (misconfigured)** (installed with
1.0.3 or older, which did not register itself), update or reinstall it from
the same page.

The repository is built by `.github/workflows/netimpair-pkg.yml` on every
change to `main` and published on the `netimpair-repo` release. It is not
signed, so `netimpair.conf` sets `signature_type: "none"`.

### By hand

Copy this folder to the OPNsense box and run, as root:

```sh
sh install.sh            # install or update
sh install.sh --remove   # uninstall
```

`build-pkg.sh <dir> <version>` builds the package and repository on any
FreeBSD host.

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
- `dnctl.sh` copies `dnctl.conf`, adds ` delay N` / ` plr X` right after
  `config` on the matching `pipe N config` lines, and ` plr X` on every
  `queue M config pipe N` line of that pipe (`impair.awk`), then loads the copy
  with `/sbin/dnctl`. The options go right after `config` because dnctl
  treats everything after `type fq_codel` / `codel` / `pie` as scheduler
  parameters and would silently ignore them at the end of the line.

No OPNsense files are changed, so firmware updates keep working. With nothing
configured, `dnctl.sh` simply runs `/sbin/dnctl` on the original file.

## Limits

- dummynet has no jitter, so latency is a fixed delay.
- Loss is random per packet (no burst loss).
- An impairment only acts on a pipe that is enabled and that a shaper rule sends
  traffic to (directly or through one of the pipe's queues).
- **Packet loss does nothing on a pipe whose scheduler is FlowQueue-CoDel or
  FlowQueue-PIE**: those FreeBSD schedulers never check the loss rate (pfSense
  has the same limit). Latency still works. Use the default scheduler for a
  lossy pipe.
- One impairment per pipe.

## Configure through the OPNsense API

Everything in the GUI is also an MVC API. Use an OPNsense API key/secret
(basic auth) whose user has the **Firewall: Shaper: Impairment** privilege
(plus **Firewall: Shaper** to manage pipes and rules).

| Call | Method |
| --- | --- |
| `/api/netimpair/settings/search_impairment` | GET/POST |
| `/api/netimpair/settings/get_impairment/<uuid>` | GET |
| `/api/netimpair/settings/add_impairment` | POST |
| `/api/netimpair/settings/set_impairment/<uuid>` | POST |
| `/api/netimpair/settings/del_impairment/<uuid>` | POST |
| `/api/netimpair/settings/toggle_impairment/<uuid>` | POST |
| `/api/netimpair/service/reconfigure` | POST → `{"status":"ok"}` |

```sh
curl -k -u "$KEY:$SECRET" -H 'Content-Type: application/json' \
  -d '{"impairment":{"enabled":"1","pipe":"<pipe uuid>","delay":"100","loss":"5","description":"wan"}}' \
  https://fw/api/netimpair/settings/add_impairment
curl -k -u "$KEY:$SECRET" -X POST https://fw/api/netimpair/service/reconfigure
```

Pipe UUIDs come from `/api/trafficshaper/settings/search_pipes`; pipes and
rules are created with the Traffic Shaper API (`add_pipe`, `add_rule`,
`/api/trafficshaper/service/reconfigure`).

**Lab Manager** drives all of this for you: Firewalls → Impairment takes a host
or subnet, interface, latency, loss and direction, and creates the pipes,
rules and impairments (tagged `lm-impair:` in their descriptions).

## Compared with pfSense limiters

| | pfSense limiter | os-netimpair |
| --- | --- | --- |
| Delay | 0–10000 ms on the limiter | 0–10000 ms per pipe |
| Packet loss | on the limiter; the queue PLR field is never applied | per pipe, also applied to the pipe's queues |
| FQ-CoDel / FQ-PIE | loss ignored by the kernel | same |
| Jitter / burst loss | no | no |
| Matching traffic | firewall rule In/Out pipe | Traffic Shaper rule |
