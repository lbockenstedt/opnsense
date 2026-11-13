# OPNsense Spoke API Specification

The OPNsense Spoke acts as a bridge between the Lab Manager Hub and the OPNsense firewall. Communication occurs via signed JSON messages over WebSockets.

## Command Set

### Management
- **`UPDATE_CONFIG`**
  - **Purpose**: Updates the connection details for the OPNsense engine.
  - **Payload**: `{"id": "string", "opn_host": "string", "api_key": "string", "api_secret": "string", "firewalls": [{"id", "host", "port", "api_key", "api_secret"}, ...]}`
    - The top-level fields are the **default firewall**. `firewalls` (optional,
      sent by newer hubs) lists **every** firewall bound to this spoke, for
      example both boxes of an HA pair. Leaving it out keeps the current list.
      `{"firewalls": []}` with no `id` means no firewall is bound to this
      spoke any more: the spoke forgets every firewall and its credentials.
  - **Response**: `{"status": "SUCCESS", "message": "..."}`

### Choosing the firewall (`firewall_id`)
Every other command may carry `"firewall_id": "<hub firewall id>"`. The spoke
runs it against that firewall, with a separate read cache per firewall. With
no `firewall_id` the command goes to the default firewall, so older hubs keep
working. An id the spoke was never given returns
`{"status": "ERROR", "message": "Firewall <id> is not configured on this spoke ..."}`;
the command never falls back to another firewall.

### Firewall Rule Management
- **`OPNSENSE_ADD_RULE`**
  - **Purpose**: Creates a new firewall rule.
  - **Payload**: `{"rule": { "action": "pass|block", "protocol": "TCP|UDP|ANY", "destination": "string", "description": "string" }}`
  - **Response**: `{"status": "SUCCESS", "rule_id": "string", "message": "..."}`
- **`OPNSENSE_DEL_RULE`**
  - **Purpose**: Removes a specific firewall rule.
  - **Payload**: `{"rule_id": "string"}`
  - **Response**: `{"status": "SUCCESS", "message": "..."}`
- **`OPNSENSE_UPDATE_ALIAS`**
  - **Purpose**: Updates a group of hosts (alias).
  - **Payload**: `{"name": "string", "hosts": ["ip1", "ip2"]}`
  - **Response**: `{"status": "SUCCESS", "message": "..."}`

### Monitoring & Telemetry
- **`GET_INTERFACE_STATUS`**
  - **Purpose**: Retrieves current network interface status.
  - **Payload**: `{}`
  - **Response**: `{"status": "SUCCESS", "data": { ... }}`
- **`GET_SYSTEM_HEALTH`**
  - **Purpose**: Retrieves CPU and Memory usage.
  - **Payload**: `{}`
  - **Response**: `{"status": "SUCCESS", "data": { ... }}`
- **`OPNSENSE_GET_OVERVIEW`**
  - **Purpose**: Dashboard snapshot for the Firewalls → Overview tab. Always live (not cached by the spoke). Each section is best-effort: a section the API key can't read is left empty.
  - **Payload**: `{}`
  - **Response**: `{"status": "SUCCESS", "data": {"hostname", "version", "uptime", "loadavg", "cpu_percent", "memory": {"used", "total", "percent"}, "gateways": [{"name", "address", "status", "online", "delay", "loss"}], "interfaces": [{"name", "in_bps", "out_bps"}]}}`
- **`OPNSENSE_GET_PERF_HISTORY`**
  - **Purpose**: Performance history for the Firewalls → Overview charts: 5-minute averages the spoke keeps for 7 days (`src/opn_perf_store.py`).
  - **Payload**: `{"start": epoch, "end": epoch}` (default: the last 24 hours)
  - **Response**: `{"status": "SUCCESS", "interval": 300, "data": [{"ts", "samples", "metrics": {"in_bps", "out_bps", "in_pps", "out_pps", "errps", "cpu", "mem", "states", "if:<interface>:in_bps", ...}}]}`
  - **Push**: each new bucket is also sent unsolicited to the hub as `STORAGE_PERF_SAMPLE` `{"module": "opnsense", "samples": [{"device_id", "ts", "samples", "metrics"}]}`.
- **`OPNSENSE_GET_RULES_BY_IP`**
  - **Purpose**: Filters firewall rules associated with a specific IP.
  - **Payload**: `{"ip": "string"}`
  - **Response**: `{"status": "SUCCESS", "ip": "string", "rules": [...]}`
- **`OPNSENSE_GET_DHCP_LEASES`**
  - **Purpose**: Lists current DHCP leases.
  - **Payload**: `{}` (cached, capped at 200 for the interactive path) **or** `{"limit": 0}` to bypass the cache and return the full uncapped set (used by the firewall→NetBox discovery sync).
  - **Response**: `{"status": "SUCCESS", "data": [{"ip", "hostname", "mac", "lease_end"}, ...]}`
- **`OPNSENSE_GET_ARP_TABLE`**
  - **Purpose**: Lists the firewall's ARP table — every IP→MAC pair for a neighbor it has recently talked to. Captures static-IP devices that never appear in DHCP (cached).
  - **Payload**: `{}`
  - **Response**: `{"status": "SUCCESS", "data": [{"ip", "mac", "hostname", "interface"}, ...]}` (MAC returned raw; the hub/NetBox normalize it).
- **`OPNSENSE_GET_ALL_RULES`**
  - **Purpose**: Lists all firewall rules.
  - **Payload**: `{}`
  - **Response**: `{"status": "SUCCESS", "data": [...]}`
- **`OPNSENSE_GET_FIREWALL_STATS`**
  - **Purpose**: Retrieves firewall packet/byte statistics.
  - **Payload**: `{}`
  - **Response**: `{"status": "SUCCESS", "data": { ... }}`
- **`OPNSENSE_GET_NAT_POLICIES`**
  - **Purpose**: Retrieves NAT and Port Forwarding rules.
  - **Payload**: `{}`
  - **Response**: `{"status": "SUCCESS", "data": [...]}`
- **`OPNSENSE_GET_DNS_RECORDS`**
  - **Purpose**: Retrieves configured DNS records.
  - **Payload**: `{}`
  - **Response**: `{"status": "SUCCESS", "data": [...]}`

### Network Impairment (latency / packet loss / bandwidth, always on or scheduled)
Needs the `os-netimpair` plugin on the firewall (see `plugin/netimpair`) and an
API key with the *Firewall: Shaper* and *Firewall: Shaper: Impairment*
privileges. Each impairment is a Traffic Shaper pipe + rule per direction plus a
netimpair entry, all tagged `lm-impair:<id>:<down|up>` in their description
(`src/impairments.py`). Without the plugin every command returns an ERROR
saying so. OPNsense refuses pipes faster than 4 Gbit/s (dummynet keeps bits/s in
32 bits), so a pipe without a bandwidth limit is created at 4 Gbit/s and a
limit above 4 Gbit/s (compared in bits/s, whatever the unit) is rejected with
"OPNsense pipes are limited to 4 Gbit/s".

**Targets.** `target_type` says what `targets` (an ordered list, at most 32)
holds:
- `ip`: addresses or subnets (`192.0.2.5`, `198.51.100.0/24`);
- `device`: the address of an LM device, picked by name in the hub UI, which
  sends the name in `labels` (one per target) for display;
- `alias`: OPNsense alias names. Shaper rules only take addresses
  (`NetworkField`), not alias names, so the spoke reads the alias list and
  writes each alias's member addresses into the rule (nested aliases are
  followed). An unknown alias, an empty one, or one with a member that is not
  an address (hostname, URL table, port) is refused. The members are copied
  when the impairment is saved: after changing the alias, save the
  impairment again. `alias_members: true` (with exactly one alias) makes each
  member its own target (at most 32 members, like a list of targets).

An older hub sends a single `target` instead; it is treated as `targets` of
one address. Each target gets its own shaper rule per direction.

**Schedule.** `schedule: {"every_hours": 1-720, "for_minutes": 1 to
every_hours*60-1, "start": epoch seconds (0 or missing = when saved)}` turns
the impairment on for `for_minutes` every `every_hours` from `start`;
`null` means always on. Window *k* (counted from `start`) impairs target
`k % len(targets)`, so a list of targets rotates one per window; a single
target is a list of one. Without a schedule every target is impaired at once.
The spoke keeps targets and schedules in `$LM_OPNSENSE_DATA_DIR/impairments.json`
(per firewall) and checks them every 30 s: it enables only the current
window's rules, disables them all outside a window, and applies
(`trafficshaper/service/reconfigure`) only when a rule changed. The answer is
worked out from the clock, so a restarted spoke puts the right rule on (or
all off) on its first pass, and switches off any scheduled rule whose
schedule is gone (lost file). If switching fails, the spoke switches every
rule of that impairment off, stores the error (shown in the list) and retries
on the next pass; a failed shaper reload is repeated every pass until it
works, since a toggled rule only takes effect after a reload. A stored
schedule whose rules are gone is dropped the next time the spoke reads the
rules (each window boundary, and after a restart). Targets
or a schedule that cannot be saved (except plain always-on addresses, which
need nothing stored) make the add or edit fail with nothing changed. A spoke that is stopped cannot switch anything: an impairment that
was on stays on until the spoke runs again.

- **`OPNSENSE_GET_IMPAIRMENTS`**
  - **Payload**: `{}`
  - **Response**: `{"status": "SUCCESS", "data": [{"uuid", "target", "target_type", "targets", "labels", "alias_members", "interface", "direction", "delay", "loss", "bandwidth", "bandwidth_unit", "description", "enabled", "complete", "active", "active_target", "schedule", "next_on", "next_off", "next_target", "error", "error_at"}]}`. `target` is the display text (labels or targets, comma-separated); `bandwidth` 0 means no limit; `active` is true while a rule is impairing, `active_target` names which; `next_on`/`next_off` (epoch seconds) and `next_target` come from the schedule (null when always on or disabled); `error` is the scheduler's last failure ("" when fine).
- **`OPNSENSE_GET_IMPAIRMENT_OPTIONS`**
  - **Payload**: `{}`
  - **Response**: `{"status": "SUCCESS", "interfaces": [{"key": "lan", "description": "LAN"}, ...]}`: the interfaces a shaper rule accepts, read live from `GET /api/trafficshaper/settings/get_rule` (a new rule's defaults; the option keys of `interface`, i.e. assigned and enabled interfaces). `{"status": "ERROR", ...}` when it cannot be read.
- **`OPNSENSE_ADD_IMPAIRMENT`**
  - **Payload**: `{"target_type": "ip|alias|device", "targets": [...], "labels": [...], "alias_members": false, "schedule": null | {...}, "interface": "lan", "direction": "both|download|upload", "delay": ms (0-10000), "loss": % (0-100), "bandwidth": optional whole number (blank/0 = no limit), "bandwidth_unit": "Kbit|Mbit|Gbit" (default Mbit, at most 4 Gbit/s in total), "description": "", "enabled": "1"}`. `interface` must be one of the `OPNSENSE_GET_IMPAIRMENT_OPTIONS` keys; any other value (or an unreadable list) is refused before anything is created, with the valid choices in the message. At least one of delay, loss or bandwidth must be set. `enabled: "0"` keeps a scheduled impairment off.
  - **Response**: `{"status": "SUCCESS", "uuid": "<id>"}`. A failed step deletes what was already created.
- **`OPNSENSE_EDIT_IMPAIRMENT`**
  - **Payload**: the add payload plus `"uuid"`. The new version is built before the old one is removed, so a failed edit keeps the original; the response carries the new `uuid`. Turning an impairment on or off is an edit with `enabled` changed.
- **`OPNSENSE_DEL_IMPAIRMENT`**
  - **Payload**: `{"uuid": "<id>"}`

## Integration Flow
1. **Command Trigger**: The Hub sends a signed WebSocket message with `command_type` (e.g., `OPNSENSE_ADD_RULE`).
2. **Execution**: The `OpnSpoke` handles the command and calls the `OpnsenseEngine`.
3. **API Call**: The Engine performs an authenticated REST request to the OPNsense API.
4. **Response**: The result is returned as a signed JSON response back to the Hub.
