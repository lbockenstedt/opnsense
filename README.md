# opnsense — OPNsense Firewall Spoke (Lab Manager Module)

The **OPNsense Spoke** (`module_type = "firewall"`) connects the Lab Manager Hub to an OPNsense firewall instance. It provides full-featured remote management of firewall rules, reusable aliases, NAT policies, Unbound DNS host overrides, interface telemetry, and certificate installation directly from the Lab Manager WebUI. Additionally, it serves as a continuous discovery source feeding live Kea DHCP leases and ARP neighbor tables to NetBox for automated IPAM/DCIM inventory updates.

---

## Architecture Overview

The spoke dials the Lab Manager Hub over an outbound TLS WebSocket connection (`wss://<hub>:443/ws/spoke`) using the standard mailbox push-ack-retry contract (`BaseSpoke`). It translates commands received from the hub into HTTPS REST API calls against the target OPNsense firewall (default port 8443).

```
                  ┌─────────────────────────────────────────────────────────┐
                  │                    Lab Manager Hub                      │
                  │       (WebUI / REST API / Discovery Relay)              │
                  └────────────────────────────┬────────────────────────────┘
                                               │ WebSocket (Port 443)
                                               ▼
                  ┌─────────────────────────────────────────────────────────┐
                  │                  OpnSpoke (BaseSpoke)                   │
                  │   src/opn_spoke.py ── Dispatch, Cache & Refresh Loop    │
                  └────────────────────────────┬────────────────────────────┘
                                               │ HTTPS REST API (Port 8443)
                                               ▼
                  ┌─────────────────────────────────────────────────────────┐
                  │                   OPNsense Firewall                     │
                  │   Filter / Aliases / NAT / Unbound DNS / Kea DHCP / ARP │
                  └─────────────────────────────────────────────────────────┘
```

### Key Architectural Patterns

- **`src/opn_spoke.py` (`OpnSpoke`)**: Core command router, in-memory TTL caching layer, sensitive credential masking, and background refresh scheduler (`_cache_refresh_loop`).
- **`src/opnsense_engine.py` (`OpnsenseEngine`)**: REST API abstraction interacting with OPNsense endpoints using system `curl` to ensure robust TLS handshake and header negotiation.
- **In-Memory Cache & Startup Priming**: Read-heavy endpoints (interface status, system health, rules, aliases, NAT, DNS, stats, ARP) are cached with a configurable TTL (default 60s) and refreshed via a periodic 1-hour background sweep. The cache is automatically primed on startup to eliminate cold-cache latency.
- **Live Volatile Reads**: Dynamic DHCP leases (`OPNSENSE_GET_DHCP_LEASES`) deliberately bypass the cache and query Kea DHCP live on every call to prevent serving stale lease states.
- **Write Invalidation & Auto-Apply**: Mutations (adding, editing, or deleting rules, aliases, NAT, or DNS records) immediately invalidate the corresponding cached GET responses and invoke OPNsense reconfigure/apply hooks so changes take effect in real time.
- **Hub-Brokered TLS Distribution**: Handles certificate payloads delivered from the Let's Encrypt (`le`) spoke via `OPNSENSE_INSTALL_CERT`, importing leaf certificates and signing CAs into OPNsense Trust Authorities.

---

## Key Features

1. **Firewall Filter Rules**: Inspect, create, edit, and delete filter rules across all physical and virtual interfaces, with instant atomic reconfiguration.
2. **Aliases & Categories**: Create and modify IP, network, port, and URL table aliases. Category names are automatically translated to and from OPNsense internal UUIDs.
3. **NAT Policies**: Support for Destination NAT (`d_nat`), Source NAT (`source_nat`), and 1:1 NAT (`one_to_one`) utilizing OPNsense 26.1+ MVC controllers.
4. **Unbound DNS Host Overrides**: Inspect, add, edit, and remove custom DNS host overrides with automatic Unbound daemon reload.
5. **Kea DHCP Leases & Static Mappings**: Monitor active IPv4 dynamic leases and reservations with tenant CIDR scoping and fast MAC/hostname substring searches.
6. **ARP Neighbor Discovery**: Extract live ARP neighbor tables, pairing IP and MAC addresses for static-IP and non-DHCP devices.
7. **NetBox Discovery Ingestion**: Continuously feeds DHCP leases and ARP neighbors into the NetBox spoke (`NETBOX_SYNC_DEVICES`) with `source="opnsense"`.
8. **Interface Telemetry & System Health**: Real-time status reporting of interface link state, MTU, IP/MAC addresses, media flags, CPU utilization, and RAM metrics.
9. **Trust Store Management**: Idempotent import and renewal of leaf SSL/TLS certificates and intermediate CA chains into the firewall trust store.

---

## Spoke Commands Reference Table

| Spoke Command | Handler / Target | Description |
| :--- | :--- | :--- |
| `GET_VERSION` | `get_version` | Returns the current spoke version and commit hash. |
| `UPDATE_CONFIG` | `OpnSpoke.__init__` / config | Reconfigures target firewall host, port, API credentials, and cache intervals. |
| `SPOKE_UPDATE` | Self-update | Triggers automated git pull and spoke service reload. |
| `OPNSENSE_REFRESH_CACHE` | `refresh_cache` | Manually triggers an immediate full sweep update of all cached read endpoints. |
| `PROBE_API` | `_request` | Diagnostic probe executing a direct GET against a specified API endpoint. |
| `OPNSENSE_CURL_TEST` | `_request` | Verifies low-level network and TLS connectivity to the firewall. |
| `GET_INTERFACE_STATUS` | `get_interface_status` | Returns normalized link state, IP, MAC, MTU, and flags for all interfaces. |
| `GET_SYSTEM_HEALTH` | `get_system_health` | Queries firewall CPU, memory, and runtime diagnostics. |
| `OPNSENSE_GET_FIREWALL_STATS` | `get_firewall_stats` | Fetches packet counters, byte rates, and filter diagnostic statistics. |
| `OPNSENSE_GET_ALL_RULES` | `get_all_firewall_rules` | Lists all configured firewall filter rules across interfaces. |
| `OPNSENSE_GET_RULES_BY_IP` | `get_rules_for_ip` | Filters firewall rules matching a specific source or destination IP. |
| `OPNSENSE_ADD_RULE` | `add_firewall_rule_and_apply` | Adds a new firewall rule and applies changes immediately. |
| `OPNSENSE_EDIT_RULE` | `edit_firewall_rule` | Modifies an existing firewall rule by UUID and applies changes. |
| `OPNSENSE_DEL_RULE` | `delete_firewall_rule_and_apply` | Deletes a firewall rule by UUID and triggers filter reload. |
| `OPNSENSE_GET_ALIASES` | `get_all_aliases` | Lists all firewall aliases with category UUIDs resolved to display names. |
| `OPNSENSE_ADD_ALIAS` | `add_alias` | Creates a new alias, resolving category names to UUIDs and reloading filter. |
| `OPNSENSE_EDIT_ALIAS` / `OPNSENSE_UPDATE_ALIAS` | `edit_alias` | Updates an existing alias by UUID, updating category memberships. |
| `OPNSENSE_DEL_ALIAS` | `delete_alias` | Deletes an alias by UUID and triggers alias reconfiguration. |
| `OPNSENSE_GET_NAT_POLICIES` | `get_nat_policies` | Probes Destination NAT, Source NAT, and 1:1 NAT rules from MVC controllers. |
| `OPNSENSE_ADD_NAT_RULE` | `add_nat_rule` | Provisions a new NAT policy rule (`d_nat`, `source_nat`, or `one_to_one`). |
| `OPNSENSE_EDIT_NAT_RULE` | `edit_nat_rule` | Modifies an existing NAT policy rule by UUID. |
| `OPNSENSE_DEL_NAT_RULE` | `delete_nat_rule` | Deletes a NAT policy rule by UUID. |
| `OPNSENSE_GET_DNS_RECORDS` | `get_dns_records` | Lists all Unbound DNS host overrides. |
| `OPNSENSE_ADD_DNS_RECORD` | `add_dns_record` | Creates an Unbound DNS host override and reconfigures the service. |
| `OPNSENSE_EDIT_DNS_RECORD` | `edit_dns_record` | Modifies an existing Unbound DNS host override by UUID. |
| `OPNSENSE_DEL_DNS_RECORD` | `delete_dns_record` | Removes an Unbound DNS host override by UUID. |
| `OPNSENSE_GET_DHCP_LEASES` | `get_dhcp_leases` | Live query of active Kea DHCP leases (uncapped or capped by `limit`). |
| `SEARCH_DHCP` | `search_dhcp` | Performs tenant-scoped search across dynamic leases and static mappings. |
| `OPNSENSE_GET_ARP_TABLE` | `get_arp_table` | Retrieves full ARP neighbor cache for static IP and neighbor discovery. |
| `OPNSENSE_INSTALL_CERT` / `INSTALL_CERT` | `import_cert` | Imports leaf certificates and CA chains into OPNsense Trust Authorities. |

---

<!-- INSTALLERS:START -->
## Installation

Every installer in this repo, with every flag and environment variable it accepts.
Installers are idempotent — re-running one updates code and preserves credentials.

### OPNsense (firewall) spoke — `install_opnsense.sh`

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/opnsense/main/install_opnsense.sh \
  | sudo bash -s -- --hub lm-hub.lrbtechnologies.com
```

`HUB_URL` defaults to `auto` — the spoke rediscovers the hub on every connect.

| Flag | Purpose |
| :--- | :--- |
| `--hub URL` | Hub WebSocket URL. A bare host is fine — `lm-hub.example.com` becomes `wss://lm-hub.example.com:443`, `host:port` gets a `wss://` prefix, and an explicit `ws://`/`wss://` is left alone. Omit it to auto-discover the hub (DNS `lm-hub.<suffix>`, then mDNS `_lm-hub._tcp.local.`). |
| `--id`, `--name` | Pin the spoke id. Omitted, the id derives from the hostname, so a renamed clone reconnects under its new name. |
| `--secret` | Pre-shared spoke secret. |
| `--hub-secret` | Hub PSK for auto-approval. Without it the spoke lands in *pending approval* in the WebUI. |
| `--all-prereqs` | Accepted and ignored — kept so the hub's install-module call doesn't abort. |

**Environment overrides:** `HUB_URL` (same normalization as `--hub`), `SPOKE_ID`.
<!-- INSTALLERS:END -->
