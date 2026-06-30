# OPNsense Spoke API Specification

The OPNsense Spoke acts as a bridge between the Lab Manager Hub and the OPNsense firewall. Communication occurs via signed JSON messages over WebSockets.

## Command Set

### Management
- **`UPDATE_CONFIG`**
  - **Purpose**: Updates the connection details for the OPNsense engine.
  - **Payload**: `{"opn_host": "string", "api_key": "string", "api_secret": "string"}`
  - **Response**: `{"status": "SUCCESS", "message": "..."}`

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

## Integration Flow
1. **Command Trigger**: The Hub sends a signed WebSocket message with `command_type` (e.g., `OPNSENSE_ADD_RULE`).
2. **Execution**: The `OpnSpoke` handles the command and calls the `OpnsenseEngine`.
3. **API Call**: The Engine performs an authenticated REST request to the OPNsense API.
4. **Response**: The result is returned as a signed JSON response back to the Hub.
