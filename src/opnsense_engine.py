import logging
import os
import base64
import time
from typing import Dict, Any, List, Optional

logger = logging.getLogger("OpnsenseEngine")

class OpnsenseEngine:
    """
    Core interaction layer for the OPNsense API.
    Handles Firewall rule management and Interface monitoring.
    """
    def __init__(self, host: str, api_key: str, api_secret: str):
        self.host = host
        self.api_key = api_key
        self.api_secret = api_secret

    async def _request(self, method: str, endpoint: str, data: Dict = None) -> Dict[str, Any]:
        """Internal helper to handle OPNsense API requests using system curl.
        Bypasses Python network stack issues that cause ConnectError while system curl works.
        """
        import json
        import asyncio
        import subprocess

        # Use the direct endpoint which now includes the /api prefix
        url = f"https://{self.host}{endpoint}"
        logger.info(f"Attempting API request to: {url}")

        # Lab firewalls use self-signed certs by default. Skip TLS verification
        # unless LM_OPNSENSE_VERIFY_TLS=1 is explicitly set in the environment.
        cmd = ["curl", "-s", "--max-time", "15"]
        if os.getenv("LM_OPNSENSE_VERIFY_TLS") != "1":
            cmd.append("-k")
        cmd.extend([
            "-u", f"{self.api_key}:{self.api_secret}",
            "-X", method,
            "-H", "Accept: application/json",
        ])
        # Only send Content-Type + body when there is a body — OPNsense returns
        # "Invalid JSON syntax" if it sees Content-Type: application/json with no body.
        if data is not None:
            cmd.extend(["-H", "Content-Type: application/json", "-d", json.dumps(data)])
        cmd.append(url)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                error_msg = stderr.decode().strip() or f"Curl failed with code {process.returncode}"
                logger.error(f"Curl request failed for {url}: {error_msg}")
                return {"status": "ERROR", "message": error_msg}

            result_text = stdout.decode().strip()
            if not result_text:
                return {"status": "ERROR", "message": "Empty response from server"}

            result = json.loads(result_text)
            logger.info(f"API request to {url} succeeded. Response keys: {list(result.keys()) if isinstance(result, dict) else 'Not a dict'}")
            return result

        except Exception as e:
            logger.exception(f"Exception during API request to {url}")
            return {"status": "ERROR", "message": str(e)}

    async def get_interface_status(self) -> Dict[str, Any]:
        """Fetches current status of network interfaces."""
        res = await self._request("GET", "/api/interfaces/overview/interfaces_info")

        if isinstance(res, dict):
            if res.get("status") == "ERROR" or "error" in res:
                return {"status": "ERROR", "details": res}

            # OPNsense usually returns a dict where keys are interface names
            # Convert to a list of dicts for easier UI consumption
            interfaces = []

            # Try to find the actual data payload
            data_payload = res.get("data") or res.get("rows") or res

            if isinstance(data_payload, dict):
                for iface_name, info in data_payload.items():
                    if isinstance(info, dict):
                        # Normalize interface data for UI consistency
                        processed_iface = {
                            "name": iface_name,
                            "ip": info.get("addr4") or info.get("ipaddr") or "N/A",
                            "status": info.get("status", "unknown"),
                            "mac": info.get("macaddr", "unknown"),
                            "mtu": info.get("mtu", "unknown"),
                            "media": info.get("media", "unknown"),
                            "description": info.get("description", ""),
                            "flags": ",".join(info.get("flags") if isinstance(info.get("flags"), list) else []),
                            "capabilities": ",".join(info.get("capabilities") if isinstance(info.get("capabilities"), list) else [])
                        }
                        interfaces.append(processed_iface)
                    else:
                        interfaces.append({"name": iface_name, "status": info, "ip": "N/A"})
            elif isinstance(data_payload, list):
                # If it's already a list, we still want to normalize a few keys
                for iface in data_payload:
                    if isinstance(iface, dict):
                        if "addr4" in iface and "ip" not in iface:
                            iface["ip"] = iface["addr4"]
                        if "flags" in iface and isinstance(iface["flags"], list):
                            iface["flags"] = ",".join(iface["flags"])
                        if "capabilities" in iface and isinstance(iface["capabilities"], list):
                            iface["capabilities"] = ",".join(iface["capabilities"])
                interfaces = data_payload

            return {"status": "SUCCESS", "data": interfaces}

        return {"status": "ERROR", "message": "Unexpected API response format"}

    async def add_firewall_rule(self, rule_config: Dict[str, Any]) -> Dict[str, Any]:
        """Adds a new firewall rule to the specified interface."""
        res = await self._request("POST", "/api/firewall/filter/add_rule", data=rule_config)
        if isinstance(res, dict) and (res.get("status") == "ERROR" or "error" in res):
            return {"status": "ERROR", "details": res}
        return {"status": "SUCCESS", "rule_id": res.get("id"), "message": "Rule added successfully"}

    async def delete_firewall_rule(self, rule_id: str) -> Dict[str, Any]:
        """Deletes a specific firewall rule."""
        # OPNsense uses POST for deletion with the UUID in the data payload
        res = await self._request("POST", "/api/firewall/filter/del_rule", data={"uuid": rule_id})
        if isinstance(res, dict) and (res.get("status") == "ERROR" or "error" in res):
            return {"status": "ERROR", "details": res}
        return {"status": "SUCCESS", "message": f"Rule {rule_id} deleted"}

    async def manage_alias(self, alias_name: str, hosts: List[str], action: str = "update") -> Dict[str, Any]:
        """Manages OPNsense aliases (groups of IPs/Hosts)."""
        # For update/create, OPNsense uses /firewall/alias/set
        data = {"name": alias_name, "hosts": hosts}
        endpoint = "/api/firewall/alias/set" if action == "update" else "/api/firewall/alias/del_item"
        method = "POST"

        if action != "update":
            data = {"alias": alias_name} # Simplification for deletion

        res = await self._request(method, endpoint, data=data)
        if isinstance(res, dict) and (res.get("status") == "ERROR" or "error" in res):
            return {"status": "ERROR", "details": res}
        return {"status": "SUCCESS", "message": f"Alias {alias_name} {action}d successfully"}

    async def get_system_health(self) -> Dict[str, Any]:
        """Fetches basic system health (CPU/Memory)."""
        res = await self._request("GET", "/api/diagnostics/systemhealth/get_system_health")
        if isinstance(res, dict) and (res.get("status") == "ERROR" or "error" in res):
            return {"status": "ERROR", "details": res}
        return {"status": "SUCCESS", "data": res}

    async def get_all_firewall_rules(self) -> Dict[str, Any]:
        """Fetches all firewall rules across all interfaces."""
        res = await self._request("POST", "/api/firewall/filter/search_rule", data={})

        # Handle API errors returned as JSON
        if isinstance(res, dict):
            if res.get("status") == "ERROR" or "error" in res or "errorMessage" in res:
                return {"status": "ERROR", "details": res}

            # Extract rules list from response
            rules_data = res.get("rules") or res.get("data") or res.get("rows")

            if rules_data is None or (isinstance(rules_data, list) and len(rules_data) == 0):
                logger.info(f"API returned success but no rules found. Response: {res}")
                return {"status": "SUCCESS", "data": [], "source": "empty"}

            # OPNsense often returns rules as a dict { "uuid": {rule_data} }
            if isinstance(rules_data, dict):
                # Convert dict values to a list and inject the key (uuid) as the 'id'
                processed_rules = []
                for uuid, rule in rules_data.items():
                    if isinstance(rule, dict):
                        rule['id'] = uuid
                        processed_rules.append(rule)
                    else:
                        processed_rules.append({"id": uuid, "raw": rule})
                rules = processed_rules
            elif isinstance(rules_data, list):
                rules = rules_data
            else:
                rules = []

            # Map OPNsense fields to WebUI expected fields: id, action, protocol, source, destination, description
            final_rules = []
            for r in rules:
                if isinstance(r, dict):
                    # Combine destination network and port for the UI display
                    dest_net = r.get("destination_net", "any")
                    dest_port = r.get("destination_port", "")
                    destination = f"{dest_net}:{dest_port}" if dest_port else dest_net

                    # Source network/IP
                    source = r.get("source", "any")

                    final_rules.append({
                        "id": r.get("uuid", "unknown"),
                        "action": r.get("action") or r.get("%action") or "pass",
                        "protocol": r.get("protocol", "TCP").upper(),
                        "source": source,
                        "destination": destination,
                        "category": r.get("category") or "",
                        "description": r.get("description") or r.get("descr", "No description")
                    })
                else:
                    final_rules.append({"id": "unknown", "raw": str(r)})

            # Safety limit to prevent massive payloads causing LLM 400 errors (Payload Too Large)
            if len(final_rules) > 200:
                logger.warning(f"Truncating firewall rules from {len(final_rules)} to 200 for stability")
                final_rules = final_rules[:200]

            return {"status": "SUCCESS", "data": final_rules}

        return {"status": "ERROR", "message": "Unexpected API response format"}

    async def get_firewall_stats(self) -> Dict[str, Any]:
        """Fetches general firewall statistics (packet counts, etc)."""
        res = await self._request("GET", "/api/diagnostics/firewall/stats")
        if isinstance(res, dict) and (res.get("status") == "ERROR" or "error" in res):
            return {"status": "ERROR", "details": res}
        return {"status": "SUCCESS", "data": res}

    async def get_dns_records(self) -> Dict[str, Any]:
        """Fetches Unbound DNS host overrides."""
        res = await self._request("GET", "/api/unbound/settings/searchHostOverride")

        if isinstance(res, dict):
            # The response contains a 'rows' list of overrides
            rows = res.get("rows")
            if rows is None:
                logger.info(f"DNS API returned success but no records found. Response: {res}")
                return {"status": "SUCCESS", "data": [], "source": "empty"}

            if not isinstance(rows, list):
                rows = []

            processed_dns = []
            for record in rows:
                if isinstance(record, dict):
                    # Combine hostname and domain for the display
                    hostname = record.get("hostname", "unknown")
                    domain = record.get("domain", "")
                    fqdn = f"{hostname}.{domain}" if domain else hostname

                    processed_dns.append({
                        "id": record.get("uuid", ""),
                        "hostname": fqdn,
                        "domain": record.get("domain", ""),
                        "ip": record.get("server", "unknown"),
                        "type": record.get("rr", "A"),
                        "ttl": 3600,
                        "description": record.get("description", ""),
                    })

            return {"status": "SUCCESS", "data": processed_dns}

        return {"status": "ERROR", "message": "Unexpected API response format"}

    @staticmethod
    def _nat_source(rule: dict) -> str:
        """Extract a NAT rule's source address into a single displayable string.

        OPNsense NAT search_rule rows expose the source under several possible
        keys (``source`` as a dict or string, ``%source.network`` /
        ``source.network`` / ``source.address``). Returns the first non-empty,
        non-``any`` value found, else ``"any"`` so the LM subnet filter can treat
        an unspecified source as a wildcard (skipped, not matched).
        """
        for key in ("source", "%source.network", "source.network", "source.address", "source_net"):
            v = rule.get(key)
            if v is None:
                continue
            if isinstance(v, dict):
                v = v.get("address") or v.get("network") or v.get("any") or ""
            s = str(v or "").strip()
            if s and s.lower() != "any":
                return s
        return "any"

    async def get_nat_policies(self) -> Dict[str, Any]:
        """Fetches NAT policies from OPNsense.
        Probes multiple NAT endpoints (Destination NAT, Outbound NAT, 1:1 NAT) to ensure full coverage.
        """
        # Endpoints to probe for NAT rules: (url, label, method)
        endpoints = [
            ("/api/firewall/d_nat/search_rule", "Destination NAT", "POST"),
            ("/api/firewall/source_nat/search_rule", "Outbound NAT", "GET"),
            ("/api/firewall/nat_1to1/search_rule", "1:1 NAT", "GET")
        ]

        all_processed_nat = []
        found_any = False

        for endpoint, label, method in endpoints:
            logger.info(f"Probing NAT endpoint: {endpoint} ({label}) via {method}")

            # Use show_all=1 for GET requests to ensure full retrieval
            request_url = f"{endpoint}?show_all=1" if method == "GET" else endpoint

            # For POST requests, we send an empty dict if no specific filter is needed,
            # as OPNsense often expects a JSON body for search_rule POSTs
            data = {} if method == "POST" else None

            res = await self._request(method, request_url, data=data)

            if isinstance(res, dict):
                rows = res.get("rows") or res.get("data") or res.get("rules")
                if rows and isinstance(rows, list):
                    logger.info(f"Found {len(rows)} rules in {label} endpoint.")
                    found_any = True
                    for rule in rows:
                        if isinstance(rule, dict):
                            # Map OPNsense NAT fields to a consistent format
                            # Destination NAT uses different fields than Outbound NAT
                            all_processed_nat.append({
                                "id": rule.get("uuid", "unknown"),
                                "type": label,
                                "protocol": rule.get("protocol", "TCP"),
                                "source": _nat_source(rule),
                                "external_ip": rule.get("%destination.network") or rule.get("destination.network") or "any",
                                "external_port": rule.get("destination.port") or rule.get("external_port") or rule.get("dest_port") or "N/A",
                                "internal_ip": rule.get("target") or rule.get("internal_ip") or rule.get("dest_address") or "unknown",
                                "internal_port": rule.get("local-port") or rule.get("internal_port") or rule.get("dest_port") or "All",
                                "category": rule.get("category") or "",
                                "description": rule.get("descr") or rule.get("description") or f"{label} Rule"
                            })
                            # Debug log to help identify missing fields if user reports issues
                            if not rule.get("dest_address") and not rule.get("internal_ip"):
                                logger.debug(f"NAT rule {rule.get('uuid')} missing IP fields. Keys: {list(rule.keys())}")
                else:
                    logger.info(f"No rules found in {label} endpoint.")
            else:
                logger.warning(f"Unexpected response format for {label} endpoint.")

        if not found_any:
            logger.info("All NAT endpoints probed; no rules found.")
            return {"status": "SUCCESS", "data": [], "source": "empty"}

        # Safety limit to prevent massive payloads causing LLM 400 errors (Payload Too Large)
        if len(all_processed_nat) > 200:
            logger.warning(f"Truncating NAT rules from {len(all_processed_nat)} to 200 for stability")
            all_processed_nat = all_processed_nat[:200]

        return {"status": "SUCCESS", "data": all_processed_nat}

    async def apply_firewall_changes(self) -> Dict[str, Any]:
        """Applies pending firewall rule changes."""
        res = await self._request("POST", "/api/firewall/filter/apply", data={})
        return {"status": "SUCCESS", "message": "Firewall changes applied"} if not (isinstance(res, dict) and res.get("status") == "ERROR") else res

    async def get_all_aliases(self) -> Dict[str, Any]:
        """Fetches all firewall aliases."""
        res = await self._request("GET", "/api/firewall/alias/searchItem")
        if isinstance(res, dict):
            rows = res.get("rows") or res.get("data") or []
            processed = []
            for row in (rows if isinstance(rows, list) else []):
                if isinstance(row, dict):
                    processed.append({
                        "id": row.get("uuid", "unknown"),
                        "name": row.get("name", ""),
                        "type": row.get("type", ""),
                        "content": row.get("content", ""),
                        "category": row.get("category") or "",
                        "description": row.get("description", ""),
                    })
            return {"status": "SUCCESS", "data": processed}
        return {"status": "ERROR", "message": "Unexpected API response format"}

    async def add_alias(self, name: str, type_: str, content: str, description: str = "", category: str = "") -> Dict[str, Any]:
        """Adds a new firewall alias. ``category`` tags the alias so the LM hub
        tenant filter can attribute it to a tenant by name/slug (an alias whose
        category matches the tenant shows regardless of its content IPs)."""
        data = {"alias": {"name": name, "type": type_, "content": content, "description": description, "category": category, "enabled": "1"}}
        res = await self._request("POST", "/api/firewall/alias/addItem", data=data)
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        await self._request("POST", "/api/firewall/alias/reconfigure", data={})
        return {"status": "SUCCESS", "message": f"Alias '{name}' added"}

    async def delete_alias(self, uuid: str) -> Dict[str, Any]:
        """Deletes a firewall alias by UUID."""
        res = await self._request("POST", f"/api/firewall/alias/delItem/{uuid}", data={})
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        await self._request("POST", "/api/firewall/alias/reconfigure", data={})
        return {"status": "SUCCESS", "message": f"Alias {uuid} deleted"}

    async def add_firewall_rule_and_apply(self, rule_config: Dict[str, Any]) -> Dict[str, Any]:
        """Adds a firewall rule and applies it."""
        res = await self.add_firewall_rule(rule_config)
        if res.get("status") == "SUCCESS":
            await self.apply_firewall_changes()
        return res

    async def delete_firewall_rule_and_apply(self, rule_id: str) -> Dict[str, Any]:
        """Deletes a firewall rule and applies changes."""
        res = await self.delete_firewall_rule(rule_id)
        if res.get("status") == "SUCCESS":
            await self.apply_firewall_changes()
        return res

    async def add_nat_rule(self, nat_type: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Adds a NAT rule. nat_type: 'd_nat' | 'source_nat' | 'nat_1to1'."""
        endpoint_map = {
            "d_nat": "/api/firewall/d_nat/addRule",
            "source_nat": "/api/firewall/source_nat/addRule",
            "nat_1to1": "/api/firewall/nat_1to1/addRule",
        }
        endpoint = endpoint_map.get(nat_type, endpoint_map["d_nat"])
        res = await self._request("POST", endpoint, data={"rule": rule})
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        await self._request("POST", "/api/firewall/filter/apply", data={})
        return {"status": "SUCCESS", "message": f"NAT rule added ({nat_type})"}

    async def delete_nat_rule(self, nat_type: str, uuid: str) -> Dict[str, Any]:
        """Deletes a NAT rule by UUID."""
        endpoint_map = {
            "d_nat": f"/api/firewall/d_nat/delRule/{uuid}",
            "source_nat": f"/api/firewall/source_nat/delRule/{uuid}",
            "nat_1to1": f"/api/firewall/nat_1to1/delRule/{uuid}",
        }
        endpoint = endpoint_map.get(nat_type, endpoint_map["d_nat"])
        res = await self._request("POST", endpoint, data={})
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        await self._request("POST", "/api/firewall/filter/apply", data={})
        return {"status": "SUCCESS", "message": f"NAT rule {uuid} deleted"}

    async def add_dns_record(self, hostname: str, domain: str, ip: str, description: str = "") -> Dict[str, Any]:
        """Adds a DNS host override in Unbound."""
        data = {"host": {"hostname": hostname, "domain": domain, "server": ip, "description": description, "enabled": "1"}}
        res = await self._request("POST", "/api/unbound/settings/addHostOverride", data=data)
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        await self._request("POST", "/api/unbound/service/reconfigure", data={})
        return {"status": "SUCCESS", "message": f"DNS record {hostname}.{domain} → {ip} added"}

    async def delete_dns_record(self, uuid: str) -> Dict[str, Any]:
        """Deletes a DNS host override by UUID."""
        res = await self._request("POST", f"/api/unbound/settings/delHostOverride/{uuid}", data={})
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        await self._request("POST", "/api/unbound/service/reconfigure", data={})
        return {"status": "SUCCESS", "message": f"DNS record {uuid} deleted"}

    async def edit_firewall_rule(self, uuid: str, rule_config: Dict[str, Any]) -> Dict[str, Any]:
        """Updates an existing firewall rule by UUID."""
        res = await self._request("POST", f"/api/firewall/filter/setRule/{uuid}", data={"rule": rule_config})
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        await self.apply_firewall_changes()
        return {"status": "SUCCESS", "message": f"Rule {uuid} updated"}

    async def edit_alias(self, uuid: str, name: str, type_: str, content: str, description: str = "", category: str = "") -> Dict[str, Any]:
        """Updates an existing alias by UUID. ``category`` tags the alias for LM
        tenant attribution (matches the tenant's name/slug/netbox-slug/id)."""
        data = {"alias": {"name": name, "type": type_, "content": content, "description": description, "category": category, "enabled": "1"}}
        res = await self._request("POST", f"/api/firewall/alias/setItem/{uuid}", data=data)
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        await self._request("POST", "/api/firewall/alias/reconfigure", data={})
        return {"status": "SUCCESS", "message": f"Alias '{name}' updated"}

    async def edit_nat_rule(self, nat_type: str, uuid: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Updates an existing NAT rule by UUID."""
        endpoint_map = {
            "d_nat": f"/api/firewall/d_nat/setRule/{uuid}",
            "source_nat": f"/api/firewall/source_nat/setRule/{uuid}",
            "nat_1to1": f"/api/firewall/nat_1to1/setRule/{uuid}",
        }
        endpoint = endpoint_map.get(nat_type, endpoint_map["d_nat"])
        res = await self._request("POST", endpoint, data={"rule": rule})
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        await self._request("POST", "/api/firewall/filter/apply", data={})
        return {"status": "SUCCESS", "message": f"NAT rule updated ({nat_type})"}

    async def edit_dns_record(self, uuid: str, hostname: str, domain: str, ip: str, description: str = "") -> Dict[str, Any]:
        """Updates an existing DNS host override by UUID."""
        data = {"host": {"hostname": hostname, "domain": domain, "server": ip, "description": description, "enabled": "1"}}
        res = await self._request("POST", f"/api/unbound/settings/setHostOverride/{uuid}", data=data)
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        await self._request("POST", "/api/unbound/service/reconfigure", data={})
        return {"status": "SUCCESS", "message": f"DNS record {uuid} updated"}

    async def get_rules_for_ip(self, ip: str) -> Dict[str, Any]:
        """Fetches all firewall rules associated with a specific IP address."""
        # Fetch all rules and filter by source/destination IP in Python
        res_data = await self.get_all_firewall_rules()
        if res_data.get("status") == "ERROR":
            return {"status": "ERROR", "details": res_data.get("details")}

        rules = res_data.get("data", [])
        if not isinstance(rules, list):
            # API might return a dict with a list under a key
            if isinstance(rules, dict):
                rules = list(rules.values())[0] if rules else []
            else:
                rules = []

        filtered_rules = [
            rule for rule in rules
            if ip in str(rule.get("source", "")) or ip in str(rule.get("destination", ""))
        ]

        if not filtered_rules:
            return {"status": "SUCCESS", "ip": ip, "rules": [], "source": "empty"}

        return {"status": "SUCCESS", "ip": ip, "rules": filtered_rules}

    async def get_dhcp_leases(self, limit: int = 200) -> Dict[str, Any]:
        """Fetches current DHCP leases using the Kea DHCP server.

        ``limit`` caps the result count (default 200) — a guard against massive
        payloads hitting LLM Payload-Too-Large errors on the interactive/search
        path. The firewall→NetBox discovery sync passes ``limit=0`` to get the
        full lease set (it bypasses the capped cache at the spoke layer).
        """
        res = await self._request("GET", "/api/kea/leases4/search")

        if isinstance(res, dict):
            rows = res.get("rows")
            if rows is None:
                logger.info(f"Kea DHCP API returned success but no leases found. Response: {res}")
                return {"status": "SUCCESS", "data": [], "source": "empty"}

            if not isinstance(rows, list):
                rows = []

            processed_leases = []
            for lease in rows:
                if isinstance(lease, dict):
                    # Note: 'expire' is a unix timestamp in the API
                    expire_ts = lease.get("expire", 0)
                    # Simple conversion or keep as is if the UI handles timestamps
                    processed_leases.append({
                        "ip": lease.get("address", "unknown"),
                        "hostname": lease.get("hostname") or "unknown",
                        "mac": lease.get("hwaddr", "unknown"),
                        "lease_end": str(expire_ts) if expire_ts else "unknown"
                    })

            # Safety limit to prevent massive payloads causing LLM 400 errors
            # (Payload Too Large) on the interactive path. limit<=0 disables it
            # so the discovery sync gets the full set.
            if limit and limit > 0 and len(processed_leases) > limit:
                logger.warning(f"Truncating DHCP leases from {len(processed_leases)} to {limit} for stability")
                processed_leases = processed_leases[:limit]

            return {"status": "SUCCESS", "data": processed_leases}

        return {"status": "ERROR", "message": "Unexpected API response format"}

    async def get_arp_table(self) -> Dict[str, Any]:
        """Fetches the firewall's ARP table — every IP→MAC pair for a neighbor
        the firewall has recently talked to.

        Complements DHCP leases by capturing STATIC-IP devices that never
        appear in DHCP — the gap that left their NetBox IP records without a
        ``mac_address`` and broke the CPPM endpoint sync's IP→MAC resolution.
        Used by the firewall→NetBox device discovery sync. No cap: the sync
        wants the full neighbor set. The MAC is returned raw; the hub/netbox
        normalize it.
        """
        res = await self._request("GET", "/api/diagnostics/interface/search_arp")

        if isinstance(res, dict):
            rows = res.get("rows")
            if rows is None:
                # Some OPNsense versions return the list under a different key.
                rows = res.get("data") or []
            if not isinstance(rows, list):
                rows = []

            arp = []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                ip = (row.get("ip") or row.get("address") or "").strip()
                mac = (row.get("mac") or row.get("hwaddr") or "").strip()
                if not ip and not mac:
                    continue
                arp.append({
                    "ip": ip or "unknown",
                    "mac": mac or "unknown",
                    "hostname": (row.get("hostname") or "").strip() or "unknown",
                    "interface": (row.get("intf") or row.get("interface") or "").strip(),
                })

            return {"status": "SUCCESS", "data": arp}

        return {"status": "ERROR", "message": "Unexpected ARP API response format"}