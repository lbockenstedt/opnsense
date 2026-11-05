"""OPNsense API client used by the OPNsense spoke.

Calls go through the system curl binary. It covers interfaces, firewall rules, NAT,
aliases, DNS overrides, DHCP leases, the ARP table, system health and certificate import.
"""
# Standard library only.
import logging
import os
import re
import tempfile
import time
import asyncio
import base64
import ssl
from typing import Dict, Any, List, Optional, Tuple

# Module logger.
logger = logging.getLogger("OpnsenseEngine")

# Marker curl writes before the HTTP status code at the end of the output.
_HTTP_STATUS_MARK = "__LM_HTTP_STATUS__:"


class OpnsenseEngine:
    """
    Core interaction layer for the OPNsense API.
    Handles Firewall rule management and Interface monitoring.
    """
    # Cert/CA imports POST large PEM payloads and the firewall persists them to
    # the trust store (slower than a rule read), so give those calls a longer
    # curl --max-time than the 15s default to avoid a spurious timeout (curl 28).
    _CERT_IMPORT_TIMEOUT = 60

    def __init__(self, host: Optional[str], api_key: Optional[str], api_secret: Optional[str]):
        """Store the connection settings and set up the alias category cache."""
        # Connection settings.
        self.host = host
        self.api_key = api_key
        self.api_secret = api_secret
        # Last time the unconfigured warning was logged.
        self._unconfigured_log_ts = 0.0
        # 5-min TTL memo for _alias_category_map: get_all_aliases + every
        # alias add/update/delete call it, and the category list changes
        # rarely. Invalidate via _alias_category_map(invalidate=True) on
        # alias writes that could add/rename a category (best-effort: the
        # next TTL expiry refreshes regardless).
        self._alias_cat_map: Optional[Dict[str, str]] = None
        self._alias_cat_map_ts: float = 0.0
        self._alias_cat_map_ttl = 300.0

    def is_configured(self) -> bool:
        """True only when a real firewall connection has been supplied: a host
        AND API credentials. There is no localhost default — an unconfigured
        engine never attempts a connection."""
        # Host and both credentials are required.
        return bool(self.host and self.api_key and self.api_secret)

    def _log_unconfigured(self) -> None:
        """Throttled 'no firewall configured' notice (every 5 min) so an
        unconfigured spoke doesn't flood the log with per-endpoint errors."""
        # Warn at most every 5 minutes.
        now = time.time()
        if now - self._unconfigured_log_ts >= 300:
            self._unconfigured_log_ts = now
            logger.warning("No firewall configured — supply opn_host + API "
                           "credentials via the OPNsense connection settings; "
                           "skipping API calls until then.")

    @staticmethod
    def _http_error_detail(text: str) -> str:
        """Short error detail from an HTTP error body: its JSON message, else the text without tags."""
        # json for parsing.
        import json
        # JSON body: use its message.
        try:
            body = json.loads(text)
            if isinstance(body, dict):
                return str(body.get("message") or body.get("errorMessage") or body)[:300]
        except Exception:  # noqa: BLE001
            # Not JSON.
            pass
        # Strip tags and whitespace, cap at 300 characters.
        return re.sub(r"<[^>]+>|\s+", " ", text).strip()[:300] or "no response body"

    async def _request(self, method: str, endpoint: str, data: Dict = None,
                       timeout: int = 15, raw: bool = False) -> Dict[str, Any]:
        """Internal helper to handle OPNsense API requests using system curl.
        Bypasses Python network stack issues that cause ConnectError while system curl works.

        ``timeout`` is curl's total ``--max-time`` (seconds). The default (15) suits
        the small read/rule calls, but cert/CA imports POST large PEM payloads and
        the firewall can take longer to persist them — those callers pass a larger
        value so a slow-but-succeeding import isn't cut off at 15s (curl exit 28).
        """
        # Local imports.
        import json
        import asyncio
        import subprocess

        # Guard: no connection until a firewall is configured (host + creds).
        # Short-circuit before touching curl so an unconfigured spoke reports
        # "no firewall configured" once (throttled) instead of hammering a
        # localhost default and logging code-7 errors per endpoint.
        if not self.is_configured():
            self._log_unconfigured()
            return {"status": "ERROR", "message": "No firewall configured"}

        # Use the direct endpoint which now includes the /api prefix
        # Full URL.
        url = f"https://{self.host}{endpoint}"
        logger.debug(f"Attempting API request to: {url}")

        # TLS verification is OFF by default (fleet convention: encrypted,
        # verify opt-in) — firewalls are addressed by IP and ship a self-signed
        # WebGUI cert, so verifying would fail every call (including the LE cert
        # install that would replace it). Opt in with LM_OPNSENSE_VERIFY_TLS=1.
        # -sS: silent progress but STILL surface errors on stderr, so a timeout
        # (curl 28) or TLS error yields a real message instead of an empty one.
        # --connect-timeout bounds the TCP/TLS handshake separately from the
        # overall --max-time so an unreachable host fails fast without eating the
        # whole (possibly long) import budget.
        # Build the curl command with time limits.
        connect_timeout = min(10, timeout)
        cmd = ["curl", "-sS", "--connect-timeout", str(connect_timeout),
               "--max-time", str(timeout)]
        # Skip TLS checks unless opted in.
        verify_tls = os.getenv("LM_OPNSENSE_VERIFY_TLS", "0").strip().lower()
        if verify_tls not in {"1", "true", "yes", "on"}:
            cmd.append("-k")
        # Path of the temporary credentials file.
        auth_cfg_path = None
        # Errors return an ERROR result; the credentials file is always removed.
        try:
            # Credentials, escaped for the curl config file.
            auth = f"{self.api_key}:{self.api_secret}"
            auth = auth.replace("\\", "\\\\").replace('"', '\\"')
            # Write them to a private temporary file so they are not on the command line.
            with tempfile.NamedTemporaryFile("w", prefix="lm-opnsense-curl-",
                                             suffix=".conf", delete=False) as auth_cfg:
                auth_cfg_path = auth_cfg.name
                os.chmod(auth_cfg_path, 0o600)
                auth_cfg.write(f'user = "{auth}"\n')
            # Method, headers and the config file.
            cmd.extend([
                "--config", auth_cfg_path,
                "-X", method,
                "-H", "Accept: application/json",
            ])
            # Only send Content-Type + body when there is a body — OPNsense returns
            # "Invalid JSON syntax" if it sees Content-Type: application/json with no body.
            if data is not None:
                cmd.extend(["-H", "Content-Type: application/json", "-d", json.dumps(data)])
            # Append the HTTP status so 4xx/5xx bodies (e.g. 403 for an API user
            # lacking a privilege) are reported as errors, not parsed as success.
            cmd.extend(["-w", "\n" + _HTTP_STATUS_MARK + "%{http_code}", url])

            # Run curl.
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            # curl failed: report timeout or stderr.
            if process.returncode != 0:
                # curl 28 = operation timed out. Make it explicit (and include the
                # budget) because -s used to swallow it into a bare "code 28".
                if process.returncode == 28:
                    error_msg = (stderr.decode().strip()
                                 or f"request timed out after {timeout}s (curl 28)")
                else:
                    error_msg = stderr.decode().strip() or f"Curl failed with code {process.returncode}"
                # Log and return the error.
                logger.error(f"Curl request failed for {url}: {error_msg}")
                return {"status": "ERROR", "message": error_msg}

            # Split the output into body and HTTP status.
            out_text = stdout.decode()
            result_text, marked, code = out_text.rpartition(_HTTP_STATUS_MARK)
            # No marker: no status.
            if not marked:
                result_text, code = out_text, ""
            # Trimmed body and numeric status.
            result_text = result_text.strip()
            http_status = int(code) if code.strip().isdigit() else 0
            # HTTP error: report with detail.
            if http_status >= 400:
                error_msg = f"HTTP {http_status}: {self._http_error_detail(result_text)}"
                # Hint for auth errors.
                if http_status in (401, 403):
                    error_msg += (" (check the API key/secret and that its user has the "
                                  "privilege for this page)")
                # Log and return the error.
                logger.error(f"API request failed for {method} {endpoint}: {error_msg}")
                return {"status": "ERROR", "message": error_msg, "http_status": http_status}
            # Empty body.
            if not result_text:
                return {"status": "ERROR", "message": "Empty response from server"}
            # Raw mode: return the text.
            if raw:
                return {"raw": result_text}

            # Parse JSON and return it.
            result = json.loads(result_text)
            logger.debug(f"API request to {url} succeeded. Response keys: {list(result.keys()) if isinstance(result, dict) else 'Not a dict'}")
            return result

        except Exception as e:
            # Log and return the error.
            logger.exception(f"Exception during API request to {url}")
            return {"status": "ERROR", "message": str(e)}
        finally:
            # Remove the credentials file.
            if auth_cfg_path:
                # Ignore removal errors.
                try:
                    os.unlink(auth_cfg_path)
                except OSError:
                    # Already gone.
                    pass

    async def get_interface_status(self) -> Dict[str, Any]:
        """Fetches current status of network interfaces."""
        # Fetch interface info.
        res = await self._request("GET", "/api/interfaces/overview/interfaces_info")

        # Expect a dict.
        if isinstance(res, dict):
            # API error.
            if res.get("status") == "ERROR" or "error" in res:
                return {"status": "ERROR", "details": res}

            # OPNsense usually returns a dict where keys are interface names
            # Convert to a list of dicts for easier UI consumption
            interfaces = []

            # Try to find the actual data payload
            data_payload = res.get("data") or res.get("rows") or res

            if isinstance(data_payload, dict):
                # Dict: one row per interface.
                for iface_name, info in data_payload.items():
                    # Normalise the fields.
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
                        # Keep it.
                        interfaces.append(processed_iface)
                    else:
                        # Not a dict: minimal row.
                        interfaces.append({"name": iface_name, "status": info, "ip": "N/A"})
            elif isinstance(data_payload, list):
                # If it's already a list, we still want to normalize a few keys
                # Normalise each row in place.
                for iface in data_payload:
                    # Only dicts.
                    if isinstance(iface, dict):
                        # ip from addr4; flags and capabilities as strings.
                        if "addr4" in iface and "ip" not in iface:
                            iface["ip"] = iface["addr4"]
                        if "flags" in iface and isinstance(iface["flags"], list):
                            iface["flags"] = ",".join(iface["flags"])
                        if "capabilities" in iface and isinstance(iface["capabilities"], list):
                            iface["capabilities"] = ",".join(iface["capabilities"])
                # Use the list as-is.
                interfaces = data_payload

            # Success.
            return {"status": "SUCCESS", "data": interfaces}

        # Not a dict.
        return {"status": "ERROR", "message": "Unexpected API response format"}

    async def add_firewall_rule(self, rule_config: Dict[str, Any]) -> Dict[str, Any]:
        """Adds a new firewall rule to the specified interface."""
        # Post the rule.
        res = await self._request("POST", "/api/firewall/filter/add_rule", data=rule_config)
        # API error.
        if isinstance(res, dict) and (res.get("status") == "ERROR" or "error" in res):
            return {"status": "ERROR", "details": res}
        # Success with the new id.
        return {"status": "SUCCESS", "rule_id": res.get("id"), "message": "Rule added successfully"}

    async def delete_firewall_rule(self, rule_id: str) -> Dict[str, Any]:
        """Deletes a specific firewall rule."""
        # OPNsense uses POST for deletion with the UUID in the data payload
        res = await self._request("POST", "/api/firewall/filter/del_rule", data={"uuid": rule_id})
        # API error.
        if isinstance(res, dict) and (res.get("status") == "ERROR" or "error" in res):
            return {"status": "ERROR", "details": res}
        # Success.
        return {"status": "SUCCESS", "message": f"Rule {rule_id} deleted"}

    async def manage_alias(self, alias_name: str, hosts: List[str], action: str = "update") -> Dict[str, Any]:
        """Manages OPNsense aliases (groups of IPs/Hosts)."""
        # For update/create, OPNsense uses /firewall/alias/set
        data = {"name": alias_name, "hosts": hosts}
        endpoint = "/api/firewall/alias/set" if action == "update" else "/api/firewall/alias/del_item"
        method = "POST"

        # Delete takes only the alias name.
        if action != "update":
            data = {"alias": alias_name} # Simplification for deletion

        # Send it.
        res = await self._request(method, endpoint, data=data)
        # API error.
        if isinstance(res, dict) and (res.get("status") == "ERROR" or "error" in res):
            return {"status": "ERROR", "details": res}
        # Success.
        return {"status": "SUCCESS", "message": f"Alias {alias_name} {action}d successfully"}

    async def get_system_health(self) -> Dict[str, Any]:
        """Fetches basic system health (CPU/Memory)."""
        # Fetch system health.
        res = await self._request("GET", "/api/diagnostics/systemhealth/get_system_health")
        # API error.
        if isinstance(res, dict) and (res.get("status") == "ERROR" or "error" in res):
            return {"status": "ERROR", "details": res}
        # Success.
        return {"status": "SUCCESS", "data": res}

    async def get_overview(self) -> Dict[str, Any]:
        """Dashboard snapshot (like the OPNsense lobby): host/version/uptime,
        CPU, memory, gateway (WAN) status and per-interface throughput.

        Each section is best-effort — a missing API privilege blanks that
        section instead of failing the whole overview. Throughput is the byte
        counter delta between two traffic samples taken around the other calls
        (the activity call runs ``top`` for ~2s, so the window is real)."""
        def ok(res):
            """True if the result is a dict and not an ERROR."""
            return isinstance(res, dict) and res.get("status") != "ERROR"

        def num(value):
            """``value`` as a float, or None if it is not numeric."""
            # Convert.
            try:
                return float(value)
            except (TypeError, ValueError):
                # Not a number.
                return None

        # First traffic sample.
        traffic_before = await self._request("GET", "/api/diagnostics/traffic/interface")
        # The other sections in parallel.
        info, uptime, resources, activity, gateways = await asyncio.gather(
            self._request("GET", "/api/diagnostics/system/system_information"),
            self._request("GET", "/api/diagnostics/system/system_time"),
            self._request("GET", "/api/diagnostics/system/system_resources"),
            self._request("GET", "/api/diagnostics/activity/get_activity"),
            self._request("GET", "/api/routes/gateway/status"),
        )
        # Second traffic sample.
        traffic_after = await self._request("GET", "/api/diagnostics/traffic/interface")

        # Everything failed: error.
        if not any(ok(r) for r in (info, uptime, resources, activity, gateways, traffic_after)):
            return {"status": "ERROR", "message": info.get("message", "Firewall unreachable")}

        # Empty overview.
        overview = {"hostname": "", "version": "", "uptime": "", "loadavg": "",
                    "cpu_percent": None, "memory": {}, "gateways": [], "interfaces": []}
        # Host name and version.
        if ok(info):
            overview["hostname"] = info.get("name", "")
            overview["version"] = (info.get("versions") or [""])[0]
        # Uptime and load.
        if ok(uptime):
            overview["uptime"] = uptime.get("uptime", "")
            overview["loadavg"] = uptime.get("loadavg", "")
        if ok(activity):
            # top header: "CPU:  2.1% user, 0.0% nice, 1.3% system, 0.2% interrupt, 96.4% idle"
            # CPU busy percent from the idle figure.
            for line in activity.get("headers") or []:
                idle = re.search(r"CPU:.*?([\d.]+)% idle", line)
                if idle:
                    overview["cpu_percent"] = round(100 - float(idle.group(1)), 1)
        # Memory use.
        memory = resources.get("memory") if ok(resources) else None
        if isinstance(memory, dict):
            # Used, total and percent.
            used, total = num(memory.get("used")), num(memory.get("total"))
            if used is not None and total:
                overview["memory"] = {"used": used, "total": total,
                                      "percent": round(used * 100 / total, 1)}
        if ok(gateways):
            # One row per gateway.
            for gw in gateways.get("items") or []:
                overview["gateways"].append({
                    "name": gw.get("name", ""),
                    "address": gw.get("address", ""),
                    "status": gw.get("status_translated") or gw.get("status", ""),
                    "online": gw.get("status") == "none",
                    "delay": gw.get("delay", ""),
                    "loss": gw.get("loss", ""),
                })
        if ok(traffic_before) and ok(traffic_after):
            # Seconds between the samples, and the first sample's counters.
            seconds = (num(traffic_after.get("time")) or 0) - (num(traffic_before.get("time")) or 0)
            before = traffic_before.get("interfaces") or {}
            # Per-interface rates in bits per second.
            for key, now in (traffic_after.get("interfaces") or {}).items():
                # Skip interfaces missing from either sample.
                prev = before.get(key)
                if not isinstance(now, dict) or not isinstance(prev, dict) or seconds <= 0:
                    continue
                # In and out rates.
                rates = {}
                for field, label in (("bytes received", "in_bps"), ("bytes transmitted", "out_bps")):
                    delta = (num(now.get(field)) or 0) - (num(prev.get(field)) or 0)
                    rates[label] = max(0, round(delta * 8 / seconds))
                # Add the row.
                overview["interfaces"].append({"name": now.get("name") or key, **rates})
        # Success.
        return {"status": "SUCCESS", "data": overview}

    async def get_all_firewall_rules(self) -> Dict[str, Any]:
        """Fetches all firewall rules across all interfaces."""
        # Search all rules.
        res = await self._request("POST", "/api/firewall/filter/search_rule", data={})

        # Handle API errors returned as JSON
        if isinstance(res, dict):
            if res.get("status") == "ERROR" or "error" in res or "errorMessage" in res:
                return {"status": "ERROR", "details": res}

            # Extract rules list from response
            rules_data = res.get("rules") or res.get("data") or res.get("rows")

            # No rules.
            if rules_data is None or (isinstance(rules_data, list) and len(rules_data) == 0):
                logger.info(f"API returned success but no rules found. Response: {res}")
                return {"status": "SUCCESS", "data": [], "source": "empty"}

            # OPNsense often returns rules as a dict { "uuid": {rule_data} }
            if isinstance(rules_data, dict):
                # Convert dict values to a list and inject the key (uuid) as the 'id'
                processed_rules = []
                # Add the uuid as the id.
                for uuid, rule in rules_data.items():
                    if isinstance(rule, dict):
                        rule['id'] = uuid
                        processed_rules.append(rule)
                    else:
                        # Not a dict: keep it raw.
                        processed_rules.append({"id": uuid, "raw": rule})
                # The list.
                rules = processed_rules
            elif isinstance(rules_data, list):
                # Already a list.
                rules = rules_data
            else:
                # Unexpected shape.
                rules = []

            # Map OPNsense fields to WebUI expected fields: id, action, protocol, source, destination, description
            final_rules = []
            # Map each rule.
            for r in rules:
                if isinstance(r, dict):
                    # Combine destination network and port for the UI display
                    dest_net = r.get("destination_net", "any")
                    dest_port = r.get("destination_port", "")
                    destination = f"{dest_net}:{dest_port}" if dest_port else dest_net

                    # OPNsense names the source "source_net", mirroring "destination_net"
                    src_net = r.get("source_net") or r.get("source") or "any"
                    src_port = r.get("source_port", "")
                    source = f"{src_net}:{src_port}" if src_port else src_net

                    final_rules.append({
                        "id": r.get("uuid", "unknown"),
                        "action": r.get("action") or r.get("%action") or "pass",
                        "protocol": r.get("protocol", "TCP").upper(),
                        "source": source,
                        "destination": destination,
                        "description": r.get("description") or r.get("descr", "No description")
                    })
                else:
                    # Not a dict: keep it raw.
                    final_rules.append({"id": "unknown", "raw": str(r)})

            # Safety limit to prevent massive payloads causing LLM 400 errors (Payload Too Large)
            if len(final_rules) > 200:
                logger.warning(f"Truncating firewall rules from {len(final_rules)} to 200 for stability")
                final_rules = final_rules[:200]

            # Success.
            return {"status": "SUCCESS", "data": final_rules}

        # Not a dict.
        return {"status": "ERROR", "message": "Unexpected API response format"}

    async def get_firewall_stats(self) -> Dict[str, Any]:
        """Fetches general firewall statistics (packet counts, etc)."""
        # Fetch stats.
        res = await self._request("GET", "/api/diagnostics/firewall/stats")
        # API error.
        if isinstance(res, dict) and (res.get("status") == "ERROR" or "error" in res):
            return {"status": "ERROR", "details": res}
        # Success.
        return {"status": "SUCCESS", "data": res}

    async def get_dns_records(self) -> Dict[str, Any]:
        """Fetches Unbound DNS host overrides."""
        # Fetch host overrides.
        res = await self._request("GET", "/api/unbound/settings/searchHostOverride")

        # Expect a dict.
        if isinstance(res, dict):
            # Classify a _request ERROR envelope BEFORE the rows-is-None handling
            # below — otherwise a 401/timeout (no "rows") looks like "no data" and
            # is returned as SUCCESS+[] (and cached as empty for 1h).
            if res.get("status") == "ERROR" or "error" in res or "errorMessage" in res:
                return {"status": "ERROR", "details": res}
            # The response contains a 'rows' list of overrides
            rows = res.get("rows")
            # No rows.
            if rows is None:
                logger.info(f"DNS API returned success but no records found. Response: {res}")
                return {"status": "SUCCESS", "data": [], "source": "empty"}

            # Guard against a non-list.
            if not isinstance(rows, list):
                rows = []

            # Map each override.
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

            # Success.
            return {"status": "SUCCESS", "data": processed_dns}

        # Not a dict.
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
        # Try each key in order.
        for key in ("source", "%source.network", "source.network", "source.address", "source_net"):
            # Skip missing keys.
            v = rule.get(key)
            if v is None:
                continue
            # Dict: take the address or network.
            if isinstance(v, dict):
                v = v.get("address") or v.get("network") or v.get("any") or ""
            # First non-empty, non-any value wins.
            s = str(v or "").strip()
            if s and s.lower() != "any":
                return s
        # Default.
        return "any"

    async def get_nat_policies(self) -> Dict[str, Any]:
        """Fetches NAT policies from OPNsense.

        Probes the MVC NAT controllers (Destination NAT, Outbound NAT, 1:1 NAT)
        introduced in OPNsense 26.1. Each probe is classified as found / empty /
        errored so a total failure (e.g. firewall < 26.1 with no NAT API, or the
        API key lacks Firewall: NAT permissions) surfaces as a loud ERROR instead
        of degrading to an empty list — which previously rendered as
        "No NAT Policies found" with no clue as to why.
        """
        # Endpoints to probe for NAT rules: (url, label, method).
        # The 1:1 controller is `one_to_one` (not `nat_1to1`); the others are
        # the documented d_nat / source_nat controllers from the OPNsense API.
        endpoints = [
            ("/api/firewall/d_nat/search_rule", "Destination NAT", "POST"),
            ("/api/firewall/source_nat/search_rule", "Outbound NAT", "GET"),
            ("/api/firewall/one_to_one/search_rule", "1:1 NAT", "GET"),
        ]

        # Collected rows, warnings and counters.
        all_processed_nat: list = []
        warnings: list = []
        errored = 0
        ok_endpoints = 0
        last_error = ""

        # Probe all three NAT controllers concurrently — the serial loop paid
        # 3 sequential curl round-trips (each a fresh TCP+TLS+Basic auth).
        # _request is async (curl subprocess), so asyncio.gather overlaps them.
        async def _probe(endpoint, label, method):
            """Run one NAT search request: POST with an empty body, or GET with show_all."""
            # URL and body for the method.
            request_url = f"{endpoint}?show_all=1" if method == "GET" else endpoint
            data = {} if method == "POST" else None
            # Send it.
            return await self._request(method, request_url, data=data)

        # Probe all endpoints in parallel.
        probe_results = await asyncio.gather(
            *[_probe(ep, lbl, m) for ep, lbl, m in endpoints]
        )

        # Handle each result.
        for (endpoint, label, method), res in zip(endpoints, probe_results):
            # Log the probe.
            logger.debug(f"Probing NAT endpoint: {endpoint} ({label}) via {method}")

            # Classify the response. An ERROR envelope from _request (curl fail,
            # 404, permission denied, etc.) must not be confused with a valid
            # empty result — that conflation was the silent-empty root cause.
            if not isinstance(res, dict) or res.get("status") == "ERROR" or "error" in res or "errorMessage" in res:
                # Count the error and keep it.
                errored += 1
                msg = (res.get("message") if isinstance(res, dict) else None) or str(res)
                last_error = f"{label}: {msg}"
                warnings.append(last_error)
                logger.warning("[sync-error] %s: NAT probe %s failed: %s", label, endpoint, msg)
                continue

            # Valid response: count it and get the rows.
            ok_endpoints += 1
            rows = res.get("rows") or res.get("data") or res.get("rules")
            # OPNsense sometimes returns rules keyed by uuid (a dict, not a list).
            if isinstance(rows, dict):
                rows = [dict({"uuid": uid}, **(v if isinstance(v, dict) else {"raw": v})) for uid, v in rows.items()]

            # Map each rule.
            if rows and isinstance(rows, list):
                logger.debug(f"Found {len(rows)} rules in {label} endpoint.")
                for rule in rows:
                    if isinstance(rule, dict):
                        # Map OPNsense NAT fields to a consistent format.
                        # Destination NAT uses different fields than Outbound NAT.
                        all_processed_nat.append({
                            "id": rule.get("uuid", "unknown"),
                            "type": label,
                            "protocol": rule.get("protocol", "TCP"),
                            "source": self._nat_source(rule),
                            "external_ip": rule.get("%destination.network") or rule.get("destination.network") or "any",
                            "external_port": rule.get("destination.port") or rule.get("external_port") or rule.get("dest_port") or "N/A",
                            "internal_ip": rule.get("target") or rule.get("internal_ip") or rule.get("dest_address") or "unknown",
                            "internal_port": rule.get("local-port") or rule.get("internal_port") or rule.get("dest_port") or "All",
                            "description": rule.get("descr") or rule.get("description") or f"{label} Rule"
                        })
                        if not rule.get("dest_address") and not rule.get("internal_ip"):
                            logger.debug(f"NAT rule {rule.get('uuid')} missing IP fields. Keys: {list(rule.keys())}")
            else:
                # Valid but empty.
                logger.debug(f"No rules found in {label} endpoint (valid empty response).")

        # Every probe failed — almost certainly OPNsense < 26.1 (no MVC NAT API)
        # or the API key lacks Firewall: NAT permissions. Surface a real error so
        # the UI can tell the user instead of showing an empty list.
        if ok_endpoints == 0:
            logger.error("[sync-error] get_nat_policies: all %d NAT endpoints errored. Last: %s", errored, last_error)
            return {
                "status": "ERROR",
                "message": (
                    "OPNsense NAT API returned errors for all probed endpoints "
                    "(d_nat / source_nat / one_to_one). The MVC NAT controllers "
                    "require OPNsense 26.1+ and a Firewall: NAT API key scope. "
                    f"Last error: {last_error}"
                ),
                "data": [],
            }

        # Safety limit to prevent massive payloads causing LLM 400 errors (Payload Too Large)
        if len(all_processed_nat) > 200:
            logger.warning(f"Truncating NAT rules from {len(all_processed_nat)} to 200 for stability")
            all_processed_nat = all_processed_nat[:200]

        # Success, with warnings and a source label.
        out: Dict[str, Any] = {"status": "SUCCESS", "data": all_processed_nat}
        if warnings:
            out["warnings"] = warnings
            out["source"] = "partial" if all_processed_nat else "empty"
        else:
            out["source"] = "empty" if not all_processed_nat else "live"
        return out

    async def apply_firewall_changes(self) -> Dict[str, Any]:
        """Applies pending firewall rule changes."""
        # Apply pending changes.
        res = await self._request("POST", "/api/firewall/filter/apply", data={})
        # Success unless the call failed.
        return {"status": "SUCCESS", "message": "Firewall changes applied"} if not (isinstance(res, dict) and res.get("status") == "ERROR") else res

    async def _alias_category_map(self, invalidate: bool = False) -> Dict[str, str]:
        """``{category_uuid: name}`` from ``/api/firewall/alias/listCategories``.

        OPNsense tags aliases with category *UUIDs* — the alias model field is
        ``categories`` (a comma-separated UUID list), and ``searchItem`` injects
        a ``categories_uuid`` array. There is no ``category`` name field on the
        alias, so the old ``row.get("category")`` read a key the API never
        returns and every alias rendered an empty Category. This map resolves
        those UUIDs to display names. Best-effort: an empty map on failure just
        yields empty categories (no worse than before).

        5-min TTL memoized (self._alias_cat_map): get_all_aliases + every
        alias write call this, and the category list changes rarely. Pass
        ``invalidate=True`` after an alias add/update that could create a new
        category to force a fresh fetch on the next call."""
        # Serve the cached map while fresh.
        now = time.time()
        if (not invalidate and self._alias_cat_map is not None
                and (now - self._alias_cat_map_ts) < self._alias_cat_map_ttl):
            return self._alias_cat_map
        # Fetch categories; on failure fall back to the cached map.
        try:
            res = await self._request("GET", "/api/firewall/alias/listCategories")
        except Exception as e:  # noqa: BLE001
            # Fetch failed.
            logger.warning("alias category list fetch failed: %s", e)
            return self._alias_cat_map or {}
        # Not a dict.
        if not isinstance(res, dict):
            return self._alias_cat_map or {}
        # Map uuid to name.
        rows = res.get("rows") or res.get("data") or []
        out: Dict[str, str] = {}
        for row in (rows if isinstance(rows, list) else []):
            if isinstance(row, dict) and row.get("uuid") and row.get("name"):
                out[str(row["uuid"])] = str(row["name"])
        # Cache it.
        self._alias_cat_map = out
        self._alias_cat_map_ts = now
        return out

    @staticmethod
    def _resolve_alias_category_uuids(row: Dict[str, Any],
                                      cat_map: Dict[str, str]) -> str:
        """Comma-separated category *names* for one alias row, resolved from the
        UUID list OPNsense returns — ``categories_uuid`` array preferred, else the
        ``categories`` comma-separated UUID string. Empty when none/unknown."""
        # Prefer the categories_uuid list.
        uuids: List[str] = []
        cu = row.get("categories_uuid")
        if isinstance(cu, list):
            uuids = [str(u) for u in cu if u]
        else:
            # Else the categories string or list.
            cats = row.get("categories")
            if isinstance(cats, str) and cats.strip():
                uuids = [u.strip() for u in cats.split(",") if u.strip()]
            elif isinstance(cats, list):
                uuids = [str(u) for u in cats if u]
        # Names for known uuids.
        return ", ".join(cat_map[u] for u in uuids if u and cat_map.get(u))

    async def _alias_category_uuids_for(self, category: str) -> str:
        """Resolve a comma-separated category *name* string (what the LM WebUI
        sends and the tenant filter matches on) to the comma-separated category
        *UUID* string OPNsense's alias model expects under ``categories``. Names
        that don't match an existing OPNsense category are dropped with a warning
        — OPNsense categories are first-class objects referenced by UUID, so a
        name that isn't pre-created cannot be assigned. Empty input → empty
        (clears the alias's categories on edit)."""
        # Empty input.
        if not category or not str(category).strip():
            return ""
        # Bypass the 5-min memo here (invalidate=True): this runs on the alias
        # add/edit write path, where the category may have been created moments
        # ago (by the same UI action or an out-of-band API call). A stale memo
        # wouldn't contain the new category UUID, so the name would fail to
        # resolve and be silently DROPPED (see the warn below). Fetching live
        # ensures a just-created category resolves and refreshes the memo.
        cat_map = await self._alias_category_map(invalidate=True)
        # Reverse map: name to uuid.
        name_to_uuid = {name: uuid for uuid, name in cat_map.items()}
        # Look up each name; drop unknown ones.
        uuids: List[str] = []
        for name in [n.strip() for n in str(category).split(",") if n.strip()]:
            # Known: keep the uuid.
            uid = name_to_uuid.get(name)
            if uid:
                uuids.append(uid)
            else:
                # Unknown: warn.
                logger.warning(
                    "alias category '%s' is not a known OPNsense category — dropping",
                    name)
        # Comma-separated uuids.
        return ",".join(uuids)

    async def get_all_aliases(self) -> Dict[str, Any]:
        """Fetches all firewall aliases. The Category column is resolved from each
        alias's ``categories`` UUID list via ``listCategories`` — OPNsense tags
        aliases by category UUID, not by a name field."""
        # Category names, then the alias list.
        cat_map = await self._alias_category_map()
        res = await self._request("GET", "/api/firewall/alias/searchItem")
        # Expect a dict.
        if isinstance(res, dict):
            # Map each alias.
            rows = res.get("rows") or res.get("data") or []
            processed = []
            for row in (rows if isinstance(rows, list) else []):
                if isinstance(row, dict):
                    processed.append({
                        "id": row.get("uuid", "unknown"),
                        "name": row.get("name", ""),
                        "type": row.get("type", ""),
                        "content": row.get("content", ""),
                        "category": self._resolve_alias_category_uuids(row, cat_map),
                        "description": row.get("description", ""),
                    })
            # Success.
            return {"status": "SUCCESS", "data": processed}
        # Not a dict.
        return {"status": "ERROR", "message": "Unexpected API response format"}

    async def add_alias(self, name: str, type_: str, content: str, description: str = "", category: str = "") -> Dict[str, Any]:
        """Adds a new firewall alias. ``category`` is a comma-separated category
        *name* string (what the LM WebUI sends); it is resolved to category UUIDs
        and sent under ``categories`` — the OPNsense alias model field. Names that
        aren't existing OPNsense categories are dropped (see
        ``_alias_category_uuids_for``)."""
        # Category uuids and the alias payload.
        cats = await self._alias_category_uuids_for(category)
        data = {"alias": {"name": name, "type": type_, "content": content, "description": description, "categories": cats, "enabled": "1"}}
        # Add it.
        res = await self._request("POST", "/api/firewall/alias/addItem", data=data)
        # API error.
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        # Apply.
        await self._request("POST", "/api/firewall/alias/reconfigure", data={})
        return {"status": "SUCCESS", "message": f"Alias '{name}' added"}

    async def delete_alias(self, uuid: str) -> Dict[str, Any]:
        """Deletes a firewall alias by UUID."""
        # Delete it.
        res = await self._request("POST", f"/api/firewall/alias/delItem/{uuid}", data={})
        # API error.
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        # Apply.
        await self._request("POST", "/api/firewall/alias/reconfigure", data={})
        return {"status": "SUCCESS", "message": f"Alias {uuid} deleted"}

    async def add_firewall_rule_and_apply(self, rule_config: Dict[str, Any]) -> Dict[str, Any]:
        """Adds a firewall rule and applies it."""
        # Add, then apply on success.
        res = await self.add_firewall_rule(rule_config)
        if res.get("status") == "SUCCESS":
            await self.apply_firewall_changes()
        return res

    async def delete_firewall_rule_and_apply(self, rule_id: str) -> Dict[str, Any]:
        """Deletes a firewall rule and applies changes."""
        # Delete, then apply on success.
        res = await self.delete_firewall_rule(rule_id)
        if res.get("status") == "SUCCESS":
            await self.apply_firewall_changes()
        return res

    async def add_nat_rule(self, nat_type: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Adds a NAT rule. nat_type: 'd_nat' | 'source_nat' | 'one_to_one'
        ('nat_1to1' accepted as a legacy alias for 'one_to_one')."""
        # Add endpoint per NAT type.
        endpoint_map = {
            "d_nat": "/api/firewall/d_nat/addRule",
            "source_nat": "/api/firewall/source_nat/addRule",
            "one_to_one": "/api/firewall/one_to_one/addRule",
            "nat_1to1": "/api/firewall/one_to_one/addRule",
        }
        # Endpoint, defaulting to d_nat.
        endpoint = endpoint_map.get(nat_type, endpoint_map["d_nat"])
        # Add the rule.
        res = await self._request("POST", endpoint, data={"rule": rule})
        # API error.
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        # Apply.
        await self._request("POST", "/api/firewall/filter/apply", data={})
        return {"status": "SUCCESS", "message": f"NAT rule added ({nat_type})"}

    async def delete_nat_rule(self, nat_type: str, uuid: str) -> Dict[str, Any]:
        """Deletes a NAT rule by UUID."""
        # Delete endpoint per NAT type.
        endpoint_map = {
            "d_nat": f"/api/firewall/d_nat/delRule/{uuid}",
            "source_nat": f"/api/firewall/source_nat/delRule/{uuid}",
            "one_to_one": f"/api/firewall/one_to_one/delRule/{uuid}",
            "nat_1to1": f"/api/firewall/one_to_one/delRule/{uuid}",
        }
        # Endpoint, defaulting to d_nat.
        endpoint = endpoint_map.get(nat_type, endpoint_map["d_nat"])
        # Delete the rule.
        res = await self._request("POST", endpoint, data={})
        # API error.
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        # Apply.
        await self._request("POST", "/api/firewall/filter/apply", data={})
        return {"status": "SUCCESS", "message": f"NAT rule {uuid} deleted"}

    async def add_dns_record(self, hostname: str, domain: str, ip: str, description: str = "") -> Dict[str, Any]:
        """Adds a DNS host override in Unbound."""
        # Override payload.
        data = {"host": {"hostname": hostname, "domain": domain, "server": ip, "description": description, "enabled": "1"}}
        # Add it.
        res = await self._request("POST", "/api/unbound/settings/addHostOverride", data=data)
        # API error.
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        # Reload Unbound.
        await self._request("POST", "/api/unbound/service/reconfigure", data={})
        return {"status": "SUCCESS", "message": f"DNS record {hostname}.{domain} → {ip} added"}

    async def delete_dns_record(self, uuid: str) -> Dict[str, Any]:
        """Deletes a DNS host override by UUID."""
        # Delete it.
        res = await self._request("POST", f"/api/unbound/settings/delHostOverride/{uuid}", data={})
        # API error.
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        # Reload Unbound.
        await self._request("POST", "/api/unbound/service/reconfigure", data={})
        return {"status": "SUCCESS", "message": f"DNS record {uuid} deleted"}

    async def edit_firewall_rule(self, uuid: str, rule_config: Dict[str, Any]) -> Dict[str, Any]:
        """Updates an existing firewall rule by UUID."""
        # Update the rule.
        res = await self._request("POST", f"/api/firewall/filter/setRule/{uuid}", data={"rule": rule_config})
        # API error.
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        # Apply.
        await self.apply_firewall_changes()
        return {"status": "SUCCESS", "message": f"Rule {uuid} updated"}

    async def edit_alias(self, uuid: str, name: str, type_: str, content: str, description: str = "", category: str = "") -> Dict[str, Any]:
        """Updates an existing alias by UUID. ``category`` is a comma-separated
        category *name* string resolved to UUIDs and sent under ``categories``
        (the OPNsense alias model field); empty clears the alias's categories."""
        # Category uuids and the alias payload.
        cats = await self._alias_category_uuids_for(category)
        data = {"alias": {"name": name, "type": type_, "content": content, "description": description, "categories": cats, "enabled": "1"}}
        # Update it.
        res = await self._request("POST", f"/api/firewall/alias/setItem/{uuid}", data=data)
        # API error.
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        # Apply.
        await self._request("POST", "/api/firewall/alias/reconfigure", data={})
        return {"status": "SUCCESS", "message": f"Alias '{name}' updated"}

    async def edit_nat_rule(self, nat_type: str, uuid: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Updates an existing NAT rule by UUID."""
        # Update endpoint per NAT type.
        endpoint_map = {
            "d_nat": f"/api/firewall/d_nat/setRule/{uuid}",
            "source_nat": f"/api/firewall/source_nat/setRule/{uuid}",
            "one_to_one": f"/api/firewall/one_to_one/setRule/{uuid}",
            "nat_1to1": f"/api/firewall/one_to_one/setRule/{uuid}",
        }
        # Endpoint, defaulting to d_nat.
        endpoint = endpoint_map.get(nat_type, endpoint_map["d_nat"])
        # Update the rule.
        res = await self._request("POST", endpoint, data={"rule": rule})
        # API error.
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        # Apply.
        await self._request("POST", "/api/firewall/filter/apply", data={})
        return {"status": "SUCCESS", "message": f"NAT rule updated ({nat_type})"}

    async def edit_dns_record(self, uuid: str, hostname: str, domain: str, ip: str, description: str = "") -> Dict[str, Any]:
        """Updates an existing DNS host override by UUID."""
        # Override payload.
        data = {"host": {"hostname": hostname, "domain": domain, "server": ip, "description": description, "enabled": "1"}}
        # Update it.
        res = await self._request("POST", f"/api/unbound/settings/setHostOverride/{uuid}", data=data)
        # API error.
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        # Reload Unbound.
        await self._request("POST", "/api/unbound/service/reconfigure", data={})
        return {"status": "SUCCESS", "message": f"DNS record {uuid} updated"}

    async def import_cert(self, domain: str, fullchain: str, privkey: str) -> Dict[str, Any]:
        """Imports (or re-imports in place) a TLS certificate into OPNsense Trust.

        Called by the hub's cert-distribution layer via ``OPNSENSE_INSTALL_CERT``
        — the hub brokers cert material from the le (Let's Encrypt) spoke to each
        target spoke, and this spoke applies it to the firewall it's in the
        vicinity of. The fullchain is split: the leaf goes to Trust→cert
        (``crt_payload``; payload nested under ``"cert"``, raw PEM not base64,
        fields ``action:"import"``, ``descr``, ``cert_type:"usr_cert"``,
        ``private_key_location:"firewall"``, ``prv_payload`` key, ``csr_payload:""``)
        and the intermediates/root are imported into Trust→Authorities FIRST as
        CAs (``/api/trust/ca/add``|``/set/<uuid>``, payload under ``"ca"``) so the
        leaf import doesn't error "missing CA key" when the signing CA isn't
        already trusted. CA import is best-effort — a CA that's already trusted
        (e.g. a public root) may error on re-import and must NOT abort the leaf.
        Idempotent: an existing cert/CA with matching ``descr`` is updated via
        ``/set/<uuid>`` rather than re-added, so renewals refresh the same object.
        No reconfigure/apply endpoint exists for trust/cert; auto-assigning the
        imported cert to the WebUI/HAProxy listener is a follow-up (the first
        assignment is UI-only in OPNsense, then ``/set/<uuid>`` renews in place).
        """
        # Split the chain into leaf and CAs; both leaf and key are required.
        leaf, ca_blocks = self._split_chain(fullchain)
        if not leaf or not privkey:
            return {"status": "ERROR",
                    "message": "import_cert requires fullchain (with a leaf) and privkey PEM"}
        # Import signing CAs (intermediates/root) into Trust→Authorities first.
        # Best-effort: a benign duplicate-root error must not block the leaf.
        base = domain or "lm-managed"
        ca_imports: List[Dict[str, Any]] = []
        # Import each CA and record the result.
        for idx, ca_pem in enumerate(ca_blocks, 1):
            ca_descr = f"lm-le-{base}-ca" if len(ca_blocks) == 1 else f"lm-le-{base}-ca{idx}"
            r = await self.import_ca(ca_descr, ca_pem)
            ca_imports.append({"descr": ca_descr, "status": r.get("status"),
                               "message": r.get("message")})
        # Leaf certificate payload.
        cert_payload = {
            "action": "import", "descr": domain or "lm-managed",
            "cert_type": "usr_cert", "private_key_location": "firewall",
            "crt_payload": leaf, "prv_payload": privkey, "csr_payload": "",
        }
        # Activation: OPNsense has no API to point the WebGUI at a different
        # cert (ssl-certref is legacy config), but updating the cert object the
        # WebGUI ALREADY serves keeps its refid — so the WebGUI picks up the new
        # material on restart. Locate that object by fingerprinting the live
        # HTTPS cert; replace it when it is the factory self-signed cert or an
        # earlier cert for this domain (never someone else's CA-signed cert).
        activate = os.getenv("LM_OPNSENSE_ACTIVATE_WEBGUI", "1").strip().lower() not in {"0", "false", "no", "off"}
        # Find the WebGUI's current cert.
        webgui = await self._webgui_cert_row() if activate else None
        webgui_uuid = None
        if webgui:
            # Replace it only if self-signed or already for this domain.
            row, self_signed = webgui
            if self_signed or row.get("descr") == domain or row.get("commonname") == domain:
                webgui_uuid = row.get("uuid")
            else:
                logger.info("[cert] WebGUI serves '%s' (%s) — not an LM/self-signed cert, leaving it",
                            row.get("descr"), row.get("commonname"))
        # Target: the WebGUI cert, else an existing cert with this name.
        existing_uuid = webgui_uuid or await self._find_cert_uuid(domain or "")
        # Update in place.
        if existing_uuid:
            res = await self._request("POST", f"/api/trust/cert/set/{existing_uuid}",
                                      data={"cert": cert_payload},
                                      timeout=self._CERT_IMPORT_TIMEOUT)
            action = "updated"
        else:
            # Otherwise add a new one.
            res = await self._request("POST", "/api/trust/cert/add",
                                      data={"cert": cert_payload},
                                      timeout=self._CERT_IMPORT_TIMEOUT)
            action = "added"
        # Write failed?
        failure = self._write_failure(res)
        if failure:
            # Surface the CA import results alongside so a "missing CA key" leaf
            # failure is diagnosable (did the CA import succeed?).
            logger.warning("[cert] import of '%s' into OPNsense Trust FAILED (%s): %s; CA imports: %s",
                           domain, action, failure, ca_imports)
            return {"status": "ERROR", "message": f"cert import failed: {failure}",
                    "ca_imports": ca_imports}
        # Log success.
        logger.info("[cert] '%s' %s in OPNsense Trust (uuid=%s); CA imports: %s",
                    domain, action, existing_uuid or (res or {}).get("uuid"), ca_imports)
        # Base message.
        message = f"cert '{domain}' {action}"
        if webgui_uuid:
            # WebGUI cert replaced: drop duplicates, restart and verify.
            await self._remove_stale_duplicates(domain, keep_uuid=webgui_uuid)
            active = await self._restart_webgui_and_verify(leaf)
            message += ("; activated on the WebGUI" if active
                        else "; WebGUI restarted but still serving the previous cert")
        elif activate and not webgui:
            # WebGUI cert not found.
            message += "; WebGUI cert could not be identified — not activated"
        elif activate:
            # WebGUI uses someone else's cert.
            message += "; WebGUI uses another cert — not activated"
        # Success.
        return {"status": "SUCCESS", "message": message, "ca_imports": ca_imports}

    @staticmethod
    def _pem_to_der(pem: str) -> Optional[bytes]:
        """DER bytes of the first certificate in a PEM string, or None."""
        # First PEM certificate block.
        m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem or "", re.DOTALL)
        if not m:
            return None
        # Convert to DER.
        try:
            return ssl.PEM_cert_to_DER_cert(m.group(0))
        except Exception:  # noqa: BLE001
            # Not a valid certificate.
            return None

    async def _served_cert_der(self) -> Optional[bytes]:
        """DER of the cert the WebGUI presents right now (no verification)."""
        # No host.
        if not self.host:
            return None
        # Host and port.
        host, _, port = self.host.partition(":")
        # Fetch the served cert in a thread, with a timeout.
        try:
            pem = await asyncio.wait_for(asyncio.to_thread(
                ssl.get_server_certificate, (host, int(port or 443))), timeout=15)
        except Exception as e:  # noqa: BLE001
            # Fetch failed.
            logger.info("[cert] could not read the WebGUI cert from %s: %s", self.host, e)
            return None
        # As DER.
        return self._pem_to_der(pem)

    async def _trust_cert_rows(self) -> List[Dict[str, Any]]:
        """All rows of the OPNsense Trust certificate list."""
        # Search all certs.
        res = await self._request("POST", "/api/trust/cert/search",
                                  data={"current": 1, "rowCount": -1, "searchPhrase": ""})
        # Not a dict.
        if not isinstance(res, dict):
            return []
        # Dict rows only.
        return [r for r in (res.get("rows") or []) if isinstance(r, dict)]

    @staticmethod
    def _row_der(row: Dict[str, Any]) -> Optional[bytes]:
        """DER bytes of a Trust row's certificate, or None."""
        # Base64 PEM from the row.
        crt = row.get("crt") or ""
        # Decode it.
        try:
            pem = base64.b64decode(crt).decode("utf-8", "replace") if crt else ""
        except Exception:  # noqa: BLE001
            # Bad base64.
            return None
        # As DER.
        return OpnsenseEngine._pem_to_der(pem)

    async def _webgui_certref(self) -> Optional[str]:
        """``system/webgui/ssl-certref`` from the latest config backup — the
        authoritative WebGUI cert assignment (no dedicated API exists). Returns
        ``None`` if the config can't be read, ``""`` if nothing is assigned.
        The config holds secrets: only this one element is parsed, nothing logged."""
        # Download the config backup as text.
        res = await self._request("GET", "/api/core/backup/download/this", raw=True)
        text = (res or {}).get("raw") if isinstance(res, dict) else None
        # Unreadable.
        if not text:
            logger.info("[cert] could not read config from %s to find the WebGUI cert: %s",
                        self.host, (res or {}).get("message") if isinstance(res, dict) else res)
            return None
        # Keep a non-secret excerpt for diagnostics.
        self._config_diag = self._config_summary(text)
        # Find the WebGUI's certref.
        m = re.search(r"<webgui>.*?<ssl-certref>\s*([^<\s]*)\s*</ssl-certref>.*?</webgui>", text, re.DOTALL)
        if not (m and m.group(1)):
            # Readable config, no assignment: "" (heal-able), not None (unknown).
            logger.info("[cert] WebGUI on %s has no ssl-certref assigned in config", self.host)
            return ""
        # The refid.
        return m.group(1)

    async def _webgui_cert_row(self, heal: bool = True) -> Optional[Tuple[Dict[str, Any], bool]]:
        """Return ``(trust row, self_signed)`` for the WebGUI's cert, or ``None``.
        Primary: the config's ``ssl-certref`` matched to a Trust row's refid
        (works even when the live cert is stale, e.g. an HA backup whose cert
        store was replaced by sync). Fallback: the live TLS cert fingerprint."""
        # Assigned refid, and Trust rows when there is one.
        certref = await self._webgui_certref()
        rows = await self._trust_cert_rows() if certref else None
        if certref:
            # Find the row with that refid.
            for row in rows:
                if row.get("refid") == certref:
                    der = self._row_der(row)
                    return row, bool(der and self._der_self_signed(der))
            # Refid not in Trust.
            logger.info("[cert] WebGUI on %s is assigned cert refid %s, which is not in Trust "
                        "(e.g. replaced by HA sync)", self.host, certref)
        # Fall back to the served cert.
        served = await self._served_cert_der()
        if not served:
            return None
        # Load rows if not loaded yet.
        if rows is None:
            rows = await self._trust_cert_rows()
        # Match by DER.
        for row in rows:
            if self._row_der(row) == served:
                return row, self._der_self_signed(served)
        # No match: log diagnostics.
        logger.info("[cert] WebGUI cert on %s matches no Trust certificate", self.host)
        self._log_webgui_diag(served, rows)
        if heal and certref is not None:
            # Missing/orphaned assignment: on restart OPNsense's
            # webgui_configure_do() finds no cert for ssl-certref, creates a
            # "Web GUI TLS certificate" in Trust and assigns it (write_config),
            # which the caller can then replace in place.
            # Restart the WebGUI.
            logger.info("[cert] restarting the WebGUI on %s to repair its cert assignment", self.host)
            await self._request("POST", "/api/core/service/restart/webgui", data={})
            # Wait up to 30s for a new served cert.
            for _ in range(10):
                await asyncio.sleep(3)
                if await self._served_cert_der() not in (None, served):
                    break
            # Try again once without healing.
            return await self._webgui_cert_row(heal=False)
        # Not found.
        return None

    @staticmethod
    def _config_summary(text: str) -> str:
        """Non-secret config excerpt for diagnostics: revision, webgui block and
        HA sync settings, with any password/key/secret elements removed."""
        def block(tag: str) -> str:
            """The first ``<tag>`` element in the config, or a placeholder."""
            # Find the element.
            m = re.search(rf"<{tag}>.*?</{tag}>", text, re.DOTALL)
            return m.group(0) if m else f"<{tag}/>(absent)"
        # Revision, WebGUI and HA blocks.
        out = " ".join(block(t) for t in ("revision", "webgui", "hasync"))
        # Mask secret elements.
        out = re.sub(r"<([\w-]*(?:pass|secret|key|prv)[\w-]*)>.*?</\1>", r"<\1>***</\1>", out,
                     flags=re.DOTALL | re.IGNORECASE)
        # Collapse whitespace, cap at 1500 characters.
        return re.sub(r"\s+", " ", out)[:1500]

    def _log_webgui_diag(self, served: Optional[bytes], rows: List[Dict[str, Any]]) -> None:
        """Log the served cert fingerprint and every Trust row, for diagnosing a cert mismatch."""
        # Short sha256 fingerprint helper.
        import hashlib
        fp = lambda d: hashlib.sha256(d).hexdigest()[:16] if d else None  # noqa: E731
        # Config excerpt.
        logger.info("[cert] diag %s config: %s", self.host, getattr(self, "_config_diag", "n/a"))
        # Served cert and Trust rows.
        logger.info("[cert] diag %s served sha256=%s self_signed=%s; trust rows: %s", self.host,
                    fp(served), served and self._der_self_signed(served),
                    [(r.get("descr"), r.get("refid"), r.get("commonname"), r.get("in_use"),
                      fp(self._row_der(r))) for r in rows])

    @staticmethod
    def _der_self_signed(der: bytes) -> bool:
        """True when subject == issuer (cryptography if installed, else the
        openssl CLI; False when neither can parse it)."""
        try:
            # Try the cryptography library.
            from cryptography import x509  # type: ignore
            c = x509.load_der_x509_certificate(der)
            return c.subject == c.issuer
        except Exception:  # noqa: BLE001
            # Not available or failed.
            pass
        try:
            # Fall back to openssl.
            import subprocess
            out = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout",
                                  "-subject", "-issuer", "-nameopt", "RFC2253"],
                                 input=der, capture_output=True, timeout=10).stdout.decode()
            # Subject and issuer values.
            vals = [ln.split("=", 1)[1].strip() for ln in out.splitlines() if "=" in ln]
            return len(vals) == 2 and vals[0] == vals[1]
        except Exception:  # noqa: BLE001
            # Could not parse.
            return False

    async def _remove_stale_duplicates(self, descr: str, keep_uuid: str) -> None:
        """Delete other Trust certs with the same descr that nothing uses
        (left by imports before WebGUI activation existed). OPNsense refuses
        to delete an in-use cert, so this is safe best-effort."""
        # Unused certs with the same name, except the one kept.
        for row in await self._trust_cert_rows():
            if (row.get("descr") == descr and row.get("uuid") and row.get("uuid") != keep_uuid
                    and str(row.get("in_use", "0")) in ("0", "", "False", "false")):
                # Delete and log.
                res = await self._request("POST", f"/api/trust/cert/del/{row['uuid']}", data={})
                logger.info("[cert] removed unused duplicate '%s' (%s): %s",
                            descr, row["uuid"], self._write_failure(res) or "ok")

    async def _restart_webgui_and_verify(self, leaf_pem: str, attempts: int = 10,
                                         delay: float = 3.0) -> bool:
        """Restart the WebGUI so it loads the updated cert, then confirm the
        live HTTPS cert is the new leaf. The restart drops the API connection
        mid-response, so a transport error from that call is expected."""
        # Already serving the new leaf?
        want = self._pem_to_der(leaf_pem)
        if want and await self._served_cert_der() == want:
            return True
        # Restart the WebGUI.
        res = await self._request("POST", "/api/core/service/restart/webgui", data={})
        logger.info("[cert] WebGUI restart requested: %s", res)
        # Poll until the new cert is served.
        for _ in range(attempts):
            await asyncio.sleep(delay)
            if want and await self._served_cert_der() == want:
                logger.info("[cert] WebGUI on %s now serves the new cert", self.host)
                return True
        # Still the old cert.
        logger.warning("[cert] WebGUI on %s still serves the previous cert after restart", self.host)
        return False

    @staticmethod
    def _write_failure(res: Any) -> Optional[str]:
        """Return a failure message for an OPNsense model write (add/set), or
        ``None`` on success. OPNsense reports validation errors as HTTP 200 with
        ``{"result": "failed", "validations": {field: msg}}`` — never as an
        HTTP error — so checking only our own ``status == "ERROR"`` let a
        rejected import be reported as SUCCESS (and the hub never retried)."""
        # Not a dict.
        if not isinstance(res, dict):
            return "unexpected response from OPNsense"
        # Our own error envelope.
        if res.get("status") == "ERROR":
            return str(res.get("message") or "request failed")
        # OPNsense validation failure.
        validations = res.get("validations")
        if str(res.get("result", "")).lower() == "failed" or validations:
            if isinstance(validations, dict) and validations:
                # Field errors.
                return "; ".join(f"{k}: {v}" for k, v in validations.items())
            return str(res.get("message") or "OPNsense rejected the request (result=failed)")
        # Success.
        return None

    async def import_ca(self, descr: str, ca_pem: str) -> Dict[str, Any]:
        """Import a CA certificate into Trust→Authorities (idempotent via search
        by ``descr`` → ``/set/<uuid>`` else ``/add``). Payload nested under
        ``"ca"``: ``action:"existing"``, ``descr``, ``crt_payload`` (raw PEM). Needed
        before importing a leaf whose signing CA isn't already trusted, else
        OPNsense errors "missing CA key"."""
        # A PEM is required.
        if not ca_pem:
            return {"status": "ERROR", "message": "import_ca requires a CA PEM"}
        # CA payload, and any existing CA with this name.
        payload = {"action": "existing", "descr": descr, "crt_payload": ca_pem}
        uuid = await self._find_ca_uuid(descr)
        # Update in place.
        if uuid:
            res = await self._request("POST", f"/api/trust/ca/set/{uuid}",
                                      data={"ca": payload},
                                      timeout=self._CERT_IMPORT_TIMEOUT)
            action = "updated"
        else:
            # Otherwise add.
            res = await self._request("POST", "/api/trust/ca/add",
                                      data={"ca": payload},
                                      timeout=self._CERT_IMPORT_TIMEOUT)
            action = "added"
        # Write failed?
        failure = self._write_failure(res)
        if failure:
            logger.info("[cert] CA '%s' import (%s) not applied: %s", descr, action, failure)
            return {"status": "ERROR", "message": failure}
        # Success.
        return {"status": "SUCCESS", "message": f"ca '{descr}' {action}"}

    async def _find_ca_uuid(self, descr: str) -> Optional[str]:
        """Search Trust→Authorities for a CA whose ``descr`` matches; return its
        uuid or ``None``. Endpoint ``POST /api/trust/ca/search`` (rows carry
        ``uuid`` + ``descr``)."""
        # A name is required.
        if not descr:
            return None
        # Search; errors give None.
        try:
            res = await self._request("POST", "/api/trust/ca/search",
                                      data={"searchPhrase": descr, "search": descr})
        except Exception:
            return None
        # Not a dict.
        if not isinstance(res, dict):
            return None
        # First row with the same name.
        rows = res.get("rows") or res.get("data") or []
        for row in rows:
            if isinstance(row, dict) and row.get("descr") == descr and row.get("uuid"):
                return row.get("uuid")
        # Not found.
        return None

    @staticmethod
    def _split_chain(fullchain: str) -> Tuple[str, List[str]]:
        """Split a fullchain PEM into ``(leaf, [ca_blocks])``. The leaf is the
        first ``CERTIFICATE`` block; the remaining blocks (intermediates + root)
        are CA material for Trust→Authorities. Each returned block ends with a
        trailing newline (OPNsense parses PEM blocks cleanly regardless)."""
        # All certificate blocks.
        blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            fullchain or "", re.DOTALL)
        # None.
        if not blocks:
            return "", []
        # Leaf first, then CAs.
        return blocks[0] + "\n", [b + "\n" for b in blocks[1:]]

    @staticmethod
    def _split_leaf_cert(fullchain: str) -> str:
        """Return the first ``-----BEGIN CERTIFICATE-----…END CERTIFICATE-----``
        block (the leaf) from a fullchain PEM, or ``""`` if none. (Kept for
        callers/tests that only want the leaf; ``_split_chain`` is the fuller
        split used by ``import_cert``.)"""
        # Leaf only.
        leaf, _ = OpnsenseEngine._split_chain(fullchain)
        return leaf

    async def _find_cert_uuid(self, descr: str) -> Optional[str]:
        """Search Trust→certs for one whose ``descr`` matches; return its uuid
        or ``None``. The OPNsense search endpoint is ``POST /api/trust/cert/search``
        (rows carry ``uuid`` + ``descr``)."""
        # A name is required.
        if not descr:
            return None
        # Search; errors give None.
        try:
            res = await self._request("POST", "/api/trust/cert/search",
                                      data={"searchPhrase": descr, "search": descr})
        except Exception:
            return None
        # Not a dict.
        if not isinstance(res, dict):
            return None
        # First row with the same name.
        rows = res.get("rows") or res.get("data") or []
        for row in rows:
            if isinstance(row, dict) and row.get("descr") == descr and row.get("uuid"):
                return row.get("uuid")
        # Not found.
        return None

    async def get_rules_for_ip(self, ip: str) -> Dict[str, Any]:
        """Fetches all firewall rules associated with a specific IP address."""
        # Fetch all rules and filter by source/destination IP in Python
        res_data = await self.get_all_firewall_rules()
        # Fetch failed.
        if res_data.get("status") == "ERROR":
            return {"status": "ERROR", "details": res_data.get("details")}

        # Rules, as a list.
        rules = res_data.get("data", [])
        if not isinstance(rules, list):
            # API might return a dict with a list under a key
            if isinstance(rules, dict):
                # Values of the first key.
                rules = list(rules.values())[0] if rules else []
            else:
                # Unexpected shape.
                rules = []

        # Rules mentioning the IP.
        filtered_rules = [
            rule for rule in rules
            if ip in str(rule.get("source", "")) or ip in str(rule.get("destination", ""))
        ]

        # None.
        if not filtered_rules:
            return {"status": "SUCCESS", "ip": ip, "rules": [], "source": "empty"}

        # Success.
        return {"status": "SUCCESS", "ip": ip, "rules": filtered_rules}

    async def get_dhcp_leases(self, limit: int = 200) -> Dict[str, Any]:
        """Fetches current DHCP leases using the Kea DHCP server.

        ``limit`` caps the result count (default 200) — a guard against massive
        payloads hitting LLM Payload-Too-Large errors on the interactive/search
        path. The firewall→NetBox discovery sync passes ``limit=0`` to get the
        full lease set (it bypasses the capped cache at the spoke layer).
        """
        # Fetch leases.
        res = await self._request("GET", "/api/kea/leases4/search")

        # Expect a dict.
        if isinstance(res, dict):
            # A _request ERROR envelope has no "rows" — classify it BEFORE the
            # rows-is-None path so an API blip isn't returned as SUCCESS+[] (which
            # feeds "zero leases" into the NetBox discovery sync at limit=0).
            if res.get("status") == "ERROR" or "error" in res or "errorMessage" in res:
                return {"status": "ERROR", "details": res}
            # Rows; none means empty.
            rows = res.get("rows")
            if rows is None:
                logger.info(f"Kea DHCP API returned success but no leases found. Response: {res}")
                return {"status": "SUCCESS", "data": [], "source": "empty"}

            # OPNsense sometimes returns row sets keyed by address/index (a dict
            # instead of a list) — flatten so we don't silently drop every lease.
            if isinstance(rows, dict):
                rows = list(rows.values())
            # Guard against a non-list.
            if not isinstance(rows, list):
                rows = []

            # Map each lease.
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

            # Success.
            return {"status": "SUCCESS", "data": processed_leases}

        # Not a dict.
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
        # Fetch the ARP table.
        res = await self._request("GET", "/api/diagnostics/interface/search_arp")

        # Expect a dict.
        if isinstance(res, dict):
            # Classify a _request ERROR envelope before treating a missing "rows"
            # as "no neighbors" (an API blip must not read as an empty ARP table).
            if res.get("status") == "ERROR" or "error" in res or "errorMessage" in res:
                return {"status": "ERROR", "details": res}
            # Rows.
            rows = res.get("rows")
            if rows is None:
                # Some OPNsense versions return the list under a different key.
                rows = res.get("data") or []
            # Guard against a non-list.
            if not isinstance(rows, list):
                rows = []

            # Map each entry.
            arp = []
            for row in rows:
                # Skip non-dict rows.
                if not isinstance(row, dict):
                    continue
                # IP and MAC; skip rows with neither.
                ip = (row.get("ip") or row.get("address") or "").strip()
                mac = (row.get("mac") or row.get("hwaddr") or "").strip()
                if not ip and not mac:
                    continue
                # Add the row.
                arp.append({
                    "ip": ip or "unknown",
                    "mac": mac or "unknown",
                    "hostname": (row.get("hostname") or "").strip() or "unknown",
                    "interface": (row.get("intf") or row.get("interface") or "").strip(),
                })

            # Success.
            return {"status": "SUCCESS", "data": arp}

        # Not a dict.
        return {"status": "ERROR", "message": "Unexpected ARP API response format"}

    # ------------------------------------------------------------------
    # DHCP global-search helpers (tenant-scoped)
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_mac(raw: str) -> str:
        """Normalize a MAC to lower-colon form (aa:bb:cc:dd:ee:ff).

        Accepts the common variants (``aa:bb:cc:dd:ee:ff``, ``aa-bb-...``,
        ``aabb.ccdd.eeff``, bare ``aabbccddeeff``). If the cleaned hex isn't
        12 chars, return the stripped lowercased input unchanged so partial
        fragments (e.g. ``aa:bb``) still flow through substring matching.
        """
        # Empty input.
        if not raw:
            return ""
        # Hex digits only.
        s = re.sub(r"[^0-9a-fA-F]", "", raw or "").lower()
        # Not a full MAC: return as typed.
        if len(s) != 12:
            return (raw or "").strip().lower()
        # Colon form.
        return ":".join(s[i:i + 2] for i in range(0, 12, 2))

    @staticmethod
    def _ip_in_prefixes(ip_str: str, prefixes: List[str]) -> bool:
        """True if ``ip_str`` (v4 or v6) falls within any CIDR in ``prefixes``.

        Bad CIDRs / IPs are silently skipped (never raise) — a malformed
        tenant prefix must not blank out the whole search.
        """
        # ipaddress for parsing.
        import ipaddress
        # Need an IP and prefixes.
        if not ip_str or not prefixes:
            return False
        # Parse the IP.
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            # Not an IP.
            return False
        # Check each prefix; skip bad ones.
        for cidr in prefixes:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                # Bad prefix.
                continue
        # No match.
        return False

    async def get_dhcp_static_mappings(self) -> Dict[str, Any]:
        """Fetch DHCPv4 static mappings (reservations) from the Kea DHCP server.

        Complements :meth:`get_dhcp_leases` for the global-search path. The
        Kea plugin exposes reservations at ``/api/kea/dhcp4/searchReserved``;
        row field names are hyphenated (``ip-address``/``hw-address``) but we
        fall back to the dynamic-lease names too so a schema drift doesn't
        drop every reservation. Returns ``{id, ip, mac, hostname}`` rows.
        """
        # Fetch reservations.
        res = await self._request("GET", "/api/kea/dhcp4/searchReserved")

        # Expect a dict.
        if isinstance(res, dict):
            # Same ERROR-envelope classification as get_dhcp_leases — an API
            # blip must not read as SUCCESS+[] (search would silently miss
            # all reservations).
            if res.get("status") == "ERROR" or "error" in res or "errorMessage" in res:
                return {"status": "ERROR", "details": res}
            # Rows, under rows or data; none means empty.
            rows = res.get("rows")
            if rows is None:
                rows = res.get("data")
            if rows is None:
                logger.info(f"Kea reservations API returned success but no rows. Response: {res}")
                return {"status": "SUCCESS", "data": [], "source": "empty"}
            # Flatten a dict and guard against a non-list.
            if isinstance(rows, dict):
                rows = list(rows.values())
            if not isinstance(rows, list):
                rows = []

            # Map each reservation.
            mappings = []
            for row in rows:
                # Skip non-dict rows.
                if not isinstance(row, dict):
                    continue
                # IP, MAC and hostname; skip rows with no IP or MAC.
                ip = (row.get("ip-address") or row.get("address") or row.get("ip") or "").strip()
                mac = (row.get("hw-address") or row.get("hwaddr") or row.get("mac") or "").strip()
                host = (row.get("hostname") or row.get("host") or "").strip()
                if not ip and not mac:
                    continue
                # Add the row.
                mappings.append({
                    "id": (row.get("uuid") or ip or "").strip(),
                    "ip": ip or "unknown",
                    "mac": mac or "unknown",
                    "hostname": host or "unknown",
                })
            # Success.
            return {"status": "SUCCESS", "data": mappings}

        # Not a dict.
        return {"status": "ERROR", "message": "Unexpected API response format"}

    async def search_dhcp(self, q: str,
                          prefixes: Optional[List[str]] = None,
                          is_admin: bool = False) -> Dict[str, Any]:
        """Tenant-scoped DHCP search across dynamic leases AND static mappings.

        Matches ``q`` against lease IP, hostname, and MAC. The hub normalizes
        a MAC query to lower-colon form before sending; we re-normalize here
        (idempotent) and also compare against the normalized lease MAC so
        ``aa:bb:cc:dd:ee:ff`` matches ``aabb.ccdd.eeff``.

        Prefix scoping (enforced spoke-side, never trusts the hub filter):
          * ``prefixes`` non-empty  → only results whose IP is in one CIDR;
          * ``prefixes`` empty + ``is_admin`` True  → unscoped (all leases);
          * ``prefixes`` empty + ``is_admin`` False → EMPTY (never leak
            another tenant's leases).

        Returns ``{status, results, count}`` where each result dict carries
        at minimum ``source``, ``type``, ``name``, ``ip``, ``mac``.
        """
        # Unexpected failures return an ERROR result.
        try:
            # Lowercase query and its MAC form.
            q_low = (q or "").strip().lower()
            q_mac = self._normalize_mac(q or "")
            has_prefixes = bool(prefixes)

            def _matches(ip: str, host: str, mac: str) -> bool:
                """True if the query appears in the IP, hostname or MAC."""
                # Empty query matches nothing.
                if not q_low:
                    return False
                # Compare against the normalised MAC too.
                mac_norm = self._normalize_mac(mac)
                return (q_low in (ip or "").lower() or
                        q_low in (host or "").lower() or
                        (bool(q_mac) and q_mac == mac_norm) or
                        q_low in mac_norm)

            def _in_scope(ip_str: str) -> bool:
                """True if the IP is visible to this caller."""
                # With prefixes: inside one of them.
                if has_prefixes:
                    return self._ip_in_prefixes(ip_str, prefixes or [])
                # No prefixes: admin sees everything, non-admin sees nothing.
                return bool(is_admin)

            # Collected results.
            results: List[Dict[str, Any]] = []

            # --- dynamic leases ---
            try:
                # Leases; a failure is only logged.
                leases_r = await self.get_dhcp_leases()
                # Matching, in-scope leases.
                if leases_r.get("status") == "SUCCESS":
                    for lease in leases_r.get("data", []):
                        # Fields.
                        ip = lease.get("ip", "") or ""
                        host = lease.get("hostname", "") or ""
                        mac = lease.get("mac", "") or ""
                        # Skip non-matches and out-of-scope IPs.
                        if not _matches(ip, host, mac):
                            continue
                        if not _in_scope(ip):
                            continue
                        # Add the result.
                        results.append({
                            "source": "opnsense",
                            "type": "dhcp_lease",
                            "id": ip,
                            "name": host if host and host != "unknown" else ip,
                            "ip": ip,
                            "mac": self._normalize_mac(mac),
                            "state": "active",
                            "lease_end": lease.get("lease_end", ""),
                        })
            except Exception as e:
                # Leases failed.
                logger.warning(f"search_dhcp dynamic-leases leg failed: {e}")

            # --- static mappings (reservations) ---
            try:
                # Reservations; a failure is only logged.
                static_r = await self.get_dhcp_static_mappings()
                # Matching, in-scope reservations.
                if static_r.get("status") == "SUCCESS":
                    for sm in static_r.get("data", []):
                        # Fields.
                        ip = sm.get("ip", "") or ""
                        host = sm.get("hostname", "") or ""
                        mac = sm.get("mac", "") or ""
                        # Skip non-matches and out-of-scope IPs.
                        if not _matches(ip, host, mac):
                            continue
                        if not _in_scope(ip):
                            continue
                        # Add the result.
                        results.append({
                            "source": "opnsense",
                            "type": "dhcp_static",
                            "id": sm.get("id") or ip,
                            "name": host if host and host != "unknown" else ip,
                            "ip": ip,
                            "mac": self._normalize_mac(mac),
                            "state": "reserved",
                        })
            except Exception as e:
                # Reservations failed.
                logger.warning(f"search_dhcp static-mappings leg failed: {e}")

            # Success.
            return {"status": "SUCCESS", "results": results, "count": len(results)}
        except Exception as e:
            # Log and return the error.
            logger.exception("search_dhcp failed")
            return {"status": "ERROR", "message": f"DHCP search failed: {e}"}