# Aruba Central URLs

Every known HPE Aruba Networking Central endpoint — API, device, provisioning and services, for firewall rules,
allow-lists, and connector configuration.

There are **two entirely separate schemes** and they do not map onto each other.
A tenant's Classic cluster does not tell you its New Central URL, or vice versa —
they are configured independently. Notably Classic has no UK or US-West-5
entry, and New Central has no `APAC-SOUTH1` under that name.

Sources: New Central — developer.arubanetworks.com "Making API Calls".
Classic — `CLUSTER_API_BASE_URL_LIST` in [aruba/pycentral](https://github.com/aruba/pycentral/blob/master/pycentral/constants.py),
which is what the client library actually dials. HPE's own doc pages return 403.

> **Using these in OPNsense:** a `URL Table (IPs)` alias accepts only IP
> addresses, CIDR and ranges — it will NOT resolve hostnames, and there is no
> alias type that fetches a list of FQDNs from a URL
> ([opnsense/core#1482](https://github.com/opnsense/core/issues/1482) is still
> open). Use a **`Host(s)`** alias and paste the names in: OPNsense re-resolves
> them via the system resolver every 300s (configurable) and populates the pf
> table with every address returned. [`aruba-central-urls.txt`](aruba-central-urls.txt)
> is the paste-ready list, one FQDN per line.

---

## New Central

| Region | URL |
|---|---|
| US-1 (prod) | `https://us1.api.central.arubanetworks.com` |
| US-2 | `https://us2.api.central.arubanetworks.com` |
| US-West-4 | `https://us4.api.central.arubanetworks.com` |
| US-West-5 | `https://us5.api.central.arubanetworks.com` |
| US-East-1 | `https://us6.api.central.arubanetworks.com` |
| Canada-1 | `https://ca1.api.central.arubanetworks.com` |
| EU-1 | `https://de1.api.central.arubanetworks.com` |
| EU-Central-2 | `https://de2.api.central.arubanetworks.com` |
| EU-Central-3 | `https://de3.api.central.arubanetworks.com` |
| UK | `https://gb1.api.central.arubanetworks.com` |
| APAC-1 (India) | `https://in1.api.central.arubanetworks.com` |
| APAC-East-1 (Japan) | `https://jp1.api.central.arubanetworks.com` |
| APAC-South-1 (Australia) | `https://au1.api.central.arubanetworks.com` |
| UAE-North-1 | `https://ae1.api.central.arubanetworks.com` |
| China | `https://cn1.api.central.arubanetworks.com.cn` |
| Internal | `https://internal.api.central.arubanetworks.com` |

```
https://us1.api.central.arubanetworks.com
https://us2.api.central.arubanetworks.com
https://us4.api.central.arubanetworks.com
https://us5.api.central.arubanetworks.com
https://us6.api.central.arubanetworks.com
https://ca1.api.central.arubanetworks.com
https://de1.api.central.arubanetworks.com
https://de2.api.central.arubanetworks.com
https://de3.api.central.arubanetworks.com
https://gb1.api.central.arubanetworks.com
https://in1.api.central.arubanetworks.com
https://jp1.api.central.arubanetworks.com
https://au1.api.central.arubanetworks.com
https://ae1.api.central.arubanetworks.com
https://cn1.api.central.arubanetworks.com.cn
https://internal.api.central.arubanetworks.com
```

---

## Classic Central

Hostnames here are irregular — they cannot be derived from the cluster name.

| Cluster | URL |
|---|---|
| US-1 | `https://app1-apigw.central.arubanetworks.com` |
| US-2 | `https://apigw-prod2.central.arubanetworks.com` |
| US-East1 | `https://apigw-us-east-1.central.arubanetworks.com` |
| US-West4 | `https://apigw-uswest4.central.arubanetworks.com` |
| EU-1 | `https://eu-apigw.central.arubanetworks.com` |
| EU-Central2 | `https://apigw-eucentral2.central.arubanetworks.com` |
| EU-Central3 | `https://apigw-eucentral3.central.arubanetworks.com` |
| Canada-1 | `https://apigw-ca.central.arubanetworks.com` |
| China-1 | `https://apigw.central.arubanetworks.com.cn` |
| APAC-1 | `https://api-ap.central.arubanetworks.com` |
| APAC-EAST1 | `https://apigw-apaceast.central.arubanetworks.com` |
| APAC-SOUTH1 | `https://apigw-apacsouth.central.arubanetworks.com` |
| UAE-NORTH1 | `https://apigw-uaenorth1.central.arubanetworks.com` |

```
https://app1-apigw.central.arubanetworks.com
https://apigw-prod2.central.arubanetworks.com
https://apigw-us-east-1.central.arubanetworks.com
https://apigw-uswest4.central.arubanetworks.com
https://eu-apigw.central.arubanetworks.com
https://apigw-eucentral2.central.arubanetworks.com
https://apigw-eucentral3.central.arubanetworks.com
https://apigw-ca.central.arubanetworks.com
https://apigw.central.arubanetworks.com.cn
https://api-ap.central.arubanetworks.com
https://apigw-apaceast.central.arubanetworks.com
https://apigw-apacsouth.central.arubanetworks.com
https://apigw-uaenorth1.central.arubanetworks.com
```

---

## All 29

```
https://us1.api.central.arubanetworks.com
https://us2.api.central.arubanetworks.com
https://us4.api.central.arubanetworks.com
https://us5.api.central.arubanetworks.com
https://us6.api.central.arubanetworks.com
https://ca1.api.central.arubanetworks.com
https://de1.api.central.arubanetworks.com
https://de2.api.central.arubanetworks.com
https://de3.api.central.arubanetworks.com
https://gb1.api.central.arubanetworks.com
https://in1.api.central.arubanetworks.com
https://jp1.api.central.arubanetworks.com
https://au1.api.central.arubanetworks.com
https://ae1.api.central.arubanetworks.com
https://cn1.api.central.arubanetworks.com.cn
https://internal.api.central.arubanetworks.com
https://app1-apigw.central.arubanetworks.com
https://apigw-prod2.central.arubanetworks.com
https://apigw-us-east-1.central.arubanetworks.com
https://apigw-uswest4.central.arubanetworks.com
https://eu-apigw.central.arubanetworks.com
https://apigw-eucentral2.central.arubanetworks.com
https://apigw-eucentral3.central.arubanetworks.com
https://apigw-ca.central.arubanetworks.com
https://apigw.central.arubanetworks.com.cn
https://api-ap.central.arubanetworks.com
https://apigw-apaceast.central.arubanetworks.com
https://apigw-apacsouth.central.arubanetworks.com
https://apigw-uaenorth1.central.arubanetworks.com
```

---

## Device, provisioning and service endpoints

The API base URLs above are only what an *API client* needs. Devices and the
platform itself reach considerably more. These are the firewall/proxy allow-list
entries from the "Opening Firewall Ports for Device Communication" tables.

**Provenance:** HPE's own doc pages return 403 or reset the connection to
automated fetches, so these came from a documentation mirror. Treat the set as
thorough but NOT guaranteed exhaustive -- new cluster zones appear over time,
and a region you use may have a `device-*` host not listed here. The
authoritative per-tenant answer is in Central under the cluster-zone / API
Gateway pages.

### Device communication (Classic clusters) — TCP 443

| Host | Notes |
|---|---|
| `app1.central.arubanetworks.com` | US-1 |
| `device-prod2.central.arubanetworks.com` | US-2 |
| `device-uswest4.central.arubanetworks.com` | US-West4 |
| `device-eu.central.arubanetworks.com` | EU-1 |
| `device-eucentral3.central.arubanetworks.com` | EU-Central3 |
| `device-ca.central.arubanetworks.com` | Canada-1 |
| `device.central.arubanetworks.com.cn` | China-1 |
| `app1-ap.central.arubanetworks.com` | APAC-1 |
| `device-apaceast.central.arubanetworks.com` | APAC-East1 |
| `device-apacsouth.central.arubanetworks.com` | APAC-South1 |
| `device-uaenorth1.central.arubanetworks.com` | UAE-North1 |

### AOS-CX device communication (`-d2`) — TCP 443

`device-prod2-d2` · `device-uswest4-d2` · `device-eucentral3-d2` ·
`device-uaenorth1-d2` (all `.central.arubanetworks.com`)

### Activate / provisioning — TCP 443

| Host | Purpose |
|---|---|
| `device.arubanetworks.com` | Activate device provisioning |
| `devices-v2.arubanetworks.com` | Activate v2 |
| `activate.arubanetworks.com` | Activate |
| `est.arubanetworks.com` | EST certificate provisioning |

### Platform services

| Host | Purpose | Ports |
|---|---|---|
| `rcs-ng-prod.central.arubanetworks.com` | Remote Configuration Service | 443 (SSH) |
| `rcs-ng-xp-prod.central.arubanetworks.com` | RCS | 443 (SSH) |
| `naw2.cloudguest.central.arubanetworks.com` | CloudGuest | 443, 2083 |
| `common.cloud.hpe.com` | HPE GreenLake / firmware registry | 80, 443 |
| `d20kce0f6gvxjn.cloudfront.net` | Firmware/software delivery CDN | 443 |
| `stun.pqm.arubanetworks.com` | STUN (path quality) | 3478-3479 |
| `pqm.arubanetworks.com` | Path quality monitoring | ICMP, 4500 |
| `pool.ntp.org` | NTP | UDP 123 |

### Web Content Classification (BrightCloud)

`aruba.brightcloud.com` · `bcap15-dualstack.brightcloud.com` ·
`api-dualstack.bcti.brightcloud.com` · `database-dualstack.brightcloud.com` — TCP 443

> `pool.ntp.org` and the BrightCloud/CloudFront hosts are third-party, not
> Aruba-operated. Include them only if you actually run those features — NTP via
> the pool and WebCC classification respectively.

---

## Fetching

```sh
curl -fsSL https://raw.githubusercontent.com/lbockenstedt/opnsense/main/docs/aruba-central-urls.md
```

Bare hostnames, one per line — paste into a `Host(s)` alias:

```sh
curl -fsSL https://raw.githubusercontent.com/lbockenstedt/opnsense/main/docs/aruba-central-urls.txt
```
