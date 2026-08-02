# Aruba Central API URLs

Every known HPE Aruba Networking Central API base URL, for firewall rules,
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

## Fetching

```sh
curl -fsSL https://raw.githubusercontent.com/lbockenstedt/opnsense/main/docs/aruba-central-urls.md
```

Bare hostnames, one per line — paste into a `Host(s)` alias:

```sh
curl -fsSL https://raw.githubusercontent.com/lbockenstedt/opnsense/main/docs/aruba-central-urls.txt
```
