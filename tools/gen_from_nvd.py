#!/usr/bin/env python3
"""Generate declarative vulnscan plugins in bulk from the NVD 2.0 API.

For each product the scanner can fingerprint, this queries NVD for its CVEs,
reads the affected *version ranges* out of each CVE's `configurations`, and
writes one plugin per (CVE, range). The result is an OFFLINE plugin catalog:
once generated, scans need no NVD access and run without per-request rate
limits, with consistent severity and remediation text.

Each generated plugin matches by CPE substring + version bounds, e.g.:
    { "cpe_contains": "apache:http_server:", "version": {"ge":"2.4.0","lt":"2.4.52"} }
which lines up with how vulnscan fingerprints a service (it stamps a CPE).

Usage:
    export NVD_API_KEY=...            # optional, but raises the rate limit a lot
    python3 tools/gen_from_nvd.py                      # HIGH+ , default products
    python3 tools/gen_from_nvd.py --min-severity CRITICAL --max-per-product 40
    python3 tools/gen_from_nvd.py --products apache-http-server,nginx
    python3 tools/gen_from_nvd.py --kev-only            # only CISA KEV CVEs

Only stdlib is used. Rank with NVD's CVSS; skip rules with no usable version
bound (those would match every version and cause false positives).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# id-prefix -> "vendor:product" (CPE). Mirrors vulnscan's fingerprint CPE map;
# add a line here (and a fingerprint there) to cover a new product.
PRODUCTS = {
    "apache-http-server": "apache:http_server",
    "nginx": "f5:nginx",
    "openssh": "openbsd:openssh",
    "iis": "microsoft:internet_information_services",
    "tomcat": "apache:tomcat",
    "jetty": "eclipse:jetty",
    "jenkins": "jenkins:jenkins",
    "elasticsearch": "elastic:elasticsearch",
    "kibana": "elastic:kibana",
    "exim": "exim:exim",
    "sendmail": "sendmail:sendmail",
    "dovecot": "dovecot:dovecot",
    "vsftpd": "beasts:vsftpd",
    "proftpd": "proftpd:proftpd",
    "redis": "redis:redis",
    "mariadb": "mariadb:mariadb",
    "couchdb": "apache:couchdb",
    "mongodb": "mongodb:mongodb",
    "wordpress": "wordpress:wordpress",
    "drupal": "drupal:drupal",
    "joomla": "joomla:joomla",
    "grafana": "grafana:grafana",
    "phpmyadmin": "phpmyadmin:phpmyadmin",
    "exchange": "microsoft:exchange_server",
    "squid": "squid-cache:squid",
    "lighttpd": "lighttpd:lighttpd",
    "openresty": "openresty:openresty",
}

SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SLUG = re.compile(r"[^a-z0-9]+")


def _req(url: str, api_key: str | None, timeout: int = 60) -> dict:
    headers = {"User-Agent": "vulnscan-plugin-gen/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    for attempt in range(4):
        try:
            r = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(r, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503):
                time.sleep(6 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            time.sleep(3 * (attempt + 1))
    raise RuntimeError(f"request failed: {url}")


def load_kev(api_key: str | None) -> set[str]:
    try:
        doc = _req(KEV_URL, None)
        return {v["cveID"] for v in doc.get("vulnerabilities", [])}
    except Exception as e:  # noqa: BLE001
        print(f"[!] could not load KEV ({e}); --kev-only disabled", file=sys.stderr)
        return set()


def best_cvss(metrics: dict) -> tuple[float | None, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            sev = (arr[0].get("baseSeverity") or data.get("baseSeverity", "")).upper()
            return data.get("baseScore"), sev
    return None, ""


def version_constraint(cpe_match: dict) -> dict | None:
    """Turn one cpeMatch into a version constraint dict, or None if unusable."""
    c = {}
    if cpe_match.get("versionStartIncluding"):
        c["ge"] = cpe_match["versionStartIncluding"]
    if cpe_match.get("versionStartExcluding"):
        c["gt"] = cpe_match["versionStartExcluding"]
    if cpe_match.get("versionEndIncluding"):
        c["le"] = cpe_match["versionEndIncluding"]
    if cpe_match.get("versionEndExcluding"):
        c["lt"] = cpe_match["versionEndExcluding"]
    if c:
        return c
    # No range -> maybe an exact pinned version in the CPE itself.
    parts = cpe_match.get("criteria", "").split(":")
    if len(parts) > 5 and parts[5] not in ("*", "-", ""):
        return {"eq": parts[5]}
    return None


def ranges_for_product(cve: dict, vendor_product: str) -> list[dict]:
    """All distinct version constraints in this CVE that hit our product."""
    needle = ":" + vendor_product + ":"
    out, seen = [], set()
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                if needle not in m.get("criteria", ""):
                    continue
                c = version_constraint(m)
                if c is None:
                    continue
                key = json.dumps(c, sort_keys=True)
                if key not in seen:
                    seen.add(key)
                    out.append(c)
    return out


def remediation(constraint: dict) -> str:
    if "lt" in constraint:
        return f"Upgrade to version {constraint['lt']} or later."
    if "le" in constraint:
        return f"Upgrade to a version newer than {constraint['le']}."
    if "eq" in constraint:
        return f"Upgrade away from the affected version {constraint['eq']}."
    return "Upgrade to a fixed version per the referenced advisory."


def fetch_cves(vendor_product: str, api_key: str | None):
    """Yield CVE dicts for a product's CPE, paging through NVD."""
    cpe = "cpe:2.3:a:" + vendor_product
    start, total = 0, None
    while total is None or start < total:
        url = (f"{NVD_API}?virtualMatchString={urllib.parse.quote(cpe)}"
               f"&resultsPerPage=2000&startIndex={start}")
        doc = _req(url, api_key)
        total = doc.get("totalResults", 0)
        vulns = doc.get("vulnerabilities", [])
        for item in vulns:
            yield item.get("cve", {})
        start += len(vulns) or 2000
        time.sleep(0.6 if api_key else 6.5)
        if not vulns:
            break


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(ROOT, "plugins"))
    ap.add_argument("--min-severity", default="HIGH",
                    choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    ap.add_argument("--max-per-product", type=int, default=80)
    ap.add_argument("--since", type=int, metavar="YEAR",
                    help="only CVEs published in/after this year")
    ap.add_argument("--products", help="comma list of ids (default: all)")
    ap.add_argument("--kev-only", action="store_true",
                    help="only emit CVEs that are in the CISA KEV catalog")
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY")
                    or os.environ.get("VULNSCAN_NVD_KEY"))
    args = ap.parse_args(argv)

    os.makedirs(args.out, exist_ok=True)
    floor = SEV_RANK[args.min_severity]
    kev = load_kev(args.api_key) if args.kev_only else set()
    wanted = (args.products.split(",") if args.products else list(PRODUCTS))

    total_written = 0
    for pid in wanted:
        vp = PRODUCTS.get(pid)
        if not vp:
            print(f"[!] unknown product id {pid!r}; known: {', '.join(PRODUCTS)}",
                  file=sys.stderr)
            continue
        print(f"[*] {pid} ({vp}) ...", file=sys.stderr)
        # Collect ALL qualifying candidates, then keep the most relevant —
        # NVD returns oldest-first, so capping without sorting would grab
        # 1999-era CVEs instead of the ones that matter.
        candidates = []
        try:
            for cve in fetch_cves(vp, args.api_key):
                cve_id = cve.get("id", "")
                if not cve_id or (kev and cve_id not in kev):
                    continue
                if args.since and (cve.get("published", "0000")[:4] or "0") < str(args.since):
                    continue
                score, sev = best_cvss(cve.get("metrics", {}))
                if SEV_RANK.get(sev, 0) < floor:
                    continue
                constraints = ranges_for_product(cve, vp)
                if not constraints:
                    continue
                descs = cve.get("descriptions", [])
                desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                refs = [r.get("url", "") for r in cve.get("references", [])][:6]
                refs.append("https://nvd.nist.gov/vuln/detail/" + cve_id)
                candidates.append({
                    "cve_id": cve_id, "sev": sev, "score": score or 0.0,
                    "published": cve.get("published", ""), "desc": desc,
                    "refs": refs, "constraints": constraints,
                })
        except Exception as e:  # noqa: BLE001
            print(f"[!] {pid}: {e}", file=sys.stderr)

        # Rank: severity, then CVSS, then most recent first.
        candidates.sort(key=lambda c: (SEV_RANK.get(c["sev"], 0), c["score"],
                                       c["published"]), reverse=True)

        written = 0
        for cand in candidates:
            if written >= args.max_per_product:
                break
            cs = cand["constraints"]
            for i, c in enumerate(cs):
                if written >= args.max_per_product:
                    break
                suffix = f"-{i+1}" if len(cs) > 1 else ""
                plugin = {
                    "id": f"nvd-{pid}-{cand['cve_id'].lower()}{suffix}",
                    "name": f"{pid.replace('-', ' ').title()} - {cand['cve_id']} ({cand['sev']})",
                    "severity": cand["sev"],
                    "cve": [cand["cve_id"]],
                    "references": cand["refs"],
                    "description": cand["desc"],
                    "remediation": remediation(c),
                    "match": {"cpe_contains": vp + ":", "version": c},
                }
                path = os.path.join(args.out, plugin["id"] + ".json")
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(plugin, f, indent=2)
                    f.write("\n")
                written += 1
        print(f"    wrote {written} plugin(s) (from {len(candidates)} CVEs)",
              file=sys.stderr)
        total_written += written

    print(f"\n[+] generated {total_written} plugin(s) into {args.out}")
    print("    next: python3 tools/gen_manifest.py   # refresh the HTTP manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
