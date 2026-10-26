# vulnscan-plugins

A shareable catalog of **declarative detection plugins** for
[vulnscan](https://github.com/barlito1416/Insider). Each plugin is one JSON file
under [`plugins/`](plugins) — pure data, never code — so pulling this catalog
only ever transfers JSON. No remote-code-execution risk.

## Use it

**As a git source** (auto-updates on `sync`):
```bash
vulnscan plugins add git https://github.com/barlito1416/vulnscan-plugins.git
vulnscan plugins sync
```

**As an HTTP source** (integrity-checked against `manifest.json`):
```bash
vulnscan plugins add http https://raw.githubusercontent.com/barlito1416/vulnscan-plugins/main/manifest.json
```

List what you got:
```bash
vulnscan plugins list
```

## Add a plugin
Drop a new file in `plugins/`, following this shape:

```json
{
  "id": "vendor-cve-2024-0000",
  "name": "Vendor Product < 1.2.3 - Short title",
  "severity": "CRITICAL",
  "cve": ["CVE-2024-0000"],
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-0000"],
  "description": "What the flaw is and when it applies.",
  "remediation": "How to fix it (upgrade target, workaround).",
  "match": { "product_regex": "product", "version": { "lt": "1.2.3" } }
}
```

`match` keys (all optional, ANDed): `service`, `product_regex`, `banner_regex`,
`cpe_contains`, `package`, and `version` (`eq` / `lt` / `le` / `gt` / `ge`).
Prefer precise version ranges; split multi-branch fixes into one plugin per
branch to avoid false positives on patched builds.

After editing, regenerate the HTTP manifest:
```bash
python3 tools/gen_manifest.py
```

## Bulk-generate from NVD
`tools/gen_from_nvd.py` builds plugins **in bulk from the NVD 2.0 API** — for
every fingerprintable product it reads each CVE's affected version ranges and
emits one plugin per range into `plugins/nvd/`. The result is an **offline**
catalog: once generated, scans need no NVD access and run without per-request
rate limits.

```bash
export NVD_API_KEY=...                 # optional, but much faster
python3 tools/gen_from_nvd.py                          # HIGH+ severity, all products
python3 tools/gen_from_nvd.py --min-severity CRITICAL --max-per-product 40
python3 tools/gen_from_nvd.py --products nginx,openssh # just these
python3 tools/gen_from_nvd.py --kev-only               # only CISA KEV CVEs
python3 tools/gen_manifest.py                          # then refresh the manifest
```

Generated plugins match by CPE substring + version bounds, so they line up with
how vulnscan fingerprints a service. Rules with no usable version bound are
skipped (they would match every version). Add a product by adding its
`vendor:product` to the `PRODUCTS` map in the tool and a fingerprint for it in
vulnscan.

## Scheduled refresh (keeps the catalog current)
A GitHub Actions workflow ([`.github/workflows/refresh.yml`](.github/workflows/refresh.yml))
regenerates the NVD plugins + manifest **every Monday at 06:00 UTC** and commits
any changes back to this repo — so `vulnscan plugins sync` always pulls fresh
data. You can also run it on demand from the repo's **Actions** tab
("Refresh plugins from NVD" → *Run workflow*), optionally overriding severity /
cap / since-year.

**Faster, friendlier runs:** add your NVD API key as a repo secret named
`NVD_API_KEY` (Settings → Secrets and variables → Actions). Without it the run
still works, just slower (NVD's keyless rate limit).

Prefer a local schedule instead? A cron entry works too:
```cron
0 6 * * 1  cd /path/to/vulnscan-plugins && python3 tools/gen_from_nvd.py --out plugins/nvd --since 2010 && python3 tools/gen_manifest.py && git commit -am refresh && git push
```

## Scope
These are **detection** rules for known, versioned vulnerabilities — a
prioritized worklist, not proof. Verify findings before acting, and only scan
systems you are authorized to test.
