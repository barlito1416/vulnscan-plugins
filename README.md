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

## Scope
These are **detection** rules for known, versioned vulnerabilities — a
prioritized worklist, not proof. Verify findings before acting, and only scan
systems you are authorized to test.
