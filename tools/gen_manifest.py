#!/usr/bin/env python3
"""Generate manifest.json for the HTTP(S) plugin source.

Lists every plugins/*.json with its sha256 so `vulnscan plugins add http <url>`
can fetch and integrity-check each file. Run from the repo root:

    python3 tools/gen_manifest.py
"""
import glob
import hashlib
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
entries = []
for path in sorted(glob.glob(os.path.join(ROOT, "plugins", "*.json"))):
    with open(path, "rb") as f:
        data = f.read()
    entries.append({
        "file": "plugins/" + os.path.basename(path),
        "sha256": hashlib.sha256(data).hexdigest(),
    })

with open(os.path.join(ROOT, "manifest.json"), "w", encoding="utf-8") as f:
    json.dump({"name": "vulnscan-plugins", "plugins": entries}, f, indent=2)
    f.write("\n")
print(f"wrote manifest.json with {len(entries)} plugin(s)")
