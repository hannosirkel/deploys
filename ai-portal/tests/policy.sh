#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$root" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
base = json.loads((root / "base/librechat.yaml").read_text())
admin = json.loads((root / "base/admin-override.json").read_text())

approved = {"qwen/qwen3.8-flash", "~deepseek/deepseek-flash-latest"}
endpoints = base["endpoints"]["custom"]
assert len(endpoints) == 1
endpoint = endpoints[0]
assert endpoint["name"] == "OpenRouter"
assert endpoint["baseURL"] == "https://openrouter.ai/api/v1"
assert endpoint["apiKey"] == "${OPENROUTER_KEY}"
assert set(endpoint["models"]["default"]) == approved
assert endpoint["models"]["fetch"] is False

specs = base["modelSpecs"]
assert specs["enforce"] is True
assert {item["preset"]["model"] for item in specs["list"]} == approved
assert all(item["preset"]["endpoint"] == "OpenRouter" for item in specs["list"])
assert len(specs["list"]) == len(approved)

assert admin["modelSpecs"] == {"enforce": False, "list": []}
assert admin["endpoints"]["custom"] == [
    {"name": "OpenRouter", "models": {"fetch": True}}
]
assert base["fileConfig"]["endpoints"]["default"]["disabled"] is True
assert base["fileConfig"]["endpoints"]["OpenRouter"]["disabled"] is True
print("AI Portal LibreChat profile policy is bounded to OpenRouter")
PY

kubectl kustomize "$root/overlays/live" >/dev/null
