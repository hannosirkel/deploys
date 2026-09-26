#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
overlay="$root/overlays/live"
digest='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
workspace="$(mktemp -d)"
trap 'rm -rf -- "$workspace"' EXIT
cp "$overlay/kustomization.yaml" "$workspace/kustomization.yaml"

if bash "$root/promote-digest.sh" 'sha256:invalid' "$workspace" 2>/dev/null; then
  echo 'malformed digest was accepted' >&2
  exit 1
fi
cmp "$overlay/kustomization.yaml" "$workspace/kustomization.yaml"
bash "$root/promote-digest.sh" "$digest" "$workspace"
test "$(grep -Ec "^    digest: ${digest}$" "$workspace/kustomization.yaml")" -eq 1
test "$(git diff --no-index --numstat "$overlay/kustomization.yaml" "$workspace/kustomization.yaml" | cut -f1,2)" = $'1\t1'
cp "$workspace/kustomization.yaml" "$workspace/before-rerun.yaml"
bash "$root/promote-digest.sh" "$digest" "$workspace"
cmp "$workspace/before-rerun.yaml" "$workspace/kustomization.yaml"
rm "$workspace/kustomization.yaml"
ln -s "$overlay/kustomization.yaml" "$workspace/kustomization.yaml"
if bash "$root/promote-digest.sh" "$digest" "$workspace" 2>/dev/null; then
  echo 'symlinked overlay was accepted' >&2
  exit 1
fi

# Ruby reads $stdin; the single quotes deliberately prevent shell expansion.
# shellcheck disable=SC2016
kubectl kustomize "$overlay" | ruby -ryaml -e '
  overlay = YAML.load_file(ARGV.fetch(0))
  images = overlay.fetch("images")
  abort "expected one AI Portal image override" unless images.length == 1 && images.fetch(0)["name"] == "ghcr.io/hannosirkel/ai-portal"
  digest = images.fetch(0).fetch("digest")
  abort "image override must pin a digest" unless digest.match?(/\Asha256:[0-9a-f]{64}\z/)
  resources = YAML.load_stream($stdin.read)
  portal = resources.find { |item| item["kind"] == "Deployment" && item.dig("metadata", "name") == "ai-portal" }
  abort "portal image did not come from live overlay" unless portal.dig("spec", "template", "spec", "containers", 0, "image") ==
    "ghcr.io/hannosirkel/ai-portal@#{digest}"
' "$overlay/kustomization.yaml"
echo 'AI Portal image digest promotion is bounded and idempotent'
