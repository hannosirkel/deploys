#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'usage: promote-digest.sh sha256:DIGEST OVERLAY_DIRECTORY' >&2
  exit 2
fi

digest="$1"
overlay="$2"
if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo 'promotion rejected: malformed digest' >&2
  exit 1
fi
file="$overlay/kustomization.yaml"
if [[ ! -d "$overlay" || -L "$overlay" || ! -f "$file" || -L "$file" ]]; then
  echo 'promotion rejected: overlay file is unavailable or linked' >&2
  exit 1
fi
if [[ "$(stat -c %h "$file")" != 1 ]]; then
  echo 'promotion rejected: overlay file has multiple hard links' >&2
  exit 1
fi

image='ghcr.io/hannosirkel/ai-portal'
if [[ "$(grep -Fxc "  - name: $image" "$file")" != 1 ]] \
  || [[ "$(grep -Ec '^    digest: sha256:[0-9a-f]{64}$' "$file")" != 1 ]] \
  || [[ "$(grep -F -A2 -x "  - name: $image" "$file" | sed -n '2p')" != "    newName: $image" ]] \
  || [[ ! "$(grep -F -A2 -x "  - name: $image" "$file" | sed -n '3p')" =~ ^\ \ \ \ digest:\ sha256:[0-9a-f]{64}$ ]]; then
  echo 'promotion rejected: expected exactly one pinned AI Portal image' >&2
  exit 1
fi

if grep -Fqx "    digest: $digest" "$file"; then
  exit 0
fi

candidate="$(mktemp "$overlay/.ai-portal-digest.XXXXXX")"
trap 'rm -f -- "$candidate"' EXIT
sed -E "s|^(    digest: )sha256:[0-9a-f]{64}$|\\1$digest|" "$file" >"$candidate"
chmod --reference="$file" "$candidate"
mv -f -- "$candidate" "$file"
trap - EXIT
