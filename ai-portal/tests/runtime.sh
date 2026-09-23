#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rendered="$(mktemp)"
trap 'rm -f -- "$rendered"' EXIT
kubectl kustomize "$root/overlays/live" >"$rendered"
test -s "$rendered"

ruby -ryaml - "$rendered" <<'RUBY'
documents = YAML.load_stream(File.read(ARGV.fetch(0)))
def one(documents, kind, name)
  found = documents.select { |item| item['kind'] == kind && item.dig('metadata', 'name') == name }
  raise "expected one #{kind}/#{name}" unless found.length == 1
  found.fetch(0)
end

deployment = one(documents, 'Deployment', 'ai-portal')
pod = deployment.dig('spec', 'template', 'spec')
container = pod.fetch('containers').fetch(0)
raise 'portal image must be pinned by digest' unless container['image'].match?(%r{\Aghcr\.io/hannosirkel/ai-portal@sha256:[0-9a-f]{64}\z})
raise 'portal must run without a service account token' unless pod['automountServiceAccountToken'] == false
raise 'portal must run non-root' unless pod.dig('securityContext', 'runAsNonRoot') == true && pod.dig('securityContext', 'runAsUser') == 10001
raise 'portal must use a read-only root filesystem' unless container.dig('securityContext', 'readOnlyRootFilesystem') == true
env = container.fetch('env').to_h { |item| [item.fetch('name'), item] }
required = %w[PORTAL_PUBLIC_ORIGIN PORTAL_OIDC_ISSUER PORTAL_OIDC_CLIENT_ID PORTAL_OIDC_CLIENT_SECRET PORTAL_SESSION_SECRET PORTAL_ACCESS_ISSUER PORTAL_ACCESS_AUDIENCE PORTAL_CHAT_UPSTREAM_ORIGIN]
raise 'portal environment contract is incomplete' unless env.keys.sort == required.sort
raise 'OIDC client Secret projection is wrong' unless env.dig('PORTAL_OIDC_CLIENT_SECRET', 'valueFrom', 'secretKeyRef') == { 'name' => 'ai-portal-runtime', 'key' => 'client-secret' }
raise 'session Secret projection is wrong' unless env.dig('PORTAL_SESSION_SECRET', 'valueFrom', 'secretKeyRef') == { 'name' => 'ai-portal-runtime', 'key' => 'session-secret' }
raise 'provider key must not enter portal' if env.keys.any? { |name| name.include?('OPENROUTER') }
raise 'public placeholders must remain reserved' unless env.dig('PORTAL_PUBLIC_ORIGIN', 'value') == 'https://ai.example.com' && env.dig('PORTAL_ACCESS_AUDIENCE', 'value') == 'example-audience'
%w[readinessProbe livenessProbe].each do |probe|
  value = container.fetch(probe).fetch('httpGet')
  raise "#{probe} must address the trusted host" unless value['path'] == '/healthz' && value['httpHeaders'] == [{ 'name' => 'Host', 'value' => 'ai.example.com' }]
end
raise 'portal must remain ClusterIP-only' unless one(documents, 'Service', 'ai-portal').dig('spec', 'type') == 'ClusterIP'
raise 'MongoDB must remain scaled down until backup and restore are ready' unless one(documents, 'StatefulSet', 'ai-portal-mongodb').dig('spec', 'replicas') == 0
policy = one(documents, 'NetworkPolicy', 'allow-portal-internal-egress')
raise 'portal egress must be limited to in-cluster peers' unless policy.dig('spec', 'egress').all? { |rule| rule.fetch('to').all? { |peer| !peer.key?('ipBlock') } }
puts 'AI Portal runtime image, credentials, probes, and network contracts hold'
RUBY
