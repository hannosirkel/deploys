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
raise 'MongoDB must run one replica for the isolated backup drill' unless one(documents, 'StatefulSet', 'ai-portal-mongodb-store').dig('spec', 'replicas') == 1
ingress = one(documents, 'NetworkPolicy', 'allow-portal-tunnel-ingress')
raise 'tunnel ingress must remain disabled until Orange supplies the observed host source range' unless ingress.dig('spec', 'podSelector', 'matchLabels') == { 'app.kubernetes.io/component' => 'portal' } && ingress.dig('spec', 'policyTypes') == ['Ingress'] && ingress.dig('spec', 'ingress') == []
policy = one(documents, 'NetworkPolicy', 'allow-portal-internal-egress')
raise 'portal egress must be limited to in-cluster peers' unless policy.dig('spec', 'egress').all? { |rule| rule.fetch('to').all? { |peer| !peer.key?('ipBlock') } }
jwks = one(documents, 'NetworkPolicy', 'allow-portal-access-jwks-egress')
raise 'Access key egress must select only portal pods' unless jwks.dig('spec', 'podSelector', 'matchLabels') == { 'app.kubernetes.io/component' => 'portal' }
raise 'Access key policy must govern egress only' unless jwks.dig('spec', 'policyTypes') == ['Egress']
rules = jwks.dig('spec', 'egress')
raise 'Access key policy must have exactly one egress rule' unless rules.length == 1
raise 'Access key egress must use only HTTPS' unless rules.fetch(0)['ports'] == [{ 'port' => 443, 'protocol' => 'TCP' }]
peers = rules.fetch(0).fetch('to')
raise 'Access key egress must use only exact CIDRs' unless peers.all? { |peer| peer.keys == ['ipBlock'] && peer.fetch('ipBlock').keys == ['cidr'] }
cidrs = peers.map { |peer| peer.fetch('ipBlock').fetch('cidr') }
expected = %w[173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22]
raise 'Access key egress must use the reviewed Cloudflare IPv4 ranges' unless cidrs.sort == expected.sort

chat = one(documents, 'Deployment', 'ai-portal-librechat')
raise 'LibreChat must remain stopped until its profile bootstrap is ready' unless chat.dig('spec', 'replicas') == 0
chat_pod = chat.dig('spec', 'template', 'spec')
chat_container = chat_pod.fetch('containers').fetch(0)
raise 'LibreChat image must pin v0.8.7 by digest' unless chat_container['image'].match?(%r{\Aghcr\.io/danny-avila/librechat:v0\.8\.7@sha256:[0-9a-f]{64}\z})
raise 'LibreChat must not receive a service account token' unless chat_pod['automountServiceAccountToken'] == false
raise 'LibreChat must run as its non-root image user' unless chat_pod.dig('securityContext', 'runAsNonRoot') == true && chat_pod.dig('securityContext', 'runAsUser') == 1000
raise 'LibreChat must have a read-only root filesystem' unless chat_container.dig('securityContext', 'readOnlyRootFilesystem') == true
chat_env = chat_container.fetch('env').to_h { |item| [item.fetch('name'), item] }
raise 'LibreChat must write npm runtime files under tmp' unless chat_env.dig('HOME', 'value') == '/tmp' && chat_env.dig('NPM_CONFIG_CACHE', 'value') == '/tmp/.npm'
raise 'local password login must be disabled' unless chat_env.dig('ALLOW_EMAIL_LOGIN', 'value') == 'false' && chat_env.dig('ALLOW_REGISTRATION', 'value') == 'false' && chat_env.dig('ALLOW_PASSWORD_RESET', 'value') == 'false'
raise 'OIDC must require an approved Authentik group' unless chat_env.dig('OPENID_REQUIRED_ROLE', 'value') == 'ai-portal-user,ai-portal-admin' && chat_env.dig('OPENID_REQUIRED_ROLE_PARAMETER_PATH', 'value') == 'groups' && chat_env.dig('OPENID_REQUIRED_ROLE_TOKEN_KIND', 'value') == 'id'
raise 'OIDC admin must require the admin group' unless chat_env.dig('OPENID_ADMIN_ROLE', 'value') == 'ai-portal-admin' && chat_env.dig('OPENID_ADMIN_ROLE_PARAMETER_PATH', 'value') == 'groups' && chat_env.dig('OPENID_ADMIN_ROLE_TOKEN_KIND', 'value') == 'id'
raise 'OIDC role sync must use managed groups' unless chat_env.dig('OPENID_ROLE_SYNC_ENABLED', 'value') == 'true' && chat_env.dig('OPENID_ROLE_SYNC_SOURCE', 'value') == 'id' && chat_env.dig('OPENID_ROLE_SYNC_CLAIM', 'value') == 'groups' && chat_env.dig('OPENID_ROLE_SYNC_ROLE_PRIORITY', 'value') == 'ai-portal-user' && chat_env.dig('OPENID_ROLE_SYNC_FALLBACK_ROLE', 'value') == 'USER'
raise 'LibreChat must use the reviewed subpath' unless chat_env.dig('DOMAIN_CLIENT', 'value') == 'https://ai.example.com/chat' && chat_env.dig('DOMAIN_SERVER', 'value') == 'https://ai.example.com/chat'
raise 'LibreChat must use the ConfigMap policy' unless chat_env.dig('CONFIG_PATH', 'value') == '/app/librechat.yaml' && chat_container.fetch('volumeMounts').any? { |item| item['mountPath'] == '/app/librechat.yaml' && item['readOnly'] == true }
raise 'OpenRouter key must come from ESO' unless chat_env.dig('OPENROUTER_KEY', 'valueFrom', 'secretKeyRef') == { 'name' => 'ai-portal-openrouter', 'key' => 'api-key' }
raise 'OIDC client secret must come from ESO' unless chat_env.dig('OPENID_CLIENT_SECRET', 'valueFrom', 'secretKeyRef') == { 'name' => 'ai-portal-runtime', 'key' => 'client-secret' }
raise 'LibreChat must remain ClusterIP-only' unless one(documents, 'Service', 'ai-portal-librechat').dig('spec', 'type') == 'ClusterIP'
puts 'AI Portal runtime image, credentials, probes, and network contracts hold'
RUBY
