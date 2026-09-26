#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rendered="$(mktemp)"
trap 'rm -f -- "$rendered"' EXIT
kubectl kustomize "$root/overlays/live" >"$rendered"

ruby -ryaml -rjson - "$root" "$rendered" <<'RUBY'
root = ARGV.fetch(0)
documents = YAML.load_stream(File.read(ARGV.fetch(1)))
one = lambda do |kind, name|
  matches = documents.select { |item| item['kind'] == kind && item.dig('metadata', 'name') == name }
  abort "expected one #{kind}/#{name}" unless matches.length == 1
  matches.fetch(0)
end

chat = JSON.parse(File.read("#{root}/base/librechat.yaml"))
endpoint = chat.fetch('endpoints').fetch('custom').fetch(0)
abort 'chat must use only the in-cluster OpenRouter gateway' unless endpoint['name'] == 'OpenRouter' && endpoint['baseURL'] == 'http://ai-portal-openrouter-egress:8080/api/v1'
abort 'provider key must remain in LibreChat' unless endpoint['apiKey'] == '${OPENROUTER_KEY}'

config = one.call('ConfigMap', 'ai-portal-openrouter-egress')
nginx = config.dig('data', 'nginx.conf.template')
abort 'proxy must pin the OpenRouter upstream and verify TLS' unless nginx&.scan('proxy_pass https://$openrouter_host;')&.length == 2 && nginx.include?('proxy_set_header Host openrouter.ai;') && nginx.include?('proxy_ssl_server_name on;') && nginx.include?('proxy_ssl_name openrouter.ai;') && nginx.include?('proxy_ssl_verify on;') && nginx.include?('proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;')
abort 'proxy must stream model responses' unless nginx.include?('proxy_buffering off;')
abort 'proxy must admit only catalogue and text-chat paths' unless nginx.include?('location = /api/v1/models') && nginx.include?('limit_except GET') && nginx.include?('location = /api/v1/chat/completions') && nginx.include?('limit_except POST') && nginx.include?('location / { return 404; }')

deployment = one.call('Deployment', 'ai-portal-openrouter-egress')
abort 'proxy must be one replica' unless deployment.dig('spec', 'replicas') == 1
pod = deployment.dig('spec', 'template', 'spec')
container = pod.fetch('containers').fetch(0)
abort 'proxy must use pinned unprivileged image' unless container.fetch('image').match?(%r{\Anginxinc/nginx-unprivileged:1\.29\.3-alpine@sha256:[0-9a-f]{64}\z})
abort 'proxy must run without a service account or root filesystem writes' unless pod['automountServiceAccountToken'] == false && pod.dig('securityContext', 'runAsNonRoot') == true && pod.dig('securityContext', 'runAsUser') == 101 && container.dig('securityContext', 'readOnlyRootFilesystem') == true
abort 'proxy must not receive a Secret' if container.fetch('env', []).any? { |item| item.key?('valueFrom') } || pod.fetch('volumes').any? { |item| item.key?('secret') }
abort 'proxy service must be private' unless one.call('Service', 'ai-portal-openrouter-egress').dig('spec', 'type') == 'ClusterIP'

ingress = one.call('NetworkPolicy', 'allow-openrouter-egress-ingress')
abort 'only chat may enter the proxy on TCP 8080' unless ingress.dig('spec', 'podSelector', 'matchLabels') == {'app.kubernetes.io/component' => 'openrouter-egress'} && ingress.dig('spec', 'ingress') == [{'from' => [{'podSelector' => {'matchLabels' => {'app.kubernetes.io/component' => 'chat'}}}], 'ports' => [{'port' => 8080, 'protocol' => 'TCP'}]}]
chat_egress = one.call('NetworkPolicy', 'allow-chat-openrouter-egress')
abort 'chat may leave only to the proxy on TCP 8080' unless chat_egress.dig('spec', 'podSelector', 'matchLabels') == {'app.kubernetes.io/component' => 'chat'} && chat_egress.dig('spec', 'egress') == [{'to' => [{'podSelector' => {'matchLabels' => {'app.kubernetes.io/component' => 'openrouter-egress'}}}], 'ports' => [{'port' => 8080, 'protocol' => 'TCP'}]}]
external = one.call('NetworkPolicy', 'allow-openrouter-https-egress')
abort 'only the proxy may use external HTTPS' unless external.dig('spec', 'podSelector', 'matchLabels') == {'app.kubernetes.io/component' => 'openrouter-egress'} && external.dig('spec', 'egress', 0, 'ports') == [{'port' => 443, 'protocol' => 'TCP'}]
cidrs = external.dig('spec', 'egress', 0, 'to').map { |peer| peer.fetch('ipBlock').fetch('cidr') }
jwks = one.call('NetworkPolicy', 'allow-portal-access-jwks-egress')
approved = jwks.dig('spec', 'egress', 0, 'to').map { |peer| peer.fetch('ipBlock').fetch('cidr') }
abort 'proxy HTTPS must stay within published Cloudflare IPv4 ranges' unless cidrs.sort == approved.sort
chat_egress_names = documents.select do |item|
  next false unless item['kind'] == 'NetworkPolicy' && item.dig('spec', 'policyTypes')&.include?('Egress')
  selector = item.dig('spec', 'podSelector')
  selector == {} || selector.dig('matchLabels', 'app.kubernetes.io/component') == 'chat' ||
    selector.fetch('matchExpressions', []).any? { |expression| expression['key'] == 'app.kubernetes.io/component' && expression.fetch('values', []).include?('chat') }
end.map { |item| item.dig('metadata', 'name') }.sort
expected_chat_egress = %w[allow-chat-authentik-egress allow-chat-openrouter-egress allow-dns-egress allow-mongodb-egress default-deny]
abort 'chat must not receive an unreviewed egress policy' unless chat_egress_names == expected_chat_egress.sort
puts 'OpenRouter chat egress is isolated behind a fixed, TLS-verified proxy'
RUBY
