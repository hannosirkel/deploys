#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf -- "$temporary"' EXIT

cd "$repo_root"

for environment in live test; do
  rendered="$temporary/$environment.yaml"
  kubectl kustomize "overlays/$environment" >"$rendered"
  test "$(grep -c 'image: ghcr.io/hannosirkel/servitium@sha256:' "$rendered")" -eq 1
  ! grep -q 'sha256:0000000000000000000000000000000000000000000000000000000000000000' "$rendered"
done

grep -q 'namespace: servitium$' "$temporary/live.yaml"
grep -q 'name: servitium$' "$temporary/live.yaml"
grep -q 'port: 8099' "$temporary/live.yaml"
grep -q 'value: servitium$' "$temporary/live.yaml"
grep -q 'secretName: servitium-secrets' "$temporary/live.yaml"

grep -q 'namespace: servitium-test$' "$temporary/test.yaml"
grep -q 'name: servitium-test$' "$temporary/test.yaml"
grep -q 'port: 8098' "$temporary/test.yaml"
grep -q 'value: servitium_test$' "$temporary/test.yaml"
grep -q 'value: servitium-test$' "$temporary/test.yaml"
grep -q 'secretName: servitium-test-secrets' "$temporary/test.yaml"
! grep -q 'secretName: servitium-secrets$' "$temporary/test.yaml"

ruby -ryaml - "$temporary/live.yaml" "$temporary/test.yaml" <<'RUBY'
def resource(documents, kind, name)
  matches = documents.select do |document|
    document['kind'] == kind && document.dig('metadata', 'name') == name
  end
  raise "expected one #{kind}/#{name}" unless matches.length == 1
  matches.first
end

def assert_manifest(path, name:, namespace:, port:, database:, user:, secret:, labels:)
  documents = YAML.load_stream(File.read(path)).compact

  raise 'Namespace resources are owned by Orange/Ansible' if documents.any? { |item| item['kind'] == 'Namespace' }
  raise 'Ingress is forbidden' if documents.any? { |item| item['kind'] == 'Ingress' }
  raise 'resource namespace mismatch' unless documents.all? { |item| item.dig('metadata', 'namespace') == namespace }

  deployment = resource(documents, 'Deployment', name)
  spec = deployment.fetch('spec')
  raise 'deployment must use Recreate' unless spec['strategy'] == { 'type' => 'Recreate' }
  expected_labels = labels
  raise 'deployment selector mismatch' unless spec.dig('selector', 'matchLabels') == expected_labels
  raise 'pod labels mismatch' unless spec.dig('template', 'metadata', 'labels') == expected_labels
  pod = spec.dig('template', 'spec')
  raise 'service account token must be disabled' unless pod['automountServiceAccountToken'] == false
  raise 'host namespaces are forbidden' if pod['hostNetwork'] || pod['hostPID'] || pod['hostIPC']
  raise 'pod identity mismatch' unless pod['securityContext'] == {
    'fsGroup' => 10_001,
    'fsGroupChangePolicy' => 'OnRootMismatch',
    'runAsNonRoot' => true,
    'runAsUser' => 10_001,
    'runAsGroup' => 10_001,
    'seccompProfile' => { 'type' => 'RuntimeDefault' },
  }

  container = pod.fetch('containers').fetch(0)
  raise 'image must use a pinned non-zero digest' unless
    container['image'].match?(%r{\Aghcr\.io/hannosirkel/servitium@sha256:[0-9a-f]{64}\z})
  raise 'host port exposure is forbidden' if
    container.fetch('ports').any? { |item| item.key?('hostPort') }
  raise 'container port exposure mismatch' unless container['ports'] == [{
    'name' => 'http', 'containerPort' => port, 'protocol' => 'TCP',
  }]
  raise 'container hardening mismatch' unless container['securityContext'] == {
    'allowPrivilegeEscalation' => false,
    'capabilities' => { 'drop' => ['ALL'] },
    'readOnlyRootFilesystem' => true,
    'runAsNonRoot' => true,
    'runAsUser' => 10_001,
    'runAsGroup' => 10_001,
  }
  raise 'resource contract mismatch' unless container['resources'] == {
    'requests' => { 'cpu' => '100m', 'memory' => '64Mi' },
    'limits' => { 'cpu' => '250m', 'memory' => '128Mi' },
  }

  environment = container.fetch('env').to_h { |entry| [entry['name'], entry['value']] }
  raise 'database environment mismatch' unless environment == {
    'MYSQL_HOST' => 'mysql.mysql.svc.cluster.local',
    'MYSQL_PORT' => '3306',
    'MYSQL_DATABASE' => database,
    'MYSQL_USER' => user,
    'PORT' => port.to_s,
  }
  mount = container.fetch('volumeMounts').fetch(0)
  raise 'secret mount mismatch' unless mount == {
    'name' => secret,
    'mountPath' => '/run/secrets/servitium',
    'readOnly' => true,
  }
  projected_secret = pod.fetch('volumes').fetch(0).fetch('secret')
  raise 'secret projection mismatch' unless
    pod.fetch('volumes').fetch(0)['name'] == secret &&
    projected_secret['secretName'] == secret &&
    projected_secret['defaultMode'] == 256 &&
    projected_secret['items'] == [
      { 'key' => 'bot-token', 'path' => 'discord-bot-token' },
      { 'key' => 'password', 'path' => 'mysql-password' },
    ]

  service = resource(documents, 'Service', name)
  raise 'service must remain ClusterIP' unless service.dig('spec', 'type') == 'ClusterIP'
  raise 'WireGuard-only service address mismatch' unless
    service.dig('spec', 'externalIPs') == ['192.168.21.2']
  raise 'service selector mismatch' unless service.dig('spec', 'selector') == expected_labels
  raise 'service port mismatch' unless service.dig('spec', 'ports') == [{
    'name' => 'http', 'port' => port, 'protocol' => 'TCP', 'targetPort' => 'http',
  }]
  forbidden_service_keys = %w[externalName loadBalancerIP loadBalancerClass]
  raise 'public service exposure is forbidden' if forbidden_service_keys.any? { |key| service.fetch('spec').key?(key) }
  raise 'explicit Service NodePort is forbidden' if service.fetch('spec').fetch('ports').any? { |item| item.key?('nodePort') }

  policy_suffix = name == 'servitium' ? '' : '-test'
  default_deny = resource(documents, 'NetworkPolicy', "default-deny#{policy_suffix}")
  raise 'default deny mismatch' unless default_deny.dig('spec', 'policyTypes').sort == %w[Egress Ingress]

  ingress = resource(documents, 'NetworkPolicy', "allow-wireguard-http#{policy_suffix}")
  raise 'WireGuard policy selector mismatch' unless ingress.dig('spec', 'podSelector', 'matchLabels') == expected_labels
  raise 'WireGuard ingress mismatch' unless ingress.dig('spec', 'ingress') == [{
    'from' => [
      { 'ipBlock' => { 'cidr' => '192.168.21.0/24' } },
      { 'ipBlock' => { 'cidr' => '192.168.1.0/24' } },
    ],
    'ports' => [{ 'port' => port, 'protocol' => 'TCP' }],
  }]

  dns = resource(documents, 'NetworkPolicy', "allow-dns-egress#{policy_suffix}")
  raise 'DNS policy selector mismatch' unless dns.dig('spec', 'podSelector', 'matchLabels') == expected_labels
  raise 'DNS egress mismatch' unless dns.dig('spec', 'egress') == [{
    'to' => [{
      'namespaceSelector' => { 'matchLabels' => {
        'kubernetes.io/metadata.name' => 'kube-system',
      } },
      'podSelector' => { 'matchLabels' => { 'k8s-app' => 'kube-dns' } },
    }],
    'ports' => [
      { 'port' => 53, 'protocol' => 'UDP' },
      { 'port' => 53, 'protocol' => 'TCP' },
    ],
  }]
  mysql = resource(documents, 'NetworkPolicy', "allow-mysql-egress#{policy_suffix}")
  raise 'MySQL policy selector mismatch' unless mysql.dig('spec', 'podSelector', 'matchLabels') == expected_labels
  raise 'MySQL egress mismatch' unless mysql.dig('spec', 'egress') == [{
    'to' => [{ 'namespaceSelector' => { 'matchLabels' => {
      'kubernetes.io/metadata.name' => 'mysql',
    } } }],
    'ports' => [{ 'port' => 3306, 'protocol' => 'TCP' }],
  }]

  rendered = File.read(path)
  raise 'IPv6 exposure is forbidden' if rendered.include?('::')
  raise 'public ingress CIDRs are forbidden' if rendered.include?('0.0.0.0/0')
end

assert_manifest(
  ARGV.fetch(0),
  name: 'servitium', namespace: 'servitium', port: 8099,
  database: 'servitium', user: 'servitium', secret: 'servitium-secrets',
  labels: { 'app.kubernetes.io/name' => 'servitium' },
)
assert_manifest(
  ARGV.fetch(1),
  name: 'servitium-test', namespace: 'servitium-test', port: 8098,
  database: 'servitium_test', user: 'servitium-test', secret: 'servitium-test-secrets',
  labels: {
    'app.kubernetes.io/name' => 'servitium',
    'app.kubernetes.io/instance' => 'test',
  },
)
puts 'manifest contract tests passed'
RUBY
