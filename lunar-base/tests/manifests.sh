#!/usr/bin/env bash
set -euo pipefail

# Renders both Lunar Base overlays and asserts their behaviour: the
# environment boundary, the single-process contract, the restricted non-root
# container, the default-deny policy and the permitted egress. Refuses rather
# than skips when a tool or an overlay is absent, as the other roots' tests do.

for tool in kubectl ruby; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is not on PATH; refusing rather than checking nothing" >&2
    exit 1
  fi
done

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf -- "$temporary"' EXIT

cd "$repo_root"

for environment in live test; do
  overlay="lunar-base/overlays/$environment"
  test -f "$overlay/kustomization.yaml" || {
    echo "missing Lunar Base $environment overlay" >&2
    exit 1
  }
  kubectl kustomize "$overlay" >"$temporary/$environment.yaml"
  test -s "$temporary/$environment.yaml" || {
    echo "Lunar Base $environment overlay rendered nothing" >&2
    exit 1
  }
done

ruby -ryaml - "$temporary/live.yaml" "$temporary/test.yaml" \
  lunar-base/overlays/live/kustomization.yaml \
  lunar-base/overlays/test/kustomization.yaml <<'RUBY'
IMAGE = 'ghcr.io/plepicgames/lunar-base'
# A digest shape, not a digest value: the bootstrap sentinel and a promoted
# digest are equally valid, because the two overlays are promoted separately.
DIGEST_SHAPE = /\Asha256:[0-9a-f]{64}\z/.freeze
BASE_PATH = '/play/lunar-base'
LOG_DIR = '/var/lib/lunar-base/games'
JEV_SECRET = 'lunar-base-jev'
POD_LABELS = {
  'app.kubernetes.io/name' => 'lunar-base',
  'app.kubernetes.io/component' => 'game',
  'app.kubernetes.io/part-of' => 'lunar-base',
}.freeze
GAME_SELECTOR = { 'matchLabels' => { 'app.kubernetes.io/component' => 'game' } }.freeze
# Reserved names only (RFC 2606). Orange injects the real origins.
RESERVED_ORIGIN = %r{\Ahttps://([a-z0-9-]+\.)*example\.(com|org|net)\z}.freeze

def check(condition, message)
  raise message unless condition
end

def resource(documents, kind, name)
  matches = documents.select do |document|
    document['kind'] == kind && document.dig('metadata', 'name') == name
  end
  check(matches.length == 1, "expected one #{kind}/#{name}, found #{matches.length}")
  matches.first
end

def wave(document)
  document.dig('metadata', 'annotations', 'argocd.argoproj.io/sync-wave')
end

def assert_inventory(documents, namespace, suffix, policies)
  kinds = documents.map { |item| item['kind'] }.sort
  expected = (%w[Deployment PersistentVolumeClaim Service] + ['NetworkPolicy'] * policies.length).sort
  # An HPA, a PodDisruptionBudget, a Secret, a Namespace or an Ingress would
  # each show up here as an unexpected kind.
  check(kinds == expected, "#{namespace}: unexpected resource kinds #{kinds.inspect}")
  check(documents.all? { |item| item.dig('metadata', 'namespace') == namespace },
        "#{namespace}: a resource is outside the namespace")
  names = documents.select { |item| item['kind'] == 'NetworkPolicy' }.map { |item| item.dig('metadata', 'name') }
  check(names.sort == policies.map { |name| "#{name}#{suffix}" }.sort,
        "#{namespace}: unexpected NetworkPolicies #{names.inspect}")
end

def assert_deployment(documents, suffix)
  deployment = resource(documents, 'Deployment', "lunar-base#{suffix}")
  spec = deployment.fetch('spec')
  check(spec['replicas'] == 1, 'the game must run exactly one replica')
  check(spec['strategy'] == { 'type' => 'Recreate' }, 'the game must use Recreate')
  check(spec.dig('selector', 'matchLabels') == { 'app.kubernetes.io/name' => 'lunar-base' },
        'deployment selector mismatch')
  check(spec.dig('template', 'metadata', 'labels') == POD_LABELS, 'pod labels mismatch')
  check(wave(deployment) == '0', 'deployment sync wave mismatch')

  pod = spec.dig('template', 'spec')
  check(pod['automountServiceAccountToken'] == false, 'service account token must be disabled')
  check(!(pod['hostNetwork'] || pod['hostPID'] || pod['hostIPC']), 'host namespaces are forbidden')
  check(pod['terminationGracePeriodSeconds'] == 30, 'termination grace period mismatch')
  check(pod['securityContext'] == {
    'runAsNonRoot' => true, 'runAsUser' => 10_001, 'runAsGroup' => 10_001,
    'fsGroup' => 10_001, 'fsGroupChangePolicy' => 'OnRootMismatch',
    'seccompProfile' => { 'type' => 'RuntimeDefault' },
  }, 'pod security context mismatch')
  check(pod.fetch('initContainers', []).empty?, 'no init container is expected')
  check(pod.fetch('containers').length == 1, 'exactly one container is expected')
  [pod, pod.fetch('containers').fetch(0)]
end

def assert_container(container)
  name, digest = container.fetch('image').split('@', 2)
  check(name == IMAGE && digest.to_s.match?(DIGEST_SHAPE),
        "image must be #{IMAGE} pinned by digest, got #{container['image']}")
  check(container['securityContext'] == {
    'allowPrivilegeEscalation' => false,
    'capabilities' => { 'drop' => ['ALL'] },
    'readOnlyRootFilesystem' => true,
  }, 'container hardening mismatch')
  check(container['ports'] == [{ 'name' => 'http', 'containerPort' => 4780, 'protocol' => 'TCP' }],
        'container port mismatch')
  check(container['resources'] == {
    'requests' => { 'cpu' => '100m', 'memory' => '128Mi' },
    'limits' => { 'cpu' => '500m', 'memory' => '384Mi' },
  }, 'resource contract mismatch')
  %w[startupProbe readinessProbe livenessProbe].each do |probe|
    check(container.dig(probe, 'httpGet') == { 'path' => "#{BASE_PATH}/healthz", 'port' => 'http' },
          "#{probe} must GET the prefixed health path on the container port")
  end
end

def assert_log_volume(documents, pod, container, suffix)
  claim = resource(documents, 'PersistentVolumeClaim', "lunar-base-games#{suffix}")
  check(claim.dig('spec', 'accessModes') == ['ReadWriteOnce'], 'log claim access mode mismatch')
  check(claim.dig('spec', 'resources', 'requests', 'storage') == '1Gi', 'log claim size mismatch')
  # local-path binds on first consumer: the claim shares the consumer's wave.
  check(wave(claim) == '0', 'log claim sync wave mismatch')
  check(pod['volumes'] == [{
    'name' => 'games', 'persistentVolumeClaim' => { 'claimName' => "lunar-base-games#{suffix}" },
  }], 'the log claim must be the only volume')
  check(container['volumeMounts'] == [{ 'name' => 'games', 'mountPath' => LOG_DIR }],
        'the log directory must be the only mount, and writable')
end

def assert_environment(container, jev:)
  entries = container.fetch('env')
  literal = entries.reject { |entry| entry.key?('valueFrom') }.to_h { |entry| [entry['name'], entry['value']] }
  origin = literal.delete('LUNAR_ALLOWED_ORIGINS')
  check(origin.to_s.match?(RESERVED_ORIGIN), "allowed origins must be a reserved placeholder, got #{origin.inspect}")
  check(literal == {
    'PORT' => '4780', 'HOST' => '0.0.0.0',
    'LUNAR_BASE_PATH' => BASE_PATH, 'LUNAR_LOG_DIR' => LOG_DIR, 'LUNAR_LOG_DAYS' => '30',
    'LUNAR_TRUST_PROXY' => 'true', 'LUNAR_MAX_GAMES' => '20',
    'LUNAR_MAX_CONNECTIONS_PER_ADDRESS' => '8', 'LUNAR_MAX_NEW_GAMES_PER_HOUR' => '10',
  }, "settings mismatch: #{literal.inspect}")
  references = entries.select { |entry| entry.key?('valueFrom') }
  expected = if jev
               [{ 'name' => 'TYPESAFE_API_KEY',
                  'valueFrom' => { 'secretKeyRef' => { 'name' => JEV_SECRET, 'key' => 'api-key' } } }]
             else
               []
             end
  check(references == expected, "Secret references mismatch: #{references.inspect}")
  check(container.fetch('envFrom', []).empty?, 'envFrom is forbidden')
end

def assert_service(documents, suffix, port)
  service = resource(documents, 'Service', "lunar-base#{suffix}")
  spec = service.fetch('spec')
  check(spec['type'] == 'ClusterIP', 'service must remain ClusterIP')
  check(spec['externalIPs'] == ['192.168.21.2'], 'WireGuard-only service address mismatch')
  check(spec['selector'] == { 'app.kubernetes.io/name' => 'lunar-base' }, 'service selector mismatch')
  check(spec['ports'] == [{ 'name' => 'http', 'port' => port, 'protocol' => 'TCP', 'targetPort' => 'http' }],
        "service port must be #{port}")
  check((%w[externalName loadBalancerIP loadBalancerClass] & spec.keys).empty?,
        'public service exposure is forbidden')
end

def assert_ingress_policies(documents, suffix)
  deny = resource(documents, 'NetworkPolicy', "default-deny#{suffix}")
  check(deny.fetch('spec') == { 'podSelector' => {}, 'policyTypes' => %w[Ingress Egress] },
        'default deny mismatch')
  ingress = resource(documents, 'NetworkPolicy', "allow-game-ingress#{suffix}")
  # Index 0 is the rule Orange replaces `/from` on; it must stay the ipBlock.
  check(ingress.fetch('spec') == {
    'podSelector' => GAME_SELECTOR, 'policyTypes' => ['Ingress'],
    'ingress' => [{
      'from' => [{ 'ipBlock' => { 'cidr' => '192.168.0.0/16' } }],
      'ports' => [{ 'port' => 4780, 'protocol' => 'TCP' }],
    }],
  }, 'game ingress mismatch')
end

def egress_policies(documents)
  documents.select { |item| item['kind'] == 'NetworkPolicy' && item.fetch('spec').key?('egress') }
end

def assert_live_egress(documents)
  check(egress_policies(documents).length == 2, 'live must allow exactly DNS and HTTPS egress')
  dns = resource(documents, 'NetworkPolicy', 'allow-dns-egress')
  check(dns.fetch('spec') == {
    'podSelector' => GAME_SELECTOR, 'policyTypes' => ['Egress'],
    'egress' => [{
      'to' => [{
        'namespaceSelector' => { 'matchLabels' => { 'kubernetes.io/metadata.name' => 'kube-system' } },
        'podSelector' => { 'matchLabels' => { 'k8s-app' => 'kube-dns' } },
      }],
      'ports' => [{ 'port' => 53, 'protocol' => 'UDP' }, { 'port' => 53, 'protocol' => 'TCP' }],
    }],
  }, 'DNS egress mismatch')
  https = resource(documents, 'NetworkPolicy', 'allow-https-egress')
  check(https.fetch('spec') == {
    'podSelector' => GAME_SELECTOR, 'policyTypes' => ['Egress'],
    'egress' => [{
      'to' => [{ 'ipBlock' => {
        'cidr' => '0.0.0.0/0',
        'except' => %w[10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16],
      } }],
      'ports' => [{ 'port' => 443, 'protocol' => 'TCP' }],
    }],
  }, 'HTTPS egress must be TCP 443 to public addresses only')
end

# The promotion rewrites a literal name / newName / digest block, so an entry
# with a fourth key would render correctly and still refuse the next release.
def assert_image_entry(path)
  images = YAML.safe_load(File.read(path)).fetch('images')
  check(images.length == 1 && images.first.keys == %w[name newName digest],
        "#{path}: the image entry must carry exactly name, newName and digest")
  entry = images.first
  check(entry['name'] == IMAGE && entry['newName'] == IMAGE && entry['digest'].match?(DIGEST_SHAPE),
        "#{path}: image entry mismatch")
end

def assert_overlay(path, namespace:, suffix:, port:, jev:)
  documents = YAML.load_stream(File.read(path)).compact
  policies = %w[default-deny allow-game-ingress] + (jev ? %w[allow-dns-egress allow-https-egress] : [])
  assert_inventory(documents, namespace, suffix, policies)
  pod, container = assert_deployment(documents, suffix)
  assert_container(container)
  assert_log_volume(documents, pod, container, suffix)
  assert_environment(container, jev: jev)
  assert_service(documents, suffix, port)
  assert_ingress_policies(documents, suffix)
  if jev
    assert_live_egress(documents)
  else
    # The environment boundary: the test game has no Jev key and no way out.
    check(egress_policies(documents).empty?, 'the test overlay must allow no egress')
    rendered = File.read(path)
    check(!rendered.include?(JEV_SECRET) && !rendered.include?('TYPESAFE_API_KEY'),
          'the test overlay must not reference the Jev Secret')
    check(!rendered.include?('secretKeyRef') && !rendered.include?('secretName'),
          'the test overlay must reference no Secret')
  end
  check(!File.read(path).include?('::'), 'IPv6 exposure is forbidden')
end

live, test, live_kustomization, test_kustomization = ARGV
assert_overlay(live, namespace: 'lunar-base', suffix: '', port: 8141, jev: true)
assert_overlay(test, namespace: 'lunar-base-test', suffix: '-test', port: 8151, jev: false)
assert_image_entry(live_kustomization)
assert_image_entry(test_kustomization)
puts 'lunar-base manifest contract tests passed'
RUBY
