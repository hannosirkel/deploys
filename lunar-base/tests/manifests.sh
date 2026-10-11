#!/usr/bin/env bash
set -euo pipefail

# Renders the Lunar Base live overlay, the only one, and asserts its
# behaviour: the single-process contract, the restricted non-root container,
# the default-deny policy, the permitted egress and the Jev Secret referenced
# by name only. Refuses rather than skips when a tool or the overlay is absent,
# as the other roots' tests do.

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

# The game has one environment, live, by the operator's decision of
# 2026-10-11. Nothing below asserts anything about a second overlay, so one
# that came back would be deployable and unchecked: refuse it here.
overlays="$(find lunar-base/overlays -mindepth 1 -maxdepth 1 | sort)"
if [ "$overlays" != 'lunar-base/overlays/live' ]; then
  echo "lunar-base must have exactly one overlay, live; found: $(echo "$overlays" | tr '\n' ' ')" >&2
  exit 1
fi

overlay='lunar-base/overlays/live'
test -f "$overlay/kustomization.yaml" || {
  echo 'missing Lunar Base live overlay' >&2
  exit 1
}
kubectl kustomize "$overlay" >"$temporary/live.yaml"
test -s "$temporary/live.yaml" || {
  echo 'Lunar Base live overlay rendered nothing' >&2
  exit 1
}

ruby -ryaml - "$temporary/live.yaml" "$overlay/kustomization.yaml" <<'RUBY'
NAMESPACE = 'lunar-base'
SERVICE_PORT = 8141
POLICIES = %w[default-deny allow-game-ingress allow-dns-egress allow-https-egress].freeze
IMAGE = 'ghcr.io/plepicgames/lunar-base'
# A digest shape, not a digest value: the bootstrap sentinel and a promoted
# digest are equally valid, so a promotion never breaks this contract.
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
# Documentation ranges only (RFC 5737): unpatched, the ingress admits nobody.
DOCUMENTATION_RANGE = %r{\A(192\.0\.2|198\.51\.100|203\.0\.113)\.0/24\z}.freeze
# Every special-use IPv4 block that is not a public address.
NON_PUBLIC_RANGES = %w[
  0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
  192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24
  203.0.113.0/24 224.0.0.0/4 240.0.0.0/4
].freeze
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

def assert_inventory(documents)
  kinds = documents.map { |item| item['kind'] }.sort
  expected = (%w[Deployment PersistentVolumeClaim Service] + ['NetworkPolicy'] * POLICIES.length).sort
  # A Secret, an ExternalSecret, an HPA, a PodDisruptionBudget, a Namespace or
  # an Ingress would each show up here as an unexpected kind.
  check(kinds == expected, "unexpected resource kinds #{kinds.inspect}")
  check(documents.all? { |item| item.dig('metadata', 'namespace') == NAMESPACE },
        "a resource is outside the namespace #{NAMESPACE}")
  names = documents.select { |item| item['kind'] == 'NetworkPolicy' }.map { |item| item.dig('metadata', 'name') }
  check(names.sort == POLICIES.sort, "unexpected NetworkPolicies #{names.inspect}")
end

def assert_deployment(documents)
  deployment = resource(documents, 'Deployment', 'lunar-base')
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
  check(!pod.key?('imagePullSecrets'), 'no imagePullSecrets is expected')
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

def assert_log_volume(documents, pod, container)
  claim = resource(documents, 'PersistentVolumeClaim', 'lunar-base-games')
  check(claim.dig('spec', 'accessModes') == ['ReadWriteOnce'], 'log claim access mode mismatch')
  check(claim.dig('spec', 'resources', 'requests', 'storage') == '1Gi', 'log claim size mismatch')
  # local-path binds on first consumer: the claim shares the consumer's wave.
  check(wave(claim) == '0', 'log claim sync wave mismatch')
  check(pod['volumes'] == [{
    'name' => 'games', 'persistentVolumeClaim' => { 'claimName' => 'lunar-base-games' },
  }], 'the log claim must be the only volume')
  check(container['volumeMounts'] == [{ 'name' => 'games', 'mountPath' => LOG_DIR }],
        'the log directory must be the only mount, and writable')
end

def assert_environment(container)
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
  check(container.fetch('envFrom', []).empty?, 'envFrom is forbidden')
end

# The Jev key reaches the game by name only: one `secretKeyRef`, and nothing
# else in the rendered root that names, mounts or defines a Secret.
def assert_jev_secret(container, rendered)
  references = container.fetch('env').select { |entry| entry.key?('valueFrom') }
  check(references == [{
    'name' => 'TYPESAFE_API_KEY',
    'valueFrom' => { 'secretKeyRef' => { 'name' => JEV_SECRET, 'key' => 'api-key' } },
  }], "Secret references mismatch: #{references.inspect}")
  check(rendered.scan(JEV_SECRET).length == 1, 'the Jev Secret must be named exactly once')
  check(%w[secretRef secretName imagePullSecrets].none? { |key| rendered.include?(key) },
        'no other Secret reference is expected')
end

def assert_service(documents)
  service = resource(documents, 'Service', 'lunar-base')
  spec = service.fetch('spec')
  check(spec['type'] == 'ClusterIP', 'service must remain ClusterIP')
  check(spec['externalIPs'] == ['192.168.21.2'], 'WireGuard-only service address mismatch')
  check(spec['selector'] == { 'app.kubernetes.io/name' => 'lunar-base' }, 'service selector mismatch')
  check(spec['ports'] == [{ 'name' => 'http', 'port' => SERVICE_PORT, 'protocol' => 'TCP', 'targetPort' => 'http' }],
        "service port must be #{SERVICE_PORT}")
  check((%w[externalName loadBalancerIP loadBalancerClass] & spec.keys).empty?,
        'public service exposure is forbidden')
end

def assert_ingress_policies(documents)
  deny = resource(documents, 'NetworkPolicy', 'default-deny')
  check(deny.fetch('spec') == { 'podSelector' => {}, 'policyTypes' => %w[Ingress Egress] },
        'default deny mismatch')
  ingress = resource(documents, 'NetworkPolicy', 'allow-game-ingress')
  # Index 0 is the rule Orange replaces `/from` on; it must stay the ipBlock.
  source = ingress.dig('spec', 'ingress', 0, 'from', 0, 'ipBlock', 'cidr').to_s
  check(source.match?(DOCUMENTATION_RANGE),
        "the ingress placeholder must be a documentation range, got #{source.inspect}")
  check(ingress.fetch('spec') == {
    'podSelector' => GAME_SELECTOR, 'policyTypes' => ['Ingress'],
    'ingress' => [{
      'from' => [{ 'ipBlock' => { 'cidr' => source } }],
      'ports' => [{ 'port' => 4780, 'protocol' => 'TCP' }],
    }],
  }, 'game ingress mismatch')
end

def egress_policies(documents)
  documents.select { |item| item['kind'] == 'NetworkPolicy' && item.fetch('spec').key?('egress') }
end

def assert_egress(documents)
  check(egress_policies(documents).length == 2, 'the game must allow exactly DNS and HTTPS egress')
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
  except = https.dig('spec', 'egress', 0, 'to', 0, 'ipBlock', 'except').to_a
  check(except.sort == NON_PUBLIC_RANGES.sort,
        "HTTPS egress must exclude every non-public range; missing #{(NON_PUBLIC_RANGES - except).inspect}, " \
        "unexpected #{(except - NON_PUBLIC_RANGES).inspect}")
  check(https.fetch('spec') == {
    'podSelector' => GAME_SELECTOR, 'policyTypes' => ['Egress'],
    'egress' => [{
      'to' => [{ 'ipBlock' => { 'cidr' => '0.0.0.0/0', 'except' => except } }],
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

rendered_path, kustomization = ARGV
rendered = File.read(rendered_path)
documents = YAML.load_stream(rendered).compact
assert_inventory(documents)
pod, container = assert_deployment(documents)
assert_container(container)
assert_log_volume(documents, pod, container)
assert_environment(container)
assert_jev_secret(container, rendered)
assert_service(documents)
assert_ingress_policies(documents)
assert_egress(documents)
check(!rendered.include?('::'), 'IPv6 exposure is forbidden')
assert_image_entry(kustomization)
puts 'lunar-base manifest contract tests passed'
RUBY
