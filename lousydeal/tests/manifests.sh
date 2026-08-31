#!/usr/bin/env bash
set -euo pipefail

# Renders both Lousy Deal overlays and asserts their shape. Matches
# `plepic/tests/manifests.sh`'s discipline: refuse rather than skip when a
# tool or an overlay is absent -- a rendered-nothing run that still exits 0 is
# the failure class this build has already shipped once (see T13a's brief).
# `set -e` alone would already turn a missing `kubectl` into a non-zero exit,
# but the two guards below make the refusal legible instead of a bare
# "command not found", and prove it deliberately rather than by accident.

if ! command -v kubectl >/dev/null 2>&1; then
  echo 'kubectl is not on PATH; refusing rather than rendering nothing' >&2
  exit 1
fi

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf -- "$temporary"' EXIT

cd "$repo_root"

for environment in live test; do
  overlay="lousydeal/overlays/$environment"
  test -f "$overlay/kustomization.yaml" || {
    echo "missing Lousy Deal $environment overlay" >&2
    exit 1
  }
  kubectl kustomize "$overlay" >"$temporary/$environment.yaml"
  test -s "$temporary/$environment.yaml" || {
    echo "Lousy Deal $environment overlay rendered nothing" >&2
    exit 1
  }
done

ruby -ryaml - "$temporary/live.yaml" "$temporary/test.yaml" <<'RUBY'
# A digest *shape*, not a digest value -- see `plepic/tests/manifests.sh` for
# why: the bootstrap sentinel and a promoted digest are equally valid here, and
# an assertion pinned to the sentinel makes promotion and the contract
# mutually exclusive. T12 (`lousydeal` repository, running after this row) is
# to add `scripts/update-gitops-digest.sh`, which is to rewrite only the
# `digest:` lines this contract already requires to be well-formed.
DIGEST_SHAPE = /\Asha256:[0-9a-f]{64}\z/.freeze
SENTINEL = "sha256:#{'0' * 64}"
raise 'the all-zero bootstrap sentinel must satisfy the digest shape' unless SENTINEL.match?(DIGEST_SHAPE)

{
  SENTINEL => true,
  "sha256:#{'a' * 64}" => true,
  "sha256:#{'0' * 63}" => false,
  "sha256:#{'0' * 65}" => false,
  "sha256:#{'A' * 64}" => false,
  'latest' => false,
  '' => false,
}.each do |candidate, expected|
  actual = candidate.match?(DIGEST_SHAPE)
  raise "digest shape control failed: #{candidate.inspect} matched=#{actual}" unless actual == expected
end

def resource(documents, kind, name)
  matches = documents.select { |document| document['kind'] == kind && document.dig('metadata', 'name') == name }
  raise "expected one #{kind}/#{name}, got #{matches.length}" unless matches.length == 1
  matches.first
end

POD_TEMPLATE_PATHS = {
  'Deployment' => %w[spec template spec],
  'StatefulSet' => %w[spec template spec],
  'Job' => %w[spec template spec],
  'DaemonSet' => %w[spec template spec],
  'ReplicaSet' => %w[spec template spec],
  'ReplicationController' => %w[spec template spec],
  'CronJob' => %w[spec jobTemplate spec template spec],
  'Pod' => %w[spec],
}.freeze

def pod_spec(document)
  path = POD_TEMPLATE_PATHS[document['kind']]
  path && document.dig(*path)
end

# Every assertion about pods reaches them through pod_spec, so an unrecognised
# kind that carries a pod template must fail loudly rather than be silently
# skipped -- same reasoning as `plepic/tests/manifests.sh`'s
# `carries_pod_template?`.
def carries_pod_template?(value)
  case value
  when Hash
    return true if %w[containers initContainers ephemeralContainers].any? { |list| value[list].is_a?(Array) }
    value.each_value.any? { |nested| carries_pod_template?(nested) }
  when Array
    value.any? { |nested| carries_pod_template?(nested) }
  else
    false
  end
end

def workloads(documents)
  documents.each do |document|
    next if pod_spec(document)
    name = document.dig('metadata', 'name')
    raise "#{document['kind']}/#{name} is a pod-carrying kind whose pod spec does not resolve" if
      POD_TEMPLATE_PATHS.key?(document['kind'])
    next unless carries_pod_template?(document)
    raise "#{document['kind']}/#{name} carries a pod template that pod_spec does not resolve"
  end
  documents.select { |document| pod_spec(document) }
end

def pod_containers(pod)
  pod.fetch('containers', []) + pod.fetch('initContainers', []) + pod.fetch('ephemeralContainers', [])
end

def env_entry(container, name)
  container.fetch('env', []).find { |item| item['name'] == name }
end

def assert_pod_hardening(document)
  pod = pod_spec(document)
  raise "missing pod spec on #{document.dig('metadata', 'name')}" unless pod
  raise 'service account token must be disabled' unless pod['automountServiceAccountToken'] == false
  raise 'host namespaces are forbidden' if pod['hostNetwork'] || pod['hostPID'] || pod['hostIPC']
  raise 'pod must run non-root' unless pod.dig('securityContext', 'runAsNonRoot') == true
  raise 'RuntimeDefault seccomp is required' unless pod.dig('securityContext', 'seccompProfile', 'type') == 'RuntimeDefault'
  pod_containers(pod).each do |container|
    security = container.fetch('securityContext')
    raise 'privilege escalation is forbidden' unless security['allowPrivilegeEscalation'] == false
    raise 'all capabilities must be dropped' unless security.dig('capabilities', 'drop') == ['ALL']
    raise 'root filesystem must be read-only' unless security['readOnlyRootFilesystem'] == true
    raise 'host ports are forbidden' if container.fetch('ports', []).any? { |port| port.key?('hostPort') }
    raise "resources missing on #{container['name']}" unless
      container['resources']&.key?('requests') && container['resources']&.key?('limits')
  end
end

BACKEND_IMAGE = 'ghcr.io/hannosirkel/lousydeal-backend'.freeze
STOREFRONT_IMAGE = 'ghcr.io/hannosirkel/lousydeal-storefront'.freeze

def image_repository(reference)
  repository = reference.to_s.split('@', 2).first.to_s
  return repository unless repository.split('/').last.to_s.include?(':')
  repository[0...repository.rindex(':')]
end

# T11 measured this exact required set against `backend/src/config/runtime.ts`
# and `database-url.ts`, at module scope, on every workload that loads
# `medusa-config.ts`. The three REDIS_* parts, JWT_SECRET, COOKIE_SECRET,
# STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET are read through `requireEnv`
# directly. The five DATABASE_* parts are not: `database-url.ts` imports no
# `requireEnv` at all (`database-url.ts:115`) -- each part is read through
# `requirePart`, which wraps `optionalEnv` (`database-url.ts:135`), and all
# five are required only when `DATABASE_URL` itself is absent
# (`database-url.ts:188`). This list is still the correct assertion for these
# manifests, none of which set `DATABASE_URL`.
# STRIPE_PAYMENT_METHOD_CONFIGURATION_ID
# is deliberately not in this list -- `runtime.ts` reads it through
# `optionalEnv`, and the per-workload check below asserts its `secretKeyRef`
# carries `optional: true` instead, which this list cannot reach.
BACKEND_IMAGE_REQUIRED_ENVIRONMENT = %w[
  DATABASE_HOST DATABASE_PORT DATABASE_NAME DATABASE_USER DATABASE_PASSWORD
  REDIS_HOST REDIS_PORT REDIS_PASSWORD
  JWT_SECRET COOKIE_SECRET
  STRIPE_SECRET_KEY STRIPE_WEBHOOK_SECRET
].freeze

# Names this application's runtime does not read, so a manifest declaring one
# of them is dead configuration carried over from the reference by mistake
# rather than something this app's code consumes.
#
# `backend/src/config/runtime.ts` reads none of the three CORS variables (its
# own header: "a later row may want them required too" -- not this one), and
# no manifest here should declare `MERCHANT_*` or `SITE_*` either:
# `storefront/src/config/runtime-config.ts`'s own header states "no
# MERCHANT_* field -- no row in this slice renders an imprint," and this
# repository's storefront reads no `SITE_*` variable at all.
FORBIDDEN_ENV_NAMES = %w[
  STORE_CORS ADMIN_CORS AUTH_CORS
  SITE_BASE_URL SITE_CANONICAL_HOST SITE_TEST_HOSTNAMES
  MERCHANT_LEGAL_NAME MERCHANT_REGISTERED_ADDRESS MERCHANT_CONTACT_ADDRESS MERCHANT_RETURN_ADDRESS
  SMTP_HOST SMTP_PORT SMTP_USERNAME SMTP_PASSWORD
].freeze

def assert_manifest(path, environment:, namespace:, suffix:)
  documents = YAML.load_stream(File.read(path)).compact
  overlay = YAML.load_file("lousydeal/overlays/#{environment}/kustomization.yaml")
  raise 'overlay may source only the shared base' unless overlay['resources'] == ['../../base']
  expected_name_suffix = environment == 'test' ? '-test' : nil
  raise 'overlay name suffix mismatch' unless overlay['nameSuffix'] == expected_name_suffix
  raise 'overlay namespace mismatch' unless overlay['namespace'] == namespace
  expected_images = [BACKEND_IMAGE, STOREFRONT_IMAGE]
  raise 'overlay image names mismatch' unless overlay.fetch('images').map { |image| image['name'] }.sort == expected_images.sort
  raise 'overlay images must be pinned by digest' unless
    overlay.fetch('images').all? { |image| image['digest'].to_s.match?(DIGEST_SHAPE) }
  # T12 (`lousydeal` repository, running after this row) is to add
  # `scripts/update-gitops-digest.sh`, matching a literal three-line
  # `name`/`newName`/`digest` block per image and refusing the whole file if
  # it cannot find exactly one such block -- the same shape
  # the `plepic` (not `deploys/plepic`) repository's
  # `scripts/update-gitops-digest.sh:221-235` already matches for the
  # reference. A shape this contract cannot match is a defect this row ships,
  # per the brief.
  raise 'overlay image entries must carry only name, newName and digest' unless
    overlay.fetch('images').all? { |image| image.keys.sort == %w[digest name newName] }

  raise 'Namespace resources are owned by Orange' if documents.any? { |document| document['kind'] == 'Namespace' }
  raise 'Secret resources are forbidden in this public repository' if documents.any? { |document| document['kind'] == 'Secret' }
  raise 'Ingress is forbidden' if documents.any? { |document| document['kind'] == 'Ingress' }
  raise 'Role and RoleBinding are forbidden' if
    documents.any? { |document| %w[Role RoleBinding ClusterRole ClusterRoleBinding].include?(document['kind']) }
  raise 'resource namespace mismatch' unless documents.all? { |document| document.dig('metadata', 'namespace') == namespace }

  workloads(documents).each { |document| assert_pod_hardening(document) }

  service_account = resource(documents, 'ServiceAccount', "lousydeal-predeploy#{suffix}")
  raise 'predeploy service account must not mount a token' unless service_account['automountServiceAccountToken'] == false

  # The census: three containers run the backend image (API, worker,
  # predeploy), one runs the storefront image -- no `catalogue-import`, this
  # application has none. Counted by repository, not by name, so a container
  # naming an application image by tag rather than digest is still counted.
  images_by_repository = Hash.new(0)
  workloads(documents).each do |workload|
    pod_containers(pod_spec(workload)).each do |container|
      repository = image_repository(container.fetch('image'))
      next unless [BACKEND_IMAGE, STOREFRONT_IMAGE].include?(repository)
      images_by_repository[repository] += 1
      raise "#{container['image']} is not pinned by digest" unless container['image'].include?('@sha256:')
    end
  end
  raise 'backend-image container census mismatch' unless images_by_repository[BACKEND_IMAGE] == 3
  raise 'storefront-image container census mismatch' unless images_by_repository[STOREFRONT_IMAGE] == 1
  backend_digests = workloads(documents).flat_map do |workload|
    pod_containers(pod_spec(workload)).select { |c| image_repository(c['image']) == BACKEND_IMAGE }.map { |c| c['image'] }
  end
  raise 'every backend-image container must run the same digest' unless backend_digests.uniq.length == 1

  # Required-environment contract: every workload running the backend image
  # declares the full set T11 measured, and none of the four workloads
  # declares a name this application's code does not read.
  workloads(documents).each do |workload|
    pod_containers(pod_spec(workload)).each do |container|
      next unless image_repository(container['image']) == BACKEND_IMAGE
      names = container.fetch('env', []).map { |e| e['name'] }
      missing = BACKEND_IMAGE_REQUIRED_ENVIRONMENT - names
      raise "#{workload.dig('metadata', 'name')}/#{container['name']} missing #{missing.join(', ')}" unless missing.empty?
      forbidden = names & FORBIDDEN_ENV_NAMES
      raise "#{workload.dig('metadata', 'name')}/#{container['name']} declares unread #{forbidden.join(', ')}" unless forbidden.empty?
      pmc = env_entry(container, 'STRIPE_PAYMENT_METHOD_CONFIGURATION_ID')
      raise 'STRIPE_PAYMENT_METHOD_CONFIGURATION_ID must be declared' unless pmc
      raise 'STRIPE_PAYMENT_METHOD_CONFIGURATION_ID must be optional' unless
        pmc.dig('valueFrom', 'secretKeyRef', 'optional') == true
    end
  end
  storefront = resource(documents, 'Deployment', "lousydeal-storefront#{suffix}")
  storefront_container = pod_containers(pod_spec(storefront)).first
  storefront_names = storefront_container.fetch('env', []).map { |e| e['name'] }
  raise 'storefront env must be exactly the three names runtime-config.ts reads' unless
    storefront_names.sort == %w[MEDUSA_BACKEND_URL MEDUSA_PUBLISHABLE_API_KEY STRIPE_PUBLISHABLE_KEY].sort

  # Probes: T13b, not this row, gives the worker a readiness/liveness probe --
  # asserting its absence here is what keeps a future accidental copy from
  # this file's own backend/storefront blocks from silently landing early.
  backend = resource(documents, 'Deployment', "lousydeal-backend#{suffix}")
  backend_container = pod_containers(pod_spec(backend)).first
  raise 'backend readiness probe must target /health' unless
    backend_container.dig('readinessProbe', 'httpGet', 'path') == '/health'
  raise 'backend liveness probe must target /health' unless
    backend_container.dig('livenessProbe', 'httpGet', 'path') == '/health'
  worker = resource(documents, 'Deployment', "lousydeal-worker#{suffix}")
  worker_container = pod_containers(pod_spec(worker)).first
  raise 'the worker must carry no probe before T13b' if
    worker_container.key?('readinessProbe') || worker_container.key?('livenessProbe')
  raise 'storefront readiness probe must render the real page' unless
    storefront_container.dig('readinessProbe', 'httpGet', 'path') == '/'
  # A TCP check, not an HTTP path -- this repository ships no backend-free
  # liveness route (no `storefront/src/app/robots.ts`); see `base/storefront.yaml`.
  raise 'storefront liveness probe must be a TCP check, not an HTTP path' unless
    storefront_container.key?('livenessProbe') && storefront_container['livenessProbe'].key?('tcpSocket') &&
    !storefront_container['livenessProbe'].key?('httpGet')

  # Exposure: the one property this row's brief names as make-or-break. The
  # Medusa Admin the backend image serves on 9000 must carry no route in from
  # outside the cluster -- not a hostname, and not the reference's WireGuard
  # CIDR either.
  backend_service = resource(documents, 'Service', "lousydeal-backend#{suffix}")
  raise 'the backend Service must not carry an externalIP' if backend_service.dig('spec', 'externalIPs')
  storefront_service = resource(documents, 'Service', "lousydeal-storefront#{suffix}")
  raise 'the storefront Service must carry the WireGuard externalIP' unless
    storefront_service.dig('spec', 'externalIPs') == ['192.168.21.2']
  backend_ingress = resource(documents, 'NetworkPolicy', "allow-backend-ingress#{suffix}")
  raise 'backend ingress must admit only the storefront pod selector' unless backend_ingress.dig('spec', 'ingress') == [{
    'from' => [{ 'podSelector' => { 'matchLabels' => { 'app.kubernetes.io/component' => 'storefront' } } }],
    'ports' => [{ 'port' => 9000, 'protocol' => 'TCP' }],
  }]
  all_policies = documents.select { |document| document['kind'] == 'NetworkPolicy' }
  broad_rules = all_policies.select { |policy| policy.to_s.include?('0.0.0.0/0') }
  raise 'only named HTTPS egress may be broad' unless broad_rules.map { |p| p.dig('metadata', 'name') } == ["allow-https-egress#{suffix}"]
  https = resource(documents, 'NetworkPolicy', "allow-https-egress#{suffix}")
  raise 'HTTPS egress selector mismatch' unless https.dig('spec', 'podSelector', 'matchExpressions', 0, 'values').sort ==
    %w[backend worker backup].sort
  raise 'no SMTP egress policy belongs in this application' if all_policies.any? { |p| p.dig('metadata', 'name')&.start_with?('allow-smtp') }

  expected_policy_names = %w[
    default-deny allow-storefront-ingress allow-backend-ingress allow-postgresql-ingress allow-redis-ingress
    allow-dns-egress allow-postgresql-egress allow-redis-egress allow-storefront-backend-egress allow-https-egress
  ].map { |name| "#{name}#{suffix}" }.sort
  raise 'NetworkPolicy set mismatch' unless all_policies.map { |p| p.dig('metadata', 'name') }.sort == expected_policy_names

  # The predeploy Job's ten `module-migrations` mounts -- measured directly
  # against the built image under `--read-only --user 10001:10001`; see
  # `base/predeploy-job.yaml` for the full account.
  migration_paths = %w[
    payment-stripe auth-emailpass fulfillment-manual notification-local cache-inmemory
    event-bus-redis locking locking-redis file file-local
  ].map { |name| "/node_modules/@medusajs/#{name}/dist/migrations" }
  predeploy = resource(documents, 'Job', "lousydeal-predeploy#{suffix}")
  expected_hook = {
    'argocd.argoproj.io/hook' => 'Sync',
    'argocd.argoproj.io/hook-delete-policy' => 'BeforeHookCreation,HookSucceeded',
    'argocd.argoproj.io/sync-wave' => '-10',
  }
  raise 'migration Sync-hook gate mismatch' unless predeploy.dig('metadata', 'annotations') == expected_hook
  predeploy_container = pod_containers(pod_spec(predeploy)).first
  predeploy_mount_paths = predeploy_container.fetch('volumeMounts', []).map { |m| m['mountPath'] }
  raise 'predeploy module-migrations mount set mismatch' unless
    (migration_paths - predeploy_mount_paths).empty? && (predeploy_mount_paths & migration_paths).length == migration_paths.length
  raise 'predeploy migration mounts must be read-only' unless
    predeploy_container.fetch('volumeMounts', []).select { |m| migration_paths.include?(m['mountPath']) }.all? { |m| m['readOnly'] == true }
  other_workloads = workloads(documents).reject { |w| w.equal?(predeploy) }
  raise 'the module-migrations mounts must reach only the predeploy Job' if other_workloads.any? do |workload|
    pod_containers(pod_spec(workload)).any? { |c| c.fetch('volumeMounts', []).any? { |m| migration_paths.include?(m['mountPath']) } }
  end

  # PostgreSQL: decision 003, an own StatefulSet per environment. `nameSuffix`
  # gives the test one its `-test` name; this asserts the base and the digest
  # census never named a shared server by mistake.
  postgresql = resource(documents, 'StatefulSet', "lousydeal-postgresql#{suffix}")
  raise 'PostgreSQL StatefulSet must run exactly one replica' unless postgresql.dig('spec', 'replicas') == 1
end

live = YAML.load_stream(File.read(ARGV[0])).compact
test_environment = YAML.load_stream(File.read(ARGV[1])).compact
assert_manifest(ARGV[0], environment: 'live', namespace: 'lousydeal', suffix: '')
assert_manifest(ARGV[1], environment: 'test', namespace: 'lousydeal-test', suffix: '-test')

# Cross-overlay: live and test must not collide on the one shared WireGuard
# address, and neither backend Service anywhere carries one at all.
live_storefront = live.find { |d| d['kind'] == 'Service' && d.dig('metadata', 'name') == 'lousydeal-storefront' }
test_storefront = test_environment.find { |d| d['kind'] == 'Service' && d.dig('metadata', 'name') == 'lousydeal-storefront-test' }
live_port = live_storefront.dig('spec', 'ports', 0, 'port')
test_port = test_storefront.dig('spec', 'ports', 0, 'port')
raise 'live and test storefront WireGuard ports must differ' if live_port == test_port

puts 'lousydeal/tests/manifests.sh: all assertions passed'
RUBY
