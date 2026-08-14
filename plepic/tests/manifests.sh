#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf -- "$temporary"' EXIT

cd "$repo_root"

for environment in live test; do
  overlay="plepic/overlays/$environment"
  test -f "$overlay/kustomization.yaml" || {
    echo "missing Plepic $environment overlay" >&2
    exit 1
  }
  kubectl kustomize "$overlay" >"$temporary/$environment.yaml"
done

ruby -ryaml - "$temporary/live.yaml" "$temporary/test.yaml" <<'RUBY'
SENTINEL = "sha256:#{'0' * 64}"

def resource(documents, kind, name)
  matches = documents.select do |document|
    document['kind'] == kind && document.dig('metadata', 'name') == name
  end
  raise "expected one #{kind}/#{name}, got #{matches.length}" unless matches.length == 1
  matches.first
end

def pod_spec(document)
  case document['kind']
  when 'Deployment', 'StatefulSet', 'Job', 'DaemonSet', 'ReplicaSet', 'ReplicationController'
    document.dig('spec', 'template', 'spec')
  when 'CronJob'
    document.dig('spec', 'jobTemplate', 'spec', 'template', 'spec')
  when 'Pod'
    document['spec']
  end
end

# Every assertion about pods reaches them through pod_spec, so a kind it does
# not recognise is not merely unchecked — it is invisible to pod hardening, to
# the Secret-reference contract, to the superuser boundary and to the assets
# writer set at once. Recognising more kinds is therefore not enough; an
# unrecognised kind that carries a pod template must fail loudly, so this set
# can never silently fall behind what the overlays render.
def carries_pod_template?(value)
  case value
  when Hash
    # The same three lists pod_containers reads. A detector that tested fewer
    # would let a template hide in the one the traversal still walks.
    return true if %w[containers initContainers ephemeralContainers]
      .any? { |list| value[list].is_a?(Array) }
    value.each_value.any? { |nested| carries_pod_template?(nested) }
  when Array
    value.any? { |nested| carries_pod_template?(nested) }
  else
    false
  end
end

def env_value(container, name)
  entry = container.fetch('env', []).find { |item| item['name'] == name }
  raise "missing #{name} on #{container['name']}" unless entry
  entry['value']
end

# Absence is a legitimate answer when the assertion is about *which* workloads
# carry a variable rather than what its value is. Unlike env_value this never
# raises, so a caller can prove a variable is scoped to one workload without
# dying on the first workload that correctly lacks it.
def env_entry(container, name)
  container.fetch('env', []).find { |item| item['name'] == name }
end

def optional_env_value(container, name)
  entry = env_entry(container, name)
  entry && entry['value']
end

# Presence, not truthiness. A variable delivered by reference — configMapKeyRef,
# fieldRef, a bare name — has no literal value, so a guard written on the value
# would silently drop the workload carrying it and report the variable absent.
def env_present?(containers, name)
  containers.any? { |container| env_entry(container, name) }
end

# Every workload in the document set, not a hand-listed subset. An assertion
# that a variable lives on exactly one workload is only as strong as the set it
# searches, and the storefront is a more plausible wrong home for a form rate
# limit than any of the database workloads.
def workloads(documents)
  documents.each do |document|
    next if pod_spec(document)
    next unless carries_pod_template?(document)
    raise "#{document['kind']}/#{document.dig('metadata', 'name')} carries a pod " \
          'template that pod_spec does not resolve'
  end
  documents.select { |document| pod_spec(document) }
end

# initContainers run with the same Secret access, the same volumes and the same
# privileges as the containers beside them, so an assertion that skips them
# checks half the pod. ephemeralContainers are included for the same reason:
# nothing here should be able to arrive through a debug surface either.
def pod_containers(pod)
  pod.fetch('containers', []) +
    pod.fetch('initContainers', []) +
    pod.fetch('ephemeralContainers', [])
end

ADDRESS_SHAPE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.freeze

# RFC 2606 and RFC 6761 reserve these names precisely so documentation and
# placeholders can use them. A reserved name can never be a real account, so an
# address at one carries no identity and is not what this boundary forbids. The
# real per-environment addresses are injected from Orange and never rendered
# here. Everything outside this set is still refused.
RESERVED_EXAMPLE_DOMAINS = %w[example.com example.org example.net].freeze
RESERVED_SUFFIX_LABELS = %w[invalid test example localhost].freeze

def build_reserved_address(example_domains, suffix_labels)
  /
    \A[A-Za-z0-9._%+-]+@
    (?:[A-Za-z0-9-]+\.)*
    (?:#{(example_domains + suffix_labels).map { |name| Regexp.escape(name) }.join('|')})
    \z
  /xi
end

RESERVED_ADDRESS = build_reserved_address(RESERVED_EXAMPLE_DOMAINS, RESERVED_SUFFIX_LABELS).freeze

# Structural control on the exemption itself, not on samples of it. The sample
# list below proves the boundary still fires for whole shape classes, but no
# finite sample can notice one specific real domain being quietly added — which
# is the widening a later reader under pressure is most likely to attempt.
#
# Both halves are needed. Pinning the declarations alone still allowed an
# alternative to be added straight to the pattern, leaving the lists untouched
# and the suite green; so the pattern is also required to be exactly what those
# declarations generate. Regexp equality compares source and options, so the two
# cannot drift apart.
raise 'the reserved-name exemption changed without its declaration being updated' unless
  RESERVED_EXAMPLE_DOMAINS == %w[example.com example.org example.net] &&
  RESERVED_SUFFIX_LABELS == %w[invalid test example localhost]
raise 'the reserved-name pattern does not match the set it claims to encode' unless
  RESERVED_ADDRESS == build_reserved_address(RESERVED_EXAMPLE_DOMAINS, RESERVED_SUFFIX_LABELS)

def public_account_addresses(text)
  text.scan(ADDRESS_SHAPE).reject { |address| RESERVED_ADDRESS.match?(address) }.uniq
end

# Positive control. A boundary that never fires is indistinguishable from one
# that is broken, and this one was widened deliberately — so prove on every run
# that it still refuses a non-reserved address before trusting it to pass.
# The forbidden samples use invented domains so this file carries no real
# identity of its own.
[
  ['orders@merchant-domain.com', true],
  ['person@some-company.co.uk', true],
  ['billing@example.com.attacker.net', true],
  ['orders@example.com', false],
  ['orders-test@example.com', false],
  ['legal@mail.example.org', false],
  ['relay@smtp.invalid', false],
  ['probe@host.test', false],
].each do |address, expected_forbidden|
  actual_forbidden = !public_account_addresses(address).empty?
  next if actual_forbidden == expected_forbidden
  raise "address boundary control failed: #{address.split('@').first}@… " \
        "expected forbidden=#{expected_forbidden}, got #{actual_forbidden}"
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
    raise "resources missing on #{container['name']}" unless container['resources']&.key?('requests') && container['resources']&.key?('limits')
  end
end

def assert_network_contract(documents, suffix)
  expected_policy_names = %w[
    default-deny
    allow-storefront-ingress
    allow-backend-ingress
    allow-postgresql-ingress
    allow-redis-ingress
    allow-dns-egress
    allow-postgresql-egress
    allow-redis-egress
    allow-storefront-backend-egress
    allow-smtp-submission-egress
    allow-https-egress
  ].map { |name| "#{name}#{suffix}" }.sort
  actual_policy_names = documents.select { |document| document['kind'] == 'NetworkPolicy' }
    .map { |document| document.dig('metadata', 'name') }.sort
  raise 'NetworkPolicy set mismatch' unless actual_policy_names == expected_policy_names

  deny = resource(documents, 'NetworkPolicy', "default-deny#{suffix}")
  raise 'default deny selector mismatch' unless deny.dig('spec', 'podSelector') == {}
  raise 'default deny policy types mismatch' unless deny.dig('spec', 'policyTypes').sort == %w[Egress Ingress]

  storefront_ingress = resource(documents, 'NetworkPolicy', "allow-storefront-ingress#{suffix}")
  raise 'storefront ingress policy type mismatch' unless storefront_ingress.dig('spec', 'policyTypes') == ['Ingress']
  raise 'storefront ingress selector mismatch' unless storefront_ingress.dig('spec', 'podSelector', 'matchLabels') == {
    'app.kubernetes.io/component' => 'storefront',
  }
  raise 'storefront ingress contract mismatch' unless storefront_ingress.dig('spec', 'ingress') == [{
    'from' => [{ 'ipBlock' => { 'cidr' => '192.168.0.0/16' } }],
    'ports' => [{ 'port' => 3000, 'protocol' => 'TCP' }],
  }]

  backend_ingress = resource(documents, 'NetworkPolicy', "allow-backend-ingress#{suffix}")
  raise 'backend ingress policy type mismatch' unless backend_ingress.dig('spec', 'policyTypes') == ['Ingress']
  raise 'backend ingress selector mismatch' unless backend_ingress.dig('spec', 'podSelector', 'matchLabels') == {
    'app.kubernetes.io/component' => 'backend',
  }
  raise 'backend ingress contract mismatch' unless backend_ingress.dig('spec', 'ingress') == [
    {
      'from' => [{ 'ipBlock' => { 'cidr' => '192.168.0.0/16' } }],
      'ports' => [{ 'port' => 9000, 'protocol' => 'TCP' }],
    },
    {
      'from' => [{ 'podSelector' => { 'matchLabels' => {
        'app.kubernetes.io/component' => 'storefront',
      } } }],
      'ports' => [{ 'port' => 9000, 'protocol' => 'TCP' }],
    },
  ]

  postgresql = resource(documents, 'NetworkPolicy', "allow-postgresql-ingress#{suffix}")
  raise 'PostgreSQL ingress policy type mismatch' unless postgresql.dig('spec', 'policyTypes') == ['Ingress']
  raise 'PostgreSQL ingress selector mismatch' unless postgresql.dig('spec', 'podSelector', 'matchLabels') == {
    'app.kubernetes.io/component' => 'postgresql',
  }
  raise 'PostgreSQL ingress mismatch' unless postgresql.dig('spec', 'ingress') == [{
    'from' => %w[backend worker predeploy catalogue-import backup recovery].map do |component|
      { 'podSelector' => { 'matchLabels' => { 'app.kubernetes.io/component' => component } } }
    end,
    'ports' => [{ 'port' => 5432, 'protocol' => 'TCP' }],
  }]

  redis = resource(documents, 'NetworkPolicy', "allow-redis-ingress#{suffix}")
  raise 'Redis ingress policy type mismatch' unless redis.dig('spec', 'policyTypes') == ['Ingress']
  raise 'Redis ingress selector mismatch' unless redis.dig('spec', 'podSelector', 'matchLabels') == {
    'app.kubernetes.io/component' => 'redis',
  }
  raise 'Redis ingress mismatch' unless redis.dig('spec', 'ingress') == [{
    'from' => %w[backend worker].map do |component|
      { 'podSelector' => { 'matchLabels' => { 'app.kubernetes.io/component' => component } } }
    end,
    'ports' => [{ 'port' => 6379, 'protocol' => 'TCP' }],
  }]

  dns = resource(documents, 'NetworkPolicy', "allow-dns-egress#{suffix}")
  raise 'DNS egress policy type mismatch' unless dns.dig('spec', 'policyTypes') == ['Egress']
  raise 'DNS egress must select all pods' unless dns.dig('spec', 'podSelector') == {}
  raise 'DNS egress mismatch' unless dns.dig('spec', 'egress') == [{
    'to' => [{
      'namespaceSelector' => { 'matchLabels' => { 'kubernetes.io/metadata.name' => 'kube-system' } },
      'podSelector' => { 'matchLabels' => { 'k8s-app' => 'kube-dns' } },
    }],
    'ports' => [{ 'port' => 53, 'protocol' => 'UDP' }, { 'port' => 53, 'protocol' => 'TCP' }],
  }]

  postgresql_egress = resource(documents, 'NetworkPolicy', "allow-postgresql-egress#{suffix}")
  raise 'PostgreSQL egress policy type mismatch' unless postgresql_egress.dig('spec', 'policyTypes') == ['Egress']
  raise 'PostgreSQL egress selector mismatch' unless postgresql_egress.dig('spec', 'podSelector') == {
    'matchExpressions' => [{
      'key' => 'app.kubernetes.io/component',
      'operator' => 'In',
      'values' => %w[backend worker predeploy catalogue-import backup recovery],
    }],
  }
  raise 'PostgreSQL egress mismatch' unless postgresql_egress.dig('spec', 'egress') == [{
    'to' => [{ 'podSelector' => { 'matchLabels' => { 'app.kubernetes.io/component' => 'postgresql' } } }],
    'ports' => [{ 'port' => 5432, 'protocol' => 'TCP' }],
  }]

  redis_egress = resource(documents, 'NetworkPolicy', "allow-redis-egress#{suffix}")
  raise 'Redis egress policy type mismatch' unless redis_egress.dig('spec', 'policyTypes') == ['Egress']
  raise 'Redis egress selector mismatch' unless redis_egress.dig('spec', 'podSelector') == {
    'matchExpressions' => [{
      'key' => 'app.kubernetes.io/component',
      'operator' => 'In',
      'values' => %w[backend worker],
    }],
  }
  raise 'Redis egress mismatch' unless redis_egress.dig('spec', 'egress') == [{
    'to' => [{ 'podSelector' => { 'matchLabels' => { 'app.kubernetes.io/component' => 'redis' } } }],
    'ports' => [{ 'port' => 6379, 'protocol' => 'TCP' }],
  }]

  storefront_egress = resource(documents, 'NetworkPolicy', "allow-storefront-backend-egress#{suffix}")
  raise 'storefront egress policy type mismatch' unless storefront_egress.dig('spec', 'policyTypes') == ['Egress']
  raise 'storefront egress selector mismatch' unless storefront_egress.dig('spec', 'podSelector', 'matchLabels') == {
    'app.kubernetes.io/component' => 'storefront',
  }
  raise 'storefront-to-backend egress mismatch' unless storefront_egress.dig('spec', 'egress') == [{
    'to' => [{ 'podSelector' => { 'matchLabels' => { 'app.kubernetes.io/component' => 'backend' } } }],
    'ports' => [{ 'port' => 9000, 'protocol' => 'TCP' }],
  }]

  smtp = resource(documents, 'NetworkPolicy', "allow-smtp-submission-egress#{suffix}")
  raise 'SMTP egress policy type mismatch' unless smtp.dig('spec', 'policyTypes') == ['Egress']
  raise 'SMTP workload selector mismatch' unless smtp.dig('spec', 'podSelector') == {
    'matchExpressions' => [{
      'key' => 'app.kubernetes.io/component',
      'operator' => 'In',
      'values' => %w[backend worker],
    }],
  }
  smtp_cidr = smtp.dig('spec', 'egress', 0, 'to', 0, 'ipBlock', 'cidr')
  raise 'SMTP patch seam must be a private /32' unless smtp_cidr&.match?(%r{\A(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d+\.\d+/32\z})
  raise 'SMTP submission egress mismatch' unless smtp.dig('spec', 'egress') == [{
    'to' => [{ 'ipBlock' => { 'cidr' => smtp_cidr } }],
    'ports' => [{ 'port' => 587, 'protocol' => 'TCP' }],
  }]

  https = resource(documents, 'NetworkPolicy', "allow-https-egress#{suffix}")
  raise 'HTTPS egress policy type mismatch' unless https.dig('spec', 'policyTypes') == ['Egress']
  raise 'HTTPS workload selector mismatch' unless https.dig('spec', 'podSelector') == {
    'matchExpressions' => [{
      'key' => 'app.kubernetes.io/component',
      'operator' => 'In',
      'values' => %w[backend worker storefront predeploy catalogue-import],
    }],
  }
  raise 'HTTPS broad egress mismatch' unless https.dig('spec', 'egress') == [{
    'to' => [{ 'ipBlock' => { 'cidr' => '0.0.0.0/0' } }],
    'ports' => [{ 'port' => 443, 'protocol' => 'TCP' }],
  }]

  all_policies = documents.select { |document| document['kind'] == 'NetworkPolicy' }
  broad_rules = all_policies.select { |policy| policy.to_s.include?('0.0.0.0/0') }
  raise 'only named HTTPS egress may be broad' unless broad_rules.map { |policy| policy.dig('metadata', 'name') } == ["allow-https-egress#{suffix}"]
  allowed_ports = all_policies.flat_map do |policy|
    policy.fetch('spec').fetch('egress', []).flat_map { |rule| rule.fetch('ports', []).map { |port| port['port'] } }
  end
  raise 'TCP 25 must not be allowed' if allowed_ports.include?(25)
end

def assert_manifest(path, environment:, namespace:, suffix:, ports:, database:, secrets:, pvc_sizes:, resources:)
  documents = YAML.load_stream(File.read(path)).compact
  overlay = YAML.load_file("plepic/overlays/#{environment}/kustomization.yaml")
  raise 'overlay may source only the shared base' unless overlay['resources'] == ['../../base']
  expected_name_suffix = environment == 'test' ? '-test' : nil
  raise 'overlay name suffix mismatch' unless overlay['nameSuffix'] == expected_name_suffix
  raise 'overlay namespace mismatch' unless overlay['namespace'] == namespace
  expected_images = %w[ghcr.io/hannosirkel/plepic-backend ghcr.io/hannosirkel/plepic-storefront]
  raise 'overlay image names mismatch' unless overlay.fetch('images').map { |image| image['name'] }.sort == expected_images.sort
  raise 'overlay must retain both Task 4 sentinels' unless overlay.fetch('images').all? { |image| image['digest'] == SENTINEL }
  raise 'Namespace resources are owned by Orange' if documents.any? { |document| document['kind'] == 'Namespace' }
  raise 'Ingress is forbidden' if documents.any? { |document| document['kind'] == 'Ingress' }
  raise 'Role and RoleBinding are forbidden' if documents.any? { |document| %w[Role RoleBinding ClusterRole ClusterRoleBinding].include?(document['kind']) }
  raise 'resource namespace mismatch' unless documents.all? { |document| document.dig('metadata', 'namespace') == namespace }

  # Driven from the resolution set, never from a kind literal. A hardcoded list
  # here is how the hardening set silently diverged from what pod_spec resolves,
  # leaving a privileged DaemonSet or CronJob recognised everywhere except the
  # one assertion that would have refused it.
  workloads(documents).each { |document| assert_pod_hardening(document) }

  service_account = resource(documents, 'ServiceAccount', "plepic-predeploy#{suffix}")
  raise 'predeploy service account must not mount a token' unless service_account['automountServiceAccountToken'] == false

  predeploy = resource(documents, 'Job', "plepic-predeploy#{suffix}")
  expected_hook = {
    'argocd.argoproj.io/hook' => 'Sync',
    'argocd.argoproj.io/hook-delete-policy' => 'BeforeHookCreation,HookSucceeded',
    'argocd.argoproj.io/sync-wave' => '-10',
  }
  raise 'migration Sync-hook gate mismatch' unless predeploy.dig('metadata', 'annotations') == expected_hook
  raise 'predeploy token exception must not return' unless pod_spec(predeploy)['automountServiceAccountToken'] == false

  import = resource(documents, 'Job', "plepic-catalogue-import#{suffix}")
  raise 'catalogue import must stay suspended' unless import.dig('spec', 'suspend') == true
  raise 'catalogue import annotations mismatch' unless import.dig('metadata', 'annotations') == {
    'argocd.argoproj.io/sync-wave' => '0',
    'argocd.argoproj.io/ignore-healthcheck' => 'true',
    'argocd.argoproj.io/sync-options' => 'Force=true,Replace=true',
  }

  wave_minus_twenty = documents.select do |document|
    document.dig('metadata', 'annotations', 'argocd.argoproj.io/sync-wave') == '-20'
  end
  raise 'data/support resources must be wave -20' unless wave_minus_twenty.any? { |document| document['kind'] == 'StatefulSet' }
  documents.each do |document|
    name = document.dig('metadata', 'name')
    expected_wave = if document.equal?(predeploy)
      '-10'
    elsif document.equal?(import) || document['kind'] == 'Deployment' ||
          (document['kind'] == 'Service' && ["plepic-backend#{suffix}", "plepic-storefront#{suffix}"].include?(name))
      '0'
    else
      '-20'
    end
    raise "#{document['kind']}/#{name} Sync wave mismatch" unless
      document.dig('metadata', 'annotations', 'argocd.argoproj.io/sync-wave') == expected_wave
    if document != predeploy && document.dig('metadata', 'annotations')&.key?('argocd.argoproj.io/hook')
      raise "only the migration Job may be an Argo hook"
    end
  end

  expected_service_names = %w[postgresql redis backend storefront].map { |component| "plepic-#{component}#{suffix}" }.sort
  actual_services = documents.select { |document| document['kind'] == 'Service' }
  raise 'Service set mismatch' unless actual_services.map { |service| service.dig('metadata', 'name') }.sort == expected_service_names
  actual_services.each do |service|
    raise 'every Service must be ClusterIP' unless service.dig('spec', 'type') == 'ClusterIP'
    raise 'NodePort field is forbidden' if service.dig('spec', 'ports').any? { |port| port.key?('nodePort') }
    forbidden_service_keys = %w[externalName loadBalancerIP loadBalancerClass]
    raise 'forbidden Service exposure field' if forbidden_service_keys.any? { |key| service.fetch('spec').key?(key) }
  end

  externally_reachable = %w[storefront backend].to_h do |component|
    service = resource(documents, 'Service', "plepic-#{component}#{suffix}")
    raise 'WireGuard externalIP mismatch' unless service.dig('spec', 'externalIPs') == ['192.168.21.2']
    port = ports.fetch(component)
    raise 'external Service port contract mismatch' unless service.dig('spec', 'ports') == [{
      'name' => 'http', 'port' => port, 'protocol' => 'TCP', 'targetPort' => 'http',
    }]
    [component, port]
  end
  raise 'external service port mismatch' unless externally_reachable == ports
  %w[postgresql redis].each do |component|
    service = resource(documents, 'Service', "plepic-#{component}#{suffix}")
    raise 'data service externalIP is forbidden' if service.fetch('spec').key?('externalIPs')
    port = component == 'postgresql' ? 5432 : 6379
    raise 'data Service port contract mismatch' unless service.dig('spec', 'ports') == [{
      'name' => component, 'port' => port, 'protocol' => 'TCP', 'targetPort' => component,
    }]
  end

  postgresql = resource(documents, 'StatefulSet', "plepic-postgresql#{suffix}")
  redis = resource(documents, 'StatefulSet', "plepic-redis#{suffix}")
  postgresql_init = resource(documents, 'ConfigMap', "plepic-postgresql-init#{suffix}")
    .dig('data', '10-medusa-owner.sh')
  raise 'application role must own the database' unless postgresql_init.include?('CREATE DATABASE %I OWNER %I')
  raise 'application-role default privileges are required' unless postgresql_init.include?('ALTER DEFAULT PRIVILEGES FOR ROLE %I')
  redis_config = resource(documents, 'ConfigMap', "plepic-redis-config#{suffix}").dig('data', 'redis.conf')
  raise 'Redis AOF contract mismatch' unless redis_config.include?("appendonly yes\n") && redis_config.include?("appendfsync everysec\n")
  raise 'Redis ACL file is required' unless redis_config.include?('aclfile /run/redis/users.acl')
  redis_args = pod_spec(redis).dig('containers', 0, 'args').join("\n")
  raise 'Redis dangerous commands must be denied by ACL' unless redis_args.include?('-@dangerous')
  raise 'deprecated Redis rename-command is forbidden' if redis_config.include?('rename-command') || redis_args.include?('rename-command')
  postgresql_image = pod_spec(postgresql).dig('containers', 0, 'image')
  redis_image = pod_spec(redis).dig('containers', 0, 'image')
  raise 'PostgreSQL must be digest pinned' unless postgresql_image&.match?(%r{\Apostgres:[^@]+@sha256:[0-9a-f]{64}\z})
  raise 'Redis must be digest pinned' unless redis_image&.match?(%r{\Aredis:[^@]+@sha256:[0-9a-f]{64}\z})

  application_images = documents.flat_map do |document|
    (pod = pod_spec(document)) ? pod_containers(pod).map { |container| container['image'] } : []
  end.select { |image| image&.start_with?('ghcr.io/hannosirkel/plepic-') }
  raise 'Task 4 backend image sentinel mismatch' unless application_images.count("ghcr.io/hannosirkel/plepic-backend@#{SENTINEL}") == 4
  raise 'Task 4 storefront image sentinel mismatch' unless application_images.count("ghcr.io/hannosirkel/plepic-storefront@#{SENTINEL}") == 1

  pvc_sizes.each do |name, size|
    pvc = resource(documents, 'PersistentVolumeClaim', "plepic-#{name}#{suffix}")
    raise "#{name} PVC size mismatch" unless pvc.dig('spec', 'resources', 'requests', 'storage') == size
  end

  resources.each do |component, expected|
    kind = %w[postgresql redis].include?(component) ? 'StatefulSet' : (component == 'predeploy' || component == 'catalogue-import' ? 'Job' : 'Deployment')
    workload = resource(documents, kind, "plepic-#{component}#{suffix}")
    actual = pod_spec(workload).dig('containers', 0, 'resources')
    raise "#{component} resource contract mismatch" unless actual == expected
  end

  database_workloads = %w[backend worker predeploy catalogue-import].map do |component|
    kind = %w[predeploy catalogue-import].include?(component) ? 'Job' : 'Deployment'
    resource(documents, kind, "plepic-#{component}#{suffix}")
  end
  merchant_environment = if environment == 'test'
    {
      'MERCHANT_LEGAL_NAME' => 'Example Test Games OÜ',
      'MERCHANT_REGISTERED_ADDRESS' => 'Test Street 1, Tallinn',
      'MERCHANT_CONTACT_ADDRESS' => 'legal-test@example.com',
      'MERCHANT_RETURN_ADDRESS' => 'Test Return Street 2, Tallinn',
    }
  else
    {
      'MERCHANT_LEGAL_NAME' => 'Example Games OÜ',
      'MERCHANT_REGISTERED_ADDRESS' => 'Example Street 1, Tallinn',
      'MERCHANT_CONTACT_ADDRESS' => 'legal@example.com',
      'MERCHANT_RETURN_ADDRESS' => 'Return Street 2, Tallinn',
    }
  end
  database_workloads.each do |workload|
    container = pod_spec(workload).dig('containers', 0)
    raise 'database name mismatch' unless env_value(container, 'DATABASE_NAME') == database
    raise 'migrations and workloads must use the application role' unless env_value(container, 'DATABASE_USER') == 'medusa'
    stripe_refs = container.fetch('env', []).filter_map do |entry|
      next unless %w[STRIPE_SECRET_KEY STRIPE_WEBHOOK_SECRET STRIPE_PAYMENT_METHOD_CONFIGURATION_ID].include?(entry['name'])
      reference = entry.dig('valueFrom', 'secretKeyRef')
      [entry['name'], reference&.fetch('name'), reference&.fetch('key')]
    end
    runtime_secret = environment == 'test' ? 'plepic-test-runtime-credentials' : 'plepic-runtime-credentials'
    expected_stripe_refs = %w[STRIPE_PAYMENT_METHOD_CONFIGURATION_ID STRIPE_SECRET_KEY STRIPE_WEBHOOK_SECRET].map do |key|
      [key, runtime_secret, key]
    end
    raise 'backend-family Stripe runtime contract mismatch' unless stripe_refs.sort == expected_stripe_refs.sort
    mail_refs = container.fetch('env', []).filter_map do |entry|
      next unless %w[SMTP_PASSWORD SMTP_USERNAME TURNSTILE_SECRET_KEY].include?(entry['name'])
      reference = entry.dig('valueFrom', 'secretKeyRef')
      [entry['name'], reference&.fetch('name'), reference&.fetch('key')]
    end
    expected_mail_refs = %w[SMTP_PASSWORD SMTP_USERNAME TURNSTILE_SECRET_KEY].map do |key|
      [key, runtime_secret, key]
    end
    raise 'backend-family mail secret contract mismatch' unless mail_refs.sort == expected_mail_refs.sort
    raise 'backend-family SMTP port must be submission 587' unless env_value(container, 'SMTP_PORT') == '587'
    raise 'backend-family SMTP host must remain deployment-supplied' unless env_value(container, 'SMTP_HOST')&.end_with?('.invalid')
    raise 'backend-family envelope sender must be synthetic' unless env_value(container, 'SMTP_ENVELOPE_FROM')&.end_with?('@example.com')
    raise 'backend-family contact recipient must be synthetic' unless env_value(container, 'CONTACT_MAIL_RECIPIENT')&.end_with?('@example.com')
    actual_merchant_environment = merchant_environment.keys.to_h do |name|
      [name, env_value(container, name)]
    end
    raise 'backend-family merchant legal contract mismatch' unless actual_merchant_environment == merchant_environment
  end
  newsletter_keys = %w[NEWSLETTER_API_KEY NEWSLETTER_LIST_ID]
  newsletter_consumers = workloads(documents).filter_map do |workload|
    containers = pod_containers(pod_spec(workload))
    keys = containers.flat_map { |container| container.fetch('env', []) }.filter_map do |entry|
      entry['name'] if newsletter_keys.include?(entry['name'])
    end.uniq.sort
    [workload.dig('metadata', 'name'), keys] unless keys.empty?
  end.to_h
  raise 'newsletter credentials must be projected only to the backend' unless newsletter_consumers == {
    "plepic-backend#{suffix}" => newsletter_keys.sort,
  }
  newsletter_limit_keys = %w[NEWSLETTER_RATE_LIMIT_MAX NEWSLETTER_RATE_LIMIT_WINDOW_SECONDS]
  newsletter_limit_environment = workloads(documents).filter_map do |workload|
    containers = pod_containers(pod_spec(workload))
    next unless newsletter_limit_keys.any? { |name| env_present?(containers, name) }
    values = newsletter_limit_keys.to_h do |name|
      # Read from whichever container carries the entry, not from container 0.
      # Reading the first container would let a sidecar on the backend declare a
      # conflicting limit invisibly, because container 0 already supplies the
      # expected value and the comparison below would never see the difference.
      declared = containers.filter_map { |container| env_entry(container, name) }
        .map { |entry| entry['value'] }.uniq
      raise "#{workload.dig('metadata', 'name')} declares conflicting #{name} across containers" if
        declared.length > 1
      [name, declared.first]
    end
    [workload.dig('metadata', 'name'), values]
  end.to_h
  raise 'newsletter rate limit must be a backend-only explicit deployment contract' unless newsletter_limit_environment == {
    "plepic-backend#{suffix}" => {
      'NEWSLETTER_RATE_LIMIT_MAX' => '20',
      'NEWSLETTER_RATE_LIMIT_WINDOW_SECONDS' => '600',
    },
  }
  pg_container = pod_spec(postgresql).dig('containers', 0)
  raise 'PostgreSQL application database mismatch' unless env_value(pg_container, 'POSTGRES_APPLICATION_DATABASE') == database

  service_ports = actual_services.to_h do |service|
    [service.dig('metadata', 'name'), service.dig('spec', 'ports', 0, 'port').to_s]
  end
  endpoint_workloads = {
    "plepic-backend#{suffix}" => %w[DATABASE REDIS],
    "plepic-worker#{suffix}" => %w[DATABASE REDIS],
    "plepic-predeploy#{suffix}" => %w[DATABASE],
    "plepic-catalogue-import#{suffix}" => %w[DATABASE],
  }
  endpoint_workloads.each do |name, endpoint_types|
    kind = name.include?('predeploy') || name.include?('catalogue-import') ? 'Job' : 'Deployment'
    workload_environment = pod_spec(resource(documents, kind, name)).dig('containers', 0, 'env').to_h do |entry|
      [entry['name'], entry['value']]
    end
    endpoint_types.each do |endpoint_type|
      host = workload_environment.fetch("#{endpoint_type}_HOST")
      port = workload_environment.fetch("#{endpoint_type}_PORT")
      raise "#{name} has dangling #{endpoint_type} Service endpoint" unless service_ports[host] == port
    end
  end
  storefront_environment = pod_spec(resource(documents, 'Deployment', "plepic-storefront#{suffix}"))
    .dig('containers', 0, 'env').to_h { |entry| [entry['name'], entry['value']] }
  raise 'storefront and backend merchant legal contracts differ' unless
    storefront_environment.slice(*merchant_environment.keys) == merchant_environment
  backend_url = URI(storefront_environment.fetch('MEDUSA_BACKEND_URL'))
  raise 'storefront has dangling backend Service endpoint' unless
    backend_url.scheme == 'http' && service_ports[backend_url.host] == backend_url.port.to_s

  secret_references = Hash.new { |hash, key| hash[key] = [] }
  documents.each do |document|
    next unless (pod = pod_spec(document))
    pod_containers(pod).each do |container|
      container.fetch('env', []).each do |entry|
        reference = entry.dig('valueFrom', 'secretKeyRef')
        secret_references[reference['name']] << reference['key'] if reference
      end
    end
  end
  normalized_references = secret_references.transform_values { |keys| keys.uniq.sort }
  raise 'ESO Secret names or keys mismatch' unless normalized_references == secrets.transform_values(&:sort)
  raise 'deploys must not render Secrets' if documents.any? { |document| document['kind'] == 'Secret' }

  predeploy_references = pod_spec(predeploy).dig('containers', 0, 'env').filter_map do |entry|
    reference = entry.dig('valueFrom', 'secretKeyRef')
    [reference['name'], reference['key']] if reference
  end
  database_admin_name = environment == 'test' ? 'plepic-test-database-admin' : 'plepic-database-admin'
  predeploy_database_admin_keys = predeploy_references.filter_map do |name, key|
    key if name == database_admin_name
  end.sort
  expected_database_admin_references = %w[MEDUSA_ADMIN_EMAIL MEDUSA_ADMIN_PASSWORD].map do |key|
    [database_admin_name, key]
  end
  actual_database_admin_references = predeploy_references.select do |name, _key|
    name.end_with?('database-admin')
  end.sort
  raise 'environment-specific database-admin references mismatch' unless
    actual_database_admin_references == expected_database_admin_references
  raise 'predeploy database-admin privilege boundary mismatch' unless
    predeploy_database_admin_keys == %w[MEDUSA_ADMIN_EMAIL MEDUSA_ADMIN_PASSWORD]

  runtime_superuser_consumers = documents.filter_map do |document|
    next unless (pod = pod_spec(document))
    references_superuser = pod_containers(pod).any? do |container|
      container.fetch('env', []).any? do |entry|
        entry.dig('valueFrom', 'secretKeyRef', 'key') == 'POSTGRES_SUPERUSER_PASSWORD'
      end
    end
    document.dig('metadata', 'name') if references_superuser
  end
  raise 'only PostgreSQL may consume the superuser password' unless
    runtime_superuser_consumers == ["plepic-postgresql#{suffix}"]

  asset_mount_owners = documents.filter_map do |document|
    next unless (pod = pod_spec(document))
    asset_volume_names = pod.fetch('volumes', []).filter_map do |volume|
      volume['name'] if volume.dig('persistentVolumeClaim', 'claimName') == "plepic-assets#{suffix}"
    end
    mounts = pod_containers(pod).flat_map { |container| container.fetch('volumeMounts', []) }
    document.dig('metadata', 'name') if mounts.any? { |mount| asset_volume_names.include?(mount['name']) }
  end.sort
  raise 'assets PVC writer set mismatch' unless asset_mount_owners == %W[
    plepic-backend#{suffix}
    plepic-catalogue-import#{suffix}
    plepic-worker#{suffix}
  ].sort

  assert_network_contract(documents, suffix)
  rendered = File.read(path)
  raise 'IPv6 exposure is forbidden' if rendered.include?('::')
  offending_addresses = public_account_addresses(rendered)
  raise "public account addresses are forbidden (#{offending_addresses.length} found)" unless offending_addresses.empty?
  rendered.scan(/\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/).each do |literal|
    next if ['0.0.0.0', '0.0.0.0/0'].include?(literal)
    raise "public IPv4 is forbidden: #{literal}" unless IPAddr.new(literal).private?
  end

  {
    names: documents.map { |document| [document['kind'], document.dig('metadata', 'name')] }.to_set,
    pvcs: documents.select { |document| document['kind'] == 'PersistentVolumeClaim' }.map { |document| document.dig('metadata', 'name') }.to_set,
    secrets: secret_references.keys.to_set,
    services: documents.select { |document| document['kind'] == 'Service' }.map { |document| document.dig('metadata', 'name') }.to_set,
    ports: externally_reachable.values.to_set,
    databases: Set[database],
  }
end

require 'ipaddr'
require 'set'
require 'tempfile'
require 'uri'

live_resources = {
  'postgresql' => { 'requests' => { 'cpu' => '200m', 'memory' => '256Mi' }, 'limits' => { 'cpu' => '1', 'memory' => '1Gi' } },
  'redis' => { 'requests' => { 'cpu' => '200m', 'memory' => '256Mi' }, 'limits' => { 'cpu' => '1', 'memory' => '1Gi' } },
  'backend' => { 'requests' => { 'cpu' => '200m', 'memory' => '256Mi' }, 'limits' => { 'cpu' => '1', 'memory' => '1Gi' } },
  'worker' => { 'requests' => { 'cpu' => '200m', 'memory' => '256Mi' }, 'limits' => { 'cpu' => '1', 'memory' => '1Gi' } },
  'storefront' => { 'requests' => { 'cpu' => '200m', 'memory' => '256Mi' }, 'limits' => { 'cpu' => '1', 'memory' => '1Gi' } },
  'predeploy' => { 'requests' => { 'cpu' => '200m', 'memory' => '256Mi' }, 'limits' => { 'cpu' => '1', 'memory' => '1Gi' } },
  'catalogue-import' => { 'requests' => { 'cpu' => '200m', 'memory' => '256Mi' }, 'limits' => { 'cpu' => '1', 'memory' => '1Gi' } },
}
test_resources = {
  'postgresql' => { 'requests' => { 'cpu' => '100m', 'memory' => '128Mi' }, 'limits' => { 'cpu' => '500m', 'memory' => '512Mi' } },
  'redis' => { 'requests' => { 'cpu' => '100m', 'memory' => '128Mi' }, 'limits' => { 'cpu' => '500m', 'memory' => '512Mi' } },
  'backend' => { 'requests' => { 'cpu' => '100m', 'memory' => '128Mi' }, 'limits' => { 'cpu' => '500m', 'memory' => '512Mi' } },
  'worker' => { 'requests' => { 'cpu' => '100m', 'memory' => '128Mi' }, 'limits' => { 'cpu' => '500m', 'memory' => '512Mi' } },
  'storefront' => { 'requests' => { 'cpu' => '100m', 'memory' => '128Mi' }, 'limits' => { 'cpu' => '500m', 'memory' => '512Mi' } },
  'predeploy' => { 'requests' => { 'cpu' => '100m', 'memory' => '128Mi' }, 'limits' => { 'cpu' => '500m', 'memory' => '512Mi' } },
  'catalogue-import' => { 'requests' => { 'cpu' => '100m', 'memory' => '128Mi' }, 'limits' => { 'cpu' => '500m', 'memory' => '512Mi' } },
}
runtime_keys = %w[COOKIE_SECRET DATABASE_PASSWORD JWT_SECRET NEWSLETTER_API_KEY NEWSLETTER_LIST_ID REDIS_PASSWORD SMTP_PASSWORD SMTP_USERNAME STRIPE_PAYMENT_METHOD_CONFIGURATION_ID STRIPE_PUBLISHABLE_KEY STRIPE_SECRET_KEY STRIPE_WEBHOOK_SECRET TURNSTILE_SECRET_KEY TURNSTILE_SITE_KEY]
admin_keys = %w[MEDUSA_ADMIN_EMAIL MEDUSA_ADMIN_PASSWORD POSTGRES_SUPERUSER_PASSWORD]

live_options = {
  environment: 'live', namespace: 'plepic', suffix: '',
  ports: { 'storefront' => 8101, 'backend' => 8102 }, database: 'plepic',
  secrets: {
    'plepic-runtime-credentials' => runtime_keys,
    'plepic-database-admin' => admin_keys,
    'plepic-publishable-key' => ['publishableKey'],
  },
  pvc_sizes: { 'postgresql' => '20Gi', 'redis' => '2Gi', 'assets' => '10Gi' },
  resources: live_resources,
}
test_options = {
  environment: 'test', namespace: 'plepic-test', suffix: '-test',
  ports: { 'storefront' => 8111, 'backend' => 8112 }, database: 'plepic_test',
  secrets: {
    'plepic-test-runtime-credentials' => runtime_keys,
    'plepic-test-database-admin' => admin_keys,
    'plepic-test-publishable-key' => ['publishableKey'],
  },
  pvc_sizes: { 'postgresql' => '5Gi', 'redis' => '1Gi', 'assets' => '2Gi' },
  resources: test_resources,
}

live = assert_manifest(ARGV.fetch(0), **live_options)
test = assert_manifest(ARGV.fetch(1), **test_options)

%i[names pvcs secrets services ports databases].each do |boundary|
  overlap = live.fetch(boundary) & test.fetch(boundary)
  raise "live and test share #{boundary}: #{overlap.to_a.inspect}" unless overlap.empty?
end

def assert_mutation_rejected(source_path, options, description, expected_error)
  documents = YAML.load_stream(File.read(source_path)).compact
  yield documents
  Tempfile.create(['plepic-manifest-mutation', '.yaml']) do |temporary|
    temporary.write(YAML.dump_stream(*documents))
    temporary.flush
    begin
      assert_manifest(temporary.path, **options)
    rescue StandardError => error
      raise "#{description} failed for the wrong reason: #{error.message}" unless error.message.include?(expected_error)
      return
    end
  end
  raise "positive control was accepted: #{description}"
end

assert_mutation_rejected(ARGV.fetch(1), test_options, 'extra NodePort Service', 'Service set mismatch') do |documents|
  documents << {
    'apiVersion' => 'v1',
    'kind' => 'Service',
    'metadata' => {
      'name' => 'rogue-nodeport',
      'namespace' => 'plepic-test',
      'annotations' => { 'argocd.argoproj.io/sync-wave' => '-20' },
    },
    'spec' => {
      'type' => 'NodePort',
      'selector' => {},
      'ports' => [{ 'port' => 9999, 'targetPort' => 9999, 'nodePort' => 30_999 }],
    },
  }
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options, 'extra broad PostgreSQL ingress', 'PostgreSQL ingress mismatch'
) do |documents|
  postgresql = resource(documents, 'NetworkPolicy', 'allow-postgresql-ingress-test')
  postgresql.fetch('spec').fetch('ingress') << {
    'from' => [{ 'ipBlock' => { 'cidr' => '0.0.0.0/0' } }],
    'ports' => [{ 'port' => 5432, 'protocol' => 'TCP' }],
  }
end

puts 'Plepic manifest contract tests passed'
RUBY
