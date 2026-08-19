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
# What every container image in the rendered overlays must carry.
#
# This is a *shape*, deliberately, and it is what this file asserts instead of
# any particular digest value. The assertions it replaces compared images to the
# all-zero bootstrap sentinel, which made them mutually exclusive with promotion
# by construction: they required the sentinel, and promotion is precisely what
# replaces it. The first `deploy-test` label was refused by this file rather than
# by anything wrong with the manifests it was checking.
#
# Two consequences are the point rather than a side effect. A promoted overlay
# and an unpromoted one are the same shape here, so the environment that is
# behind does not break the moment the other moves ahead — no *image* assertion
# below knows or asks which environment it is looking at. (assert_manifest does
# branch on environment, for the name suffix, the Secret references and the
# merchant values; none of that reaches image pinning, which is the property
# that has to hold across a promotion.) And because the requirement is
# structural, no future promotion touches this file at all.
DIGEST_SHAPE = /\Asha256:[0-9a-f]{64}\z/.freeze

# The bootstrap value Task 4 put in both overlays. Nothing below requires it any
# more; it survives as the one thing that must be *accepted*, because "the
# sentinel is still a valid digest" is the half of the asymmetry a shape test
# could silently lose while every other case still passed.
SENTINEL = "sha256:#{'0' * 64}"

raise 'the all-zero bootstrap sentinel must satisfy the digest shape' unless
  SENTINEL.match?(DIGEST_SHAPE)

# Negative controls on the shape itself. A digest test that accepted a truncated
# or non-hexadecimal string would pass every manifest in this repository today
# and pin nothing, so prove it discriminates before trusting it.
{
  SENTINEL => true,
  "sha256:#{'a' * 64}" => true,
  "sha256:#{'0' * 63}" => false,
  "sha256:#{'0' * 65}" => false,
  "sha256:#{'A' * 64}" => false,
  "sha256:#{'g' * 64}" => false,
  "sha512:#{'0' * 64}" => false,
  "SHA256:#{'0' * 64}" => false,
  'latest' => false,
  '' => false,
}.each do |candidate, expected|
  actual = candidate.match?(DIGEST_SHAPE)
  raise "digest shape control failed: #{candidate.inspect} matched=#{actual}" unless actual == expected
end

def resource(documents, kind, name)
  matches = documents.select do |document|
    document['kind'] == kind && document.dig('metadata', 'name') == name
  end
  raise "expected one #{kind}/#{name}, got #{matches.length}" unless matches.length == 1
  matches.first
end

# One declaration of what carries a pod, so nothing can enumerate a stale subset
# of it. Every kind here is resolved, and membership is what tells a caller the
# difference between "not a pod-carrying kind" and "a pod-carrying kind that
# failed to resolve" — two answers a bare nil cannot distinguish.
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
    name = document.dig('metadata', 'name')
    # A recognised kind that fails to resolve must not be quietly filtered out.
    # Selecting on truthiness alone skipped it and left the "missing pod spec"
    # guard unreachable for exactly the case it was written for.
    raise "#{document['kind']}/#{name} is a pod-carrying kind whose pod spec does not resolve" if
      POD_TEMPLATE_PATHS.key?(document['kind'])
    next unless carries_pod_template?(document)
    raise "#{document['kind']}/#{name} carries a pod template that pod_spec does not resolve"
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

BACKEND_IMAGE = 'ghcr.io/hannosirkel/plepic-backend'.freeze
STOREFRONT_IMAGE = 'ghcr.io/hannosirkel/plepic-storefront'.freeze
APPLICATION_IMAGE_PREFIX = 'ghcr.io/hannosirkel/plepic-'.freeze

# An image reference reduced to its repository, discarding tag and digest.
#
# Matching the digest form alone is not enough. A container naming the same
# image by tag is invisible to a `…@` prefix test. This file used to predict
# here that its own sentinel counter would stop holding at the first promotion,
# and it did: the counters compared exact digest strings, so a tag-form
# reference slipped past them, and they refused promotion outright rather than
# ageing quietly. Both failures are closed by asserting a digest *shape* on
# every container and running the census through this reducer, so neither the
# census nor the digest requirement depends on any particular digest value.
#
# A tag is the part after the last colon of the final path segment, so the colon
# in a registry's `host:port` is not mistaken for one.
def image_repository(reference)
  repository = reference.to_s.split('@', 2).first.to_s
  return repository unless repository.split('/').last.to_s.include?(':')
  repository[0...repository.rindex(':')]
end

# Positive control on the reducer itself. Every form below names the same
# repository, and the near-miss must not.
#
# The port-and-tag row is the one that pins the reasoning above rather than
# merely exercising it: a registry port and a tag are the only shape where the
# *last* colon and the *first* colon differ, so without it the comment's claim
# about which colon is the tag is unasserted and `rindex` could be spelled
# `index` with the whole contract still green.
{
  'ghcr.io/hannosirkel/plepic-backend' => BACKEND_IMAGE,
  'ghcr.io/hannosirkel/plepic-backend:latest' => BACKEND_IMAGE,
  "ghcr.io/hannosirkel/plepic-backend@sha256:#{'0' * 64}" => BACKEND_IMAGE,
  "ghcr.io/hannosirkel/plepic-backend:v1@sha256:#{'0' * 64}" => BACKEND_IMAGE,
  'registry.example:5000/hannosirkel/plepic-backend' => 'registry.example:5000/hannosirkel/plepic-backend',
  'registry.example:5000/hannosirkel/plepic-backend:v1' => 'registry.example:5000/hannosirkel/plepic-backend',
  'ghcr.io/hannosirkel/plepic-backend-tools:latest' => 'ghcr.io/hannosirkel/plepic-backend-tools',
}.each do |reference, expected|
  actual = image_repository(reference)
  raise "image repository control failed: #{reference} reduced to #{actual}" unless actual == expected
end

# What the backend image requires of anything that runs it.
#
# Declared here, not read from `hannosirkel/plepic`. That repository is not
# available at validation time, and making a green build depend on another
# repository's `main` would be worse than a list a reader has to update
# deliberately. The source is `backend/src/config/runtime.ts`:
# `requiredEnvironmentVariables`, plus the five `DATABASE_*` parts
# `config/database-url.ts` assembles a connection string from — these manifests
# supply the parts and no `DATABASE_URL`, so the parts are what this asserts.
#
# Every one of them is read at module scope, so a workload missing a single
# entry does not degrade: it exits at start. This guard exists because nothing
# compared the two sides. Task 4 reviewed the manifests against the plan and
# Task 5 reviewed the image against the plan, and four workloads shipped
# without STORE_CORS, ADMIN_CORS or AUTH_CORS while both gates stayed green.
#
# REDIS_HOST and REDIS_PORT are here for the same "plus" that admits the
# DATABASE_* parts, and the reasoning is worth stating because it is not the
# obvious one. They are not in `requiredEnvironmentVariables`; they are required
# because `readBackendRuntimeConfig` calls `readRedisRuntimeConfig` at
# `runtime.ts:430` unconditionally, which requires all three. Listing them here
# is not redundant with the Service-endpoint table further down either: that
# table reads them with `fetch`, so a workload that omits one died there with
# `key not found: "REDIS_HOST"` — a crash naming the lookup rather than a
# refusal naming the workload and the variable. This list runs first and says
# which workload is missing what.
#
# REDIS_PASSWORD is deliberately *not* here. The per-workload Redis secret
# contract above refuses its absence first and refuses strictly more — the
# Secret it comes from and the key within it — so an entry here would be one no
# mutation can reach, and an assertion no mutation can reach is one a future
# edit deletes in silence.
BACKEND_IMAGE_REQUIRED_ENVIRONMENT = %w[
  DATABASE_HOST
  DATABASE_PORT
  DATABASE_NAME
  DATABASE_USER
  DATABASE_PASSWORD
  REDIS_HOST
  REDIS_PORT
  JWT_SECRET
  COOKIE_SECRET
  STORE_CORS
  ADMIN_CORS
  AUTH_CORS
  STRIPE_SECRET_KEY
  STRIPE_WEBHOOK_SECRET
  STRIPE_PAYMENT_METHOD_CONFIGURATION_ID
  SMTP_HOST
  SMTP_PORT
  SMTP_USERNAME
  SMTP_PASSWORD
  SMTP_ENVELOPE_FROM
  CONTACT_MAIL_RECIPIENT
  TURNSTILE_SECRET_KEY
  MERCHANT_LEGAL_NAME
  MERCHANT_REGISTERED_ADDRESS
  MERCHANT_CONTACT_ADDRESS
  MERCHANT_RETURN_ADDRESS
].freeze

# Required, and required to be empty. Nothing reaches this backend cross-origin
# — the storefront proxies the allowlisted /store-api prefixes from its own
# origin and Admin is served by the backend itself — so any origin declared here
# would be a public hostname this repository must not carry and an exposure the
# plan forbids. Empty rather than absent so the choice is visible in the
# manifest and the image's requirement stays fail-closed.
SAME_ORIGIN_CORS_VARIABLES = %w[STORE_CORS ADMIN_CORS AUTH_CORS].freeze

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

# The same exemption one level up: a bare *hostname*, not an address at one.
#
# `build_reserved_address` cannot answer this question and does not reach it —
# its pattern requires a `local-part@`, so a bare hostname or a URL never enters
# it. That gap mattered: the contact recipient is refused structurally by
# `backend-family contact recipient must be synthetic` and again by the
# whole-file address scan, and the SMTP host by its `.invalid` suffix, while the
# three SITE_* values were the only externally-facing names in these manifests
# with no structural boundary at all. An exact-value comparison is not one: it
# refuses an overlay that drifts from the option table, and an editor who
# changes both in the same commit — which exact equality *forces* — moves past
# it with the suite green.
#
# Anchored at a label boundary rather than written as `end_with?`, so a real
# domain that merely ends in the right letters is refused.
def build_reserved_hostname(example_domains, suffix_labels)
  /
    \A(?:[A-Za-z0-9-]+\.)*
    (?:#{(example_domains + suffix_labels).map { |name| Regexp.escape(name) }.join('|')})
    \z
  /xi
end

RESERVED_HOSTNAME = build_reserved_hostname(RESERVED_EXAMPLE_DOMAINS, RESERVED_SUFFIX_LABELS).freeze

# The same structural control the address pattern carries above, for the same
# reason: pinning the two declarations alone would still allow an alternative to
# be added straight to this pattern with the lists untouched.
raise 'the reserved-hostname pattern does not match the set it claims to encode' unless
  RESERVED_HOSTNAME == build_reserved_hostname(RESERVED_EXAMPLE_DOMAINS, RESERVED_SUFFIX_LABELS)

# Controls, in the shape of the address controls below and for the same reason.
# The forbidden samples are invented names, so this file carries no real
# identity of its own. `notexample.com` and `mytest` are the rows that separate
# a label-anchored pattern from a bare suffix test — both would be accepted by
# `end_with?`, and one of them is how a real domain would arrive.
{
  'example.com' => false,
  'test.example.org' => false,
  'shop.staging.example.net' => false,
  'relay.smtp.invalid' => false,
  'host.test' => false,
  'localhost' => false,
  'shop.merchant-domain.com' => true,
  'www.some-company.co.uk' => true,
  'example.com.attacker.net' => true,
  'notexample.com' => true,
  'mytest' => true,
  '' => true,
}.each do |hostname, expected_forbidden|
  actual_forbidden = !RESERVED_HOSTNAME.match?(hostname)
  next if actual_forbidden == expected_forbidden
  raise "reserved hostname control failed: #{hostname.inspect} " \
        "expected forbidden=#{expected_forbidden}, got #{actual_forbidden}"
end

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

# The one volume that gives `medusa db:migrate` the directories the Migrator
# insists on, and the ten places it is mounted.
#
# Mikro-ORM's `Migrator.up()` calls `ensureMigrationsDirExists()` at least once
# for every module *and* every provider it loads — each gets its own migrations
# directory, derived from its own discovery path, which is why seven of the ten
# entries below are providers rather than modules. It is more often than once
# each: `migrationScripts` in `@medusajs/modules-sdk`'s `load-internal.js`
# accumulates across loaded services and the build loop re-walks the whole
# accumulator each pass. The count is not what matters here.
#
# That call does not tolerate a missing
# directory — it *creates* it. Every package in this application's module set
# that ships no `dist/migrations` therefore failed against
# `readOnlyRootFilesystem: true`, and the predeploy Job exited 1 *after* 176
# migrations across 121 tables had already applied. An empty directory is the
# whole requirement: the migrator globs it, finds nothing, and reports the module
# up to date. The mounts are `readOnly` because `db:migrate` never writes there —
# only `db:generate` does, and that never runs in-cluster.
#
# **This list is coupled to the application's module and provider set, not to the
# error log.** The log names only the *first* missing directory per module, so
# `locking` and `file` each hide a second one, and `MODULE: notification` is not
# `notification-local`: `backend/medusa-config.ts` loads
# `notificationModule(runtime.smtp)`, whose provider resolves to
# `./src/notifications` — the application's own SMTP provider, which ships no
# `migrations` directory and lives under `/app`, not `/node_modules`. Adding a
# provider or module whose package ships no migrations directory reproduces the
# failure and needs another entry here and in `plepic/base/predeploy-job.yaml`.
MIGRATIONS_VOLUME = 'module-migrations'.freeze
MIGRATIONS_DIRECTORIES = [
  ['payment-stripe', '/node_modules/@medusajs/payment-stripe/dist/migrations'],
  ['auth-emailpass', '/node_modules/@medusajs/auth-emailpass/dist/migrations'],
  ['fulfillment-manual', '/node_modules/@medusajs/fulfillment-manual/dist/migrations'],
  ['cache-inmemory', '/node_modules/@medusajs/cache-inmemory/dist/migrations'],
  ['event-bus-redis', '/node_modules/@medusajs/event-bus-redis/dist/migrations'],
  ['locking', '/node_modules/@medusajs/locking/dist/migrations'],
  ['locking-redis', '/node_modules/@medusajs/locking-redis/dist/migrations'],
  ['file', '/node_modules/@medusajs/file/dist/migrations'],
  ['file-local', '/node_modules/@medusajs/file-local/dist/migrations'],
  ['notifications', '/app/src/notifications/migrations'],
].freeze

# Controls on the table itself, before anything is compared against it. One
# `emptyDir` reaching ten paths only works if every mount takes a distinct
# `subPath`: two mounts sharing one would give the migrator two names for one
# directory, and a duplicate written here would be invisible to an equality test
# that compared the manifest to this same list.
raise 'migration directory subPaths must be distinct' unless
  MIGRATIONS_DIRECTORIES.map(&:first).uniq.length == MIGRATIONS_DIRECTORIES.length
raise 'migration directory mount paths must be distinct' unless
  MIGRATIONS_DIRECTORIES.map(&:last).uniq.length == MIGRATIONS_DIRECTORIES.length

def assert_migration_directories(documents, predeploy)
  pod = pod_spec(predeploy)
  expected_mounts = MIGRATIONS_DIRECTORIES.map do |sub_path, mount_path|
    { 'name' => MIGRATIONS_VOLUME, 'mountPath' => mount_path, 'subPath' => sub_path, 'readOnly' => true }
  end
  # Selected by volume name *or* by mount path, so the comparison is two-sided: a
  # missing, writable, misdirected or subPath-less entry fails it, and so does a
  # second volume quietly taking over one of the ten paths while the named ones
  # still look right.
  migration_paths = MIGRATIONS_DIRECTORIES.map(&:last)
  actual_mounts = pod_containers(pod).flat_map do |container|
    container.fetch('volumeMounts', []).select do |mount|
      mount['name'] == MIGRATIONS_VOLUME || migration_paths.include?(mount['mountPath'])
    end
  end
  raise 'predeploy module migrations mount contract mismatch' unless actual_mounts == expected_mounts

  migration_volumes = pod.fetch('volumes', []).select { |volume| volume['name'] == MIGRATIONS_VOLUME }
  raise 'predeploy module migrations volume contract mismatch' unless
    migration_volumes == [{ 'name' => MIGRATIONS_VOLUME, 'emptyDir' => {} }]

  # Relaxing the root filesystem is the *other* way to make this failure
  # disappear, and it is rejected: this Job holds the admin, database, Stripe and
  # JWT secrets and is the worst container in the deployment to soften. Nothing
  # above would notice — ten mounted directories and a writable root satisfy
  # every assertion in this method — so the coupling is stated here where the
  # remedy is, rather than left implicit.
  #
  # assert_pod_hardening already requires this of every container and runs
  # first, so this restatement is not the guard that fires; a mutation opening
  # the root filesystem is refused there, by name, before reaching here. It is
  # deliberately redundant: the hardening loop is generic and could be narrowed
  # for some unrelated workload, and this contract must not lose its premise
  # when that happens.
  pod_containers(pod).each do |container|
    raise 'the predeploy root filesystem must stay read-only' unless
      container.dig('securityContext', 'readOnlyRootFilesystem') == true
  end

  # Only the predeploy Job invokes the Migrator. The two Deployments and the
  # import Job run the same image and never call it, so they need none of this,
  # and spreading it to them by copy-paste would widen a mount set nobody there
  # reads.
  other_consumers = workloads(documents).reject { |workload| workload.equal?(predeploy) }.filter_map do |workload|
    other_pod = pod_spec(workload)
    has_mount = pod_containers(other_pod).any? do |container|
      container.fetch('volumeMounts', []).any? do |mount|
        mount['name'] == MIGRATIONS_VOLUME || migration_paths.include?(mount['mountPath'])
      end
    end
    has_volume = other_pod.fetch('volumes', []).any? { |volume| volume['name'] == MIGRATIONS_VOLUME }
    workload.dig('metadata', 'name') if has_mount || has_volume
  end
  raise 'the module migrations volume must reach only the predeploy Job' unless other_consumers.empty?
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
  # The two Jobs are admitted for the same reason they are admitted to
  # PostgreSQL: they run the backend image, whose module container opens a Redis
  # connection at module scope, so a Job that cannot reach Redis does not skip
  # the event bus — it retries forever. For the predeploy Job that is a Sync
  # hook that never completes, which blocks every wave behind it.
  raise 'Redis ingress mismatch' unless redis.dig('spec', 'ingress') == [{
    'from' => %w[backend worker predeploy catalogue-import].map do |component|
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
      'values' => %w[backend worker predeploy catalogue-import],
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
  # `backup` is admitted here and `recovery` is not, and the difference is the
  # whole of what this list is for.
  #
  # Orange's `backups` Application renders two backup CronJobs into each Plepic
  # namespace — one for PostgreSQL, one for the assets PVC — all labelled
  # `app.kubernetes.io/component: backup`; they dump their source and then
  # upload to Backblaze B2 over TCP 443. Egress here is CIDR-only, so reaching
  # B2 means being in this selector. Without it the Pods connected to the
  # database — `allow-postgresql-egress` already names them — and then failed at
  # the upload, which surfaces as a credential or bucket error at the first
  # backup cycle rather than as a policy one.
  #
  # `recovery` stays out because the restore path never speaks to B2 from the
  # cluster. `roles/recovery/tasks/download.yml` lists, downloads and decrypts
  # the object on the Ansible controller (`delegate_to: localhost`), and
  # `roles/recovery/templates/postgresql-restore.yaml.j2` mounts the result into
  # the Job read-only from a `hostPath`. A restore Pod therefore needs 5432 and
  # nothing else, and this rule's peer is `0.0.0.0/0`, so it stays out by plain
  # least privilege.
  #
  # Exact set equality, not membership, for the same reason: this rule egresses
  # to `0.0.0.0/0`, so every name added to it gains general outbound HTTPS, and
  # a membership test would let a later author add one silently.
  raise 'HTTPS workload selector mismatch' unless https.dig('spec', 'podSelector') == {
    'matchExpressions' => [{
      'key' => 'app.kubernetes.io/component',
      'operator' => 'In',
      'values' => %w[backend worker storefront predeploy catalogue-import backup],
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

# SITE_TEST_HOSTNAMES is a comma-separated list, and an empty declaration is a
# list of nothing rather than a list containing one empty name — which is what
# `readEnvList` in the storefront does with it too.
def site_host_list(value)
  value.to_s.split(',').map(&:strip).reject(&:empty?)
end

def site_base_url_host(site_hosts)
  URI(site_hosts.fetch('SITE_BASE_URL')).host
end

# Every hostname this environment's storefront answers to, as far as a manifest
# can know: the host of its base URL and its canonical host.
#
# Named separately because the rule below quantifies over this set, and the set
# is not the same thing as the canonical host. The invariant is
# *"SITE_TEST_HOSTNAMES contains every hostname the test storefront answers
# to"*; the canonical host is one member of that set, never the rule itself.
# `isTestHost(host, config)` matches the incoming request's `Host` header
# against the list and never consults the canonical host — that is the separate
# `isCanonicalHost`. The two coincide today only because the test storefront
# answers to exactly one name. The day it answers to a second — a preview
# hostname, a `www` form, a retired name still pointed at it — that name
# belongs in this function *and* in the list, and a rule written as "the
# canonical host is in the list" would have said nothing about it.
def site_answered_hostnames(site_hosts)
  [site_base_url_host(site_hosts), site_hosts.fetch('SITE_CANONICAL_HOST')].compact.uniq
end

def assert_manifest(path, environment:, namespace:, suffix:, ports:, database:, secrets:, pvc_sizes:, resources:,
                    site_hosts:, overlay_path: nil)
  documents = YAML.load_stream(File.read(path)).compact
  # The overlay is read from disk rather than recovered from the rendered
  # documents, because what the assertions just below check is the source the
  # digest lines get written into, not the result of applying them.
  #
  # overlay_path exists only so a mutation can reach those assertions at all.
  # The mutation harness rewrites rendered documents, and no rewriting of a
  # rendered document can change what this line loads, which is exactly how the
  # overlay digest assertion ended up as the one guard in this change with no
  # kill test behind it. Production callers pass nothing and get the real file.
  overlay = YAML.load_file(overlay_path || "plepic/overlays/#{environment}/kustomization.yaml")
  raise 'overlay may source only the shared base' unless overlay['resources'] == ['../../base']
  expected_name_suffix = environment == 'test' ? '-test' : nil
  raise 'overlay name suffix mismatch' unless overlay['nameSuffix'] == expected_name_suffix
  raise 'overlay namespace mismatch' unless overlay['namespace'] == namespace
  expected_images = %w[ghcr.io/hannosirkel/plepic-backend ghcr.io/hannosirkel/plepic-storefront]
  raise 'overlay image names mismatch' unless overlay.fetch('images').map { |image| image['name'] }.sort == expected_images.sort
  # Every overlay image entry pins a digest — the bootstrap sentinel and a
  # promoted digest are equally valid here, and an entry that pins only a tag,
  # or nothing, is not. The rendered check further down is the authoritative one;
  # this refuses the same mistake at the source it would be written into.
  raise 'overlay images must be pinned by digest' unless
    overlay.fetch('images').all? { |image| image['digest'].to_s.match?(DIGEST_SHAPE) }
  # And nothing else in the entry. `scripts/update-gitops-digest.sh` in the
  # Plepic repository rewrites these lines by matching a literal three-line block
  # — `name`, `newName`, `digest` — and refuses the whole file if it cannot find
  # exactly one such block per image.
  #
  # An extra key is therefore not a rendering problem. A `newTag` beside a digest
  # renders `…:latest@sha256:…`, which pins correctly, because the digest is what
  # the runtime resolves and the tag is ignored. It is a *promotion* problem: the
  # overlay would still deploy the right image and the next promotion into it
  # would be refused. That is the same shape of defect as the sentinel assertions
  # this file replaced — a contract here agreeing to an overlay the promotion
  # path cannot write to — so it is refused here rather than discovered in CI at
  # the next release.
  raise 'overlay image entries must carry only name, newName and digest' unless
    overlay.fetch('images').all? { |image| image.keys.sort == %w[digest name newName] }
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
  assert_migration_directories(documents, predeploy)

  import = resource(documents, 'Job', "plepic-catalogue-import#{suffix}")
  raise 'catalogue import must stay suspended' unless import.dig('spec', 'suspend') == true
  raise 'catalogue import annotations mismatch' unless import.dig('metadata', 'annotations') == {
    'argocd.argoproj.io/sync-wave' => '0',
    'argocd.argoproj.io/ignore-healthcheck' => 'true',
    'argocd.argoproj.io/sync-options' => 'Force=true,Replace=true',
  }

  assets = resource(documents, 'PersistentVolumeClaim', "plepic-assets#{suffix}")
  wave_minus_twenty = documents.select do |document|
    document.dig('metadata', 'annotations', 'argocd.argoproj.io/sync-wave') == '-20'
  end
  raise 'data/support resources must be wave -20' unless wave_minus_twenty.any? { |document| document['kind'] == 'StatefulSet' }
  documents.each do |document|
    name = document.dig('metadata', 'name')
    expected_wave = if document.equal?(predeploy)
      '-10'
    elsif document.equal?(import) || document.equal?(assets) ||
          document['kind'] == 'Deployment' ||
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
  redis_acl_line = redis_args.lines
    .find { |line| line.include?("printf 'user default on >%s") }
    &.strip
  expected_redis_acl_line = %q{printf 'user default on >%s ~* &* +@all -@dangerous +info\n' "$REDIS_PASSWORD" > /run/redis/users.acl}
  raise 'Redis ACL least-privilege contract mismatch' unless redis_acl_line == expected_redis_acl_line
  raise 'deprecated Redis rename-command is forbidden' if redis_config.include?('rename-command') || redis_args.include?('rename-command')
  postgresql_image = pod_spec(postgresql).dig('containers', 0, 'image')
  redis_image = pod_spec(redis).dig('containers', 0, 'image')
  raise 'PostgreSQL must be digest pinned' unless postgresql_image&.match?(%r{\Apostgres:[^@]+@sha256:[0-9a-f]{64}\z})
  raise 'Redis must be digest pinned' unless redis_image&.match?(%r{\Aredis:[^@]+@sha256:[0-9a-f]{64}\z})

  # Named containers, because "which container" is the only useful thing to say
  # about an unpinned image and the two assertions below both need the pairing.
  named_containers = documents.flat_map do |document|
    next [] unless (pod = pod_spec(document))
    pod_containers(pod).map { |container| [document.dig('metadata', 'name'), container] }
  end

  # Every container image in the rendered overlays carries an `@sha256:` digest.
  #
  # Not only the application images: PostgreSQL and Redis are pinned by the two
  # assertions just above, but a future container added to any pod is inside this
  # one the moment it appears rather than the moment someone remembers to pin it.
  # initContainers and ephemeralContainers included — a debug surface pulling a
  # mutable tag is the same unpinned image with a smaller audience.
  named_containers.each do |name, container|
    reference = container['image'].to_s
    digest = reference.split('@', 2)[1]
    raise "#{name}/#{container['name']} must pin its image by digest, not #{reference.inspect}" unless
      digest&.match?(DIGEST_SHAPE)
  end

  # The container census the replaced sentinel counters also carried, kept whole:
  # four containers run the backend image, one runs the storefront image.
  #
  # Two things below rest on it. The backend-image workload set is only a
  # meaningful assertion while the container count is bounded, and the mutation
  # that moves the backend image onto the storefront is reachable *because* a
  # fifth backend-image container is refused here first.
  #
  # Counted through image_repository rather than on an exact reference, so a
  # container naming an application image by tag is counted rather than
  # invisible — the blindness that made the old counters miss exactly the case
  # they were supposed to bound. Comparing the whole tally rather than two counts
  # additionally refuses a third `plepic-` repository nobody declared.
  application_image_census = named_containers
    .map { |_name, container| image_repository(container['image']) }
    .tally.select { |repository, _count| repository.start_with?(APPLICATION_IMAGE_PREFIX) }
  raise "application image census mismatch: #{application_image_census.inspect}" unless
    application_image_census == { BACKEND_IMAGE => 4, STOREFRONT_IMAGE => 1 }

  # One digest per application repository, across the whole overlay.
  #
  # The sentinel equality this file replaced forced this implicitly — every
  # backend container had to carry one identical value — and a shape requirement
  # on each container separately does not. The class it bounds is a migration or
  # catalogue-import Job running a different backend build than the backend it
  # prepares, which is what the Sync waves exist to order and which four
  # independently well-formed digests would otherwise satisfy.
  #
  # Value-relative, not value-fixed: it says the digests agree, never which
  # digest they agree on, so it survives every promotion untouched and still asks
  # nothing about which environment it is reading. It is unreachable through the
  # supported path today, because kustomize's `images:` transformer runs after
  # patches and rewrites every matching reference to the one declared digest; it
  # is held against the rendering path changing, and the mutation below is what
  # stops it becoming decorative.
  application_digests = named_containers
    .map { |_name, container| [image_repository(container['image']), container['image'].to_s.split('@', 2)[1]] }
    .select { |repository, _digest| repository.start_with?(APPLICATION_IMAGE_PREFIX) }
    .group_by(&:first)
    .transform_values { |pairs| pairs.map(&:last).uniq }
  divergent = application_digests.select { |_repository, digests| digests.length > 1 }
  raise "application image digests diverge: #{divergent.inspect}" unless divergent.empty?

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
    # The two Jobs run the same image and the same module-scope config loader as
    # the two Deployments, so they need these from the same Secret under the same
    # keys — and by reference, never as a literal. Checked per workload because
    # the aggregate ESO key contract further down is satisfied by any one
    # workload carrying the key, which is exactly how both Jobs shipped without
    # them.
    session_refs = container.fetch('env', []).filter_map do |entry|
      next unless %w[COOKIE_SECRET JWT_SECRET].include?(entry['name'])
      reference = entry.dig('valueFrom', 'secretKeyRef')
      [entry['name'], reference&.fetch('name'), reference&.fetch('key')]
    end
    expected_session_refs = %w[COOKIE_SECRET JWT_SECRET].map { |key| [key, runtime_secret, key] }
    raise 'backend-family session secret contract mismatch' unless session_refs.sort == expected_session_refs.sort
    # Redis, per workload, for the same reason and with the same blind spot in
    # mind. The aggregate ESO key contract further down is satisfied the moment
    # *any* workload references REDIS_PASSWORD, which is exactly how the two
    # Jobs shipped without it while the backend and worker carried it — the same
    # shape of miss as the session secrets above.
    #
    # The host and port are checked separately, by the Service-endpoint table
    # below, which is strictly stronger than a declaration check: it requires
    # REDIS_HOST to name a Service in this overlay whose port is REDIS_PORT. So
    # only the credential is asserted here, and only that it arrives by
    # reference from this environment's runtime Secret under its own key. A
    # literal password in a manifest is refused by the shape of this assertion,
    # not merely discouraged.
    redis_refs = container.fetch('env', []).filter_map do |entry|
      next unless entry['name'] == 'REDIS_PASSWORD'
      reference = entry.dig('valueFrom', 'secretKeyRef')
      [entry['name'], reference&.fetch('name'), reference&.fetch('key')]
    end
    raise 'backend-family Redis secret contract mismatch' unless
      redis_refs == [['REDIS_PASSWORD', runtime_secret, 'REDIS_PASSWORD']]
    raise 'backend-family SMTP port must be submission 587' unless env_value(container, 'SMTP_PORT') == '587'
    raise 'backend-family SMTP host must remain deployment-supplied' unless env_value(container, 'SMTP_HOST')&.end_with?('.invalid')
    raise 'backend-family envelope sender must be synthetic' unless env_value(container, 'SMTP_ENVELOPE_FROM')&.end_with?('@example.com')
    raise 'backend-family contact recipient must be synthetic' unless env_value(container, 'CONTACT_MAIL_RECIPIENT')&.end_with?('@example.com')
    actual_merchant_environment = merchant_environment.keys.to_h do |name|
      [name, env_value(container, name)]
    end
    raise 'backend-family merchant legal contract mismatch' unless actual_merchant_environment == merchant_environment
  end

  # Selected by the repository they run, not by a hand-written list of names and
  # not by the digest form. The question this answers is "does everything
  # running the backend image supply what that image requires", so anything that
  # acquires the image later — a second Job, a sidecar, a debug ephemeral
  # container — is inside the guard the moment it appears, rather than the moment
  # someone remembers to add it.
  #
  # The reducer still accepts a tag-form reference, but nothing can reach this
  # point carrying one: the digest requirement above refuses an unpinned image
  # before the environment contract is ever consulted. That is deliberate
  # redundancy in the selector, not coverage this assertion still provides.
  backend_image_containers = documents.flat_map do |document|
    next [] unless (pod = pod_spec(document))
    pod_containers(pod)
      .select { |container| image_repository(container['image']) == BACKEND_IMAGE }
      .map { |container| [document.dig('metadata', 'name'), container] }
  end
  expected_backend_image_workloads = %W[
    plepic-backend#{suffix}
    plepic-catalogue-import#{suffix}
    plepic-predeploy#{suffix}
    plepic-worker#{suffix}
  ].sort
  # Which *workloads* run it, deduplicated on purpose: this assertion is about
  # the set of workloads, and comparing an undeduplicated list would conflate a
  # workload that should not run the image with a pod that runs it twice.
  #
  # The container count is bounded upstream, not here. The census refuses a fifth
  # backend-image container whatever form it is named in, so a second such
  # container inside one of these pods is now stopped before this point rather
  # than falling through to the environment contract below. That contract still
  # covers every container it can reach, which is the four the census permits.
  raise 'backend-image workload set mismatch' unless
    backend_image_containers.map(&:first).uniq.sort == expected_backend_image_workloads
  backend_image_containers.each do |name, container|
    where = "#{name}/#{container['name']}"
    declared = container.fetch('env', []).map { |entry| entry['name'] }
    missing = BACKEND_IMAGE_REQUIRED_ENVIRONMENT.reject { |variable| declared.include?(variable) }
    raise "#{where} does not supply the backend image's required environment: #{missing.join(' ')}" unless
      missing.empty?
    SAME_ORIGIN_CORS_VARIABLES.each do |variable|
      # Every occurrence, not the first. Kubernetes accepts a duplicate name and
      # the later assignment is the effective one, so a guard that stops at the
      # first match would read a value the container never sees.
      entries = container.fetch('env', []).select { |entry| entry['name'] == variable }
      raise "#{where} must declare #{variable} exactly once" unless entries.length == 1
      entry = entries.first
      # The `valueFrom` clause is retained redundancy and is named as such, so
      # this file states one position rather than two. An entry delivered by
      # reference has no `value` and is refused by the comparison beside it; an
      # entry carrying both is refused by the API server before it can reach a
      # pod. The site-host block below therefore writes the comparison alone,
      # and that is not a disagreement with this line.
      raise "#{where} must declare #{variable} as an explicit empty value" unless
        entry['value'] == '' && !entry.key?('valueFrom')
    end
  end

  # The API pod publishes work but must never consume it. In `server` mode the
  # separate worker is the only BullMQ consumer, which keeps recovery ordering
  # and worker health observable. The variable is a literal on the backend only:
  # copying it to the worker or either lifecycle Job changes what those commands
  # mean and is refused even when the value is still `server`.
  worker_mode_consumers = workloads(documents).filter_map do |workload|
    entries = pod_containers(pod_spec(workload)).flat_map do |container|
      container.fetch('env', []).select { |entry| entry['name'] == 'MEDUSA_WORKER_MODE' }
    end
    [workload.dig('metadata', 'name'), entries] unless entries.empty?
  end.to_h
  raise 'MEDUSA_WORKER_MODE must be literal server on the backend only' unless
    worker_mode_consumers == {
      "plepic-backend#{suffix}" => [{ 'name' => 'MEDUSA_WORKER_MODE', 'value' => 'server' }],
    }

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
  # Every backend-image workload reaches both data services, and the two Jobs
  # are not the exception they were written as. `medusa exec` boots the full
  # module container — `skipLoadingEntryPoints` skips routes and subscribers,
  # not modules — so the Redis event bus and workflow engine connect at module
  # load in a Job exactly as they do in a Deployment.
  #
  # This is stronger than asking whether the variables are declared: the host
  # must name a Service this overlay actually renders, and the port must be that
  # Service's port. A Job pointed at the other environment's Redis, or at the
  # right host on the wrong port, is refused here rather than at first sync.
  endpoint_workloads = {
    "plepic-backend#{suffix}" => %w[DATABASE REDIS],
    "plepic-worker#{suffix}" => %w[DATABASE REDIS],
    "plepic-predeploy#{suffix}" => %w[DATABASE REDIS],
    "plepic-catalogue-import#{suffix}" => %w[DATABASE REDIS],
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

  # The site's own identity — the one thing the storefront was shipped without.
  #
  # `storefront/src/config/hosts.ts` does not fail when these are absent. It
  # falls back to `https://example.com` for SITE_BASE_URL, derives
  # SITE_CANONICAL_HOST from it, and `readEnvList` answers `[]` for an absent
  # SITE_TEST_HOSTNAMES. A deployment that forgets them therefore starts,
  # serves, and looks healthy while emitting example.com as every canonical
  # URL, `og:url`, sitemap entry and `hreflang` alternate — and while
  # `isTestHost()` answers false for every request, which is precisely how the
  # test environment ships without `noindex`. Nothing crashes and nothing warns.
  # That is the failure a manifest contract has to catch, because the
  # application deliberately cannot: hosts.ts's own note says "nothing here is
  # optional-and-silently-absent, because a silently absent canonical host is
  # how a redirect loop or an un-canonicalised duplicate page ships unnoticed."
  #
  # Live declares SITE_TEST_HOSTNAMES empty rather than omitting it, on the same
  # reasoning as STORE_CORS/ADMIN_CORS/AUTH_CORS above: `readEnvList` cannot
  # tell empty from absent, so the value costs nothing at runtime and buys the
  # reviewer the difference between "live has no unindexed hostname" as a stated
  # decision and as an omission. It also lets this contract require all three in
  # both environments, so the live/test difference is a *value* difference a
  # diff shows, never a presence difference a diff has to be read for.
  # Read across every container of the storefront pod, not container 0. The
  # sibling newsletter guards above do the same, for the same reason: a
  # sidecar's environment is as real as container 0's, and container 0 already
  # carrying the expected value is exactly what would hide a second declaration.
  storefront_containers = pod_containers(pod_spec(resource(documents, 'Deployment', "plepic-storefront#{suffix}")))
  site_hosts.each do |name, expected|
    # Every occurrence, not the first: Kubernetes accepts a duplicate name and
    # the later assignment wins, so a guard that stopped at the first match
    # would read a hostname the container never sees.
    entries = storefront_containers.flat_map do |container|
      container.fetch('env', []).select { |entry| entry['name'] == name }
    end
    raise "storefront must declare #{name} exactly once" unless entries.length == 1
    # A literal, and never a reference. None of the three is a credential, and a
    # `valueFrom` would move the site's public identity out of the one place a
    # reviewer of this repository can read it. That is not a separate `raise`,
    # because an entry delivered by reference carries no `value` at all and this
    # comparison refuses it on the spot — a `raise` for it could never be
    # reached, and an unreachable assertion is one a future edit deletes in
    # silence. (The CORS block above keeps an explicit `valueFrom` clause beside
    # the same kind of comparison. It is retained redundancy, not a contrary
    # position: an entry carrying `value` *and* `valueFrom` is refused by the
    # API server before it can reach a pod, so neither guard is what stands
    # between this repository and that mistake.)
    #
    # Compared as a list rather than through `entries.first`, so that deleting
    # the count assertion above leaves a clean refusal here instead of a
    # `NoMethodError` on nil — a kill test should go red for the property it
    # removed, not for the crash that followed it.
    raise "storefront #{name} mismatch" unless entries.map { |entry| entry['value'] } == [expected]
  end

  # Three properties of the option table itself, and the reason they are sited
  # here rather than over the rendered values.
  #
  # Everything above compares a rendered value to the table, which refuses an
  # overlay that has drifted from the table and nothing else. It cannot refuse
  # the edit that matters: change a value in the overlay and update the table in
  # the same commit — which an exact-equality contract *forces* an editor to do
  # — and both sides move together with the suite green. An assertion over a
  # rendered value that the equality already refuses is decoration; the same
  # assertion over the table constrains what a future editor may write in it.
  # These three are therefore written over `site_hosts`, and their kill tests
  # mutate the overlay and the table in lockstep, the way a real edit would.

  # *Reserved names only.* Not an aesthetic rule: the real per-environment
  # hostnames are injected from Orange and this repository is public. Applied to
  # every hostname the table names, the members of the test-hostname list
  # included, because a list is as good a place to put a real name as a scalar.
  declared_site_hostnames =
    [['SITE_BASE_URL', site_base_url_host(site_hosts)],
     ['SITE_CANONICAL_HOST', site_hosts.fetch('SITE_CANONICAL_HOST')]] +
    site_host_list(site_hosts.fetch('SITE_TEST_HOSTNAMES')).map { |host| ['SITE_TEST_HOSTNAMES', host] }
  unreserved_site_hostnames = declared_site_hostnames
    .reject { |_source, host| RESERVED_HOSTNAME.match?(host.to_s) }
  raise "site hostnames must be reserved example names: #{unreserved_site_hostnames.inspect}" unless
    unreserved_site_hostnames.empty?

  # *The canonical host is the base URL's host.* hosts.ts derives the canonical
  # host from the base URL when SITE_CANONICAL_HOST is absent, so two declared
  # values that disagree are a state the application never produces on its own:
  # canonical links pointing at one origin while requests are canonicalised to
  # another.
  raise "#{environment} canonical host must be the base URL's host" unless
    site_hosts.fetch('SITE_CANONICAL_HOST') == site_base_url_host(site_hosts)

  # *The `noindex` invariant.* SITE_TEST_HOSTNAMES must contain every hostname
  # the test storefront answers to — see site_answered_hostnames for why that,
  # and not "the canonical host is in the list", is the rule. A hostname the
  # test environment serves and does not list is `isTestHost()` false for every
  # request to it, which is `proxy.ts` sending no `X-Robots-Tag`, an allow-all
  # `robots.txt`, `robots: {index: true}` in the page metadata, and analytics no
  # longer suppressed. "The test environment is never indexed" is a stated
  # completion criterion of this plan, and this is the only thing in this
  # repository that holds it.
  #
  # Live gets the mirror image rather than nothing. Its list is empty, and the
  # failure that empty value exists to prevent is the opposite one: a live
  # hostname that appears in it is a live site serving `noindex` to every
  # crawler, silently, with every page still rendering perfectly.
  answered_hostnames = site_answered_hostnames(site_hosts)
  listed_test_hostnames = site_host_list(site_hosts.fetch('SITE_TEST_HOSTNAMES'))
  if environment == 'test'
    unlisted = answered_hostnames - listed_test_hostnames
    raise "the test storefront answers to hostnames its test-hostname list omits: #{unlisted.inspect}" unless
      unlisted.empty?
  else
    indexable_but_listed = answered_hostnames & listed_test_hostnames
    raise "#{environment} declares a hostname it answers to unindexable: #{indexable_but_listed.inspect}" unless
      indexable_but_listed.empty?
  end

  # Only the storefront. These three configure the public site's identity, and
  # nothing else renders a canonical URL, a sitemap, or a `noindex`. A copy on
  # the backend or a Job is drift with no reader — and, worse, a second place a
  # future edit can update instead of this one.
  site_host_names = site_hosts.keys
  site_host_consumers = workloads(documents).filter_map do |workload|
    containers = pod_containers(pod_spec(workload))
    declared = site_host_names.select { |name| env_present?(containers, name) }
    [workload.dig('metadata', 'name'), declared.sort] unless declared.empty?
  end.to_h
  raise 'the site host configuration must reach only the storefront' unless site_host_consumers == {
    "plepic-storefront#{suffix}" => site_host_names.sort,
  }

  # Analytics identity is *forbidden here*, in both environments. That is a
  # different rule from every placeholder above rather than a stricter one: the
  # site hosts are values this repository carries in reserved form and Orange
  # replaces, and this one is a value this repository must not carry in any
  # form.
  #
  # `ANALYTICS_MEASUREMENT_ID` is the single variable the storefront reads for
  # it — `storefront/src/config/runtime-config.ts` resolves it to `null` when
  # absent, and `ConsentManager` never mounts the loader on a null measurement
  # ID — so presence is the whole property and there is nothing else to name.
  #
  # One tracked line declaring it in `base/` breaks two Global Constraints at
  # once, and did: executed against the previous version of this file it gave
  # `exit=0` and "Plepic manifest contract tests passed", with a GA4 identifier
  # rendered into *both* overlays. It is an account identifier in a public
  # repository, and — because the base is shared — analytics reaching the test
  # environment, which the plan says has no analytics at all.
  #
  # Nothing else in this file could see it, which is why the rule is written
  # rather than assumed. The whole-file address scan needs a `local-part@`, so a
  # bare measurement ID never enters ADDRESS_SHAPE; the reserved-name boundary
  # is applied to the three SITE_* hostnames and a GA4 ID is not a hostname; and
  # there is no shape a measurement ID could fail, because it is an opaque
  # account identifier rather than a structured name.
  #
  # A presence ban rather than a placeholder, and it costs Task 6 nothing.
  # Absence is the *correct* configuration for test, so there is nothing there
  # to placehold. There is no reserved-example GA4 ID the way there is a
  # reserved example domain, so a placeholder would be a real-looking fake in a
  # public repository bought for no gain. And live's real value is delivered as
  # an Ansible-rendered patch on the Argo CD Application, which never enters
  # this repository at all — see "What Task 6 must inject" in the README.
  #
  # Presence, not value, so an ID arriving by `valueFrom` is refused too: ESO is
  # the wrong path for a non-credential, and the README says so.
  analytics_identity_consumers = workloads(documents).filter_map do |workload|
    containers = pod_containers(pod_spec(workload))
    workload.dig('metadata', 'name') if env_present?(containers, 'ANALYTICS_MEASUREMENT_ID')
  end.sort
  raise "analytics identity must never be tracked here: #{analytics_identity_consumers.inspect}" unless
    analytics_identity_consumers.empty?

  # The Medusa publishable key, by the name the storefront actually reads.
  #
  # `storefront/src/config/runtime-env.ts` lists MEDUSA_PUBLISHABLE_API_KEY, and
  # `src/lib/medusa-client.ts` throws "MEDUSA_PUBLISHABLE_API_KEY is required
  # for Store API requests" without it. These manifests supplied
  # MEDUSA_PUBLISHABLE_KEY — the right Secret, the right key, the wrong variable
  # — so ESO projected the credential correctly and every Store API call from
  # the storefront would still have failed. The aggregate Secret contract below
  # cannot see this: it compares Secret names and keys, and both were right.
  # Across every container of the pod, for the reason the site-host read above
  # gives: a second declaration in a sidecar is invisible to a container-0 read,
  # and this assertion exists precisely because the wrong *name* was the defect.
  publishable_entries = storefront_containers.flat_map do |container|
    container.fetch('env', []).select { |entry| entry['name'].to_s.start_with?('MEDUSA_PUBLISHABLE') }
  end
  publishable_secret = environment == 'test' ? 'plepic-test-publishable-key' : 'plepic-publishable-key'
  raise 'storefront publishable-key variable contract mismatch' unless
    publishable_entries.map { |entry| [entry['name'], entry.dig('valueFrom', 'secretKeyRef')] } ==
    [['MEDUSA_PUBLISHABLE_API_KEY', { 'name' => publishable_secret, 'key' => 'publishableKey' }]]

  # Redirects are runtime site configuration, but the storefront reads them as
  # a file and memoizes the parsed result. Project exactly one purpose-specific
  # Secret key at the literal path the application reads. The explicit item set
  # prevents the storefront from receiving any later key added to that Secret.
  redirect_secret = environment == 'test' ? 'plepic-test-redirect-map' : 'plepic-redirect-map'
  redirect_path_consumers = workloads(documents).filter_map do |workload|
    entries = pod_containers(pod_spec(workload)).flat_map do |container|
      container.fetch('env', []).select { |entry| entry['name'] == 'REDIRECT_MAP_PATH' }
    end
    [workload.dig('metadata', 'name'), entries] unless entries.empty?
  end.to_h
  raise 'REDIRECT_MAP_PATH must be the literal projected path on the storefront only' unless
    redirect_path_consumers == {
      "plepic-storefront#{suffix}" => [{
        'name' => 'REDIRECT_MAP_PATH',
        'value' => '/var/run/plepic/redirect-map/redirect-map.json',
      }],
    }
  storefront = resource(documents, 'Deployment', "plepic-storefront#{suffix}")
  storefront_pod = pod_spec(storefront)
  redirect_volumes = storefront_pod.fetch('volumes', []).select { |volume| volume['name'] == 'redirect-map' }
  raise 'storefront redirect-map Secret volume contract mismatch' unless redirect_volumes == [{
    'name' => 'redirect-map',
    'secret' => {
      'secretName' => redirect_secret,
      'items' => [{ 'key' => 'redirect-map.json', 'path' => 'redirect-map.json' }],
    },
  }]
  redirect_mounts = storefront_containers.flat_map do |container|
    container.fetch('volumeMounts', []).select { |mount| mount['name'] == 'redirect-map' }
  end
  raise 'storefront redirect-map mount contract mismatch' unless redirect_mounts == [{
    'name' => 'redirect-map',
    'mountPath' => '/var/run/plepic/redirect-map',
    'readOnly' => true,
  }]
  redirect_secret_consumers = workloads(documents).filter_map do |workload|
    names = pod_spec(workload).fetch('volumes', []).filter_map do |volume|
      volume['name'] if volume.dig('secret', 'secretName') == redirect_secret
    end
    [workload.dig('metadata', 'name'), names.sort] unless names.empty?
  end.to_h
  raise 'redirect-map Secret must reach only the storefront volume' unless redirect_secret_consumers == {
    "plepic-storefront#{suffix}" => ['redirect-map'],
  }
  other_redirect_volume_consumers = workloads(documents).reject { |workload| workload.equal?(storefront) }.filter_map do |workload|
    pod = pod_spec(workload)
    has_mount = pod_containers(pod).any? do |container|
      container.fetch('volumeMounts', []).any? { |mount| mount['name'] == 'redirect-map' }
    end
    workload.dig('metadata', 'name') if has_mount || pod.fetch('volumes', []).any? { |volume| volume['name'] == 'redirect-map' }
  end
  raise 'redirect-map volume must reach only the storefront' unless other_redirect_volume_consumers.empty?
  runtime_secret = environment == 'test' ? 'plepic-test-runtime-credentials' : 'plepic-runtime-credentials'
  runtime_secret_volume_consumers = workloads(documents).filter_map do |workload|
    workload.dig('metadata', 'name') if pod_spec(workload).fetch('volumes', []).any? do |volume|
      volume.dig('secret', 'secretName') == runtime_secret
    end
  end
  raise 'runtime credentials must never be mounted as a Secret volume' unless runtime_secret_volume_consumers.empty?

  # The expected archive digest is cadenced state, not a tracked placeholder.
  # It comes from its own one-key ESO projection, explicitly and only on the
  # suspended import Job. Exact hash equality rejects a literal, an optional
  # reference, a wrong key, or a second delivery of the same variable. This runs
  # before the aggregate Secret census so those failures are named precisely.
  import_expectation_secret = environment == 'test' ?
    'plepic-test-import-expectation' : 'plepic-import-expectation'
  digest_consumers = workloads(documents).filter_map do |workload|
    entries = pod_containers(pod_spec(workload)).flat_map do |container|
      container.fetch('env', []).select { |entry| entry['name'] == 'CATALOGUE_IMPORT_ARCHIVE_SHA256' }
    end
    [workload.dig('metadata', 'name'), entries] unless entries.empty?
  end.to_h
  raise 'catalogue import archive digest delivery contract mismatch' unless digest_consumers == {
    "plepic-catalogue-import#{suffix}" => [{
      'name' => 'CATALOGUE_IMPORT_ARCHIVE_SHA256',
      'valueFrom' => {
        'secretKeyRef' => {
          'name' => import_expectation_secret,
          'key' => 'CATALOGUE_IMPORT_ARCHIVE_SHA256',
        },
      },
    }],
  }
  import_expectation_consumers = workloads(documents).filter_map do |workload|
    references = pod_containers(pod_spec(workload)).flat_map do |container|
      container.fetch('env', []).filter_map do |entry|
        reference = entry.dig('valueFrom', 'secretKeyRef')
        [entry['name'], reference['key']] if reference&.fetch('name') == import_expectation_secret
      end
    end
    [workload.dig('metadata', 'name'), references] unless references.empty?
  end.to_h
  raise 'import-expectation Secret must reach only the catalogue import digest variable' unless
    import_expectation_consumers == {
      "plepic-catalogue-import#{suffix}" => [[
        'CATALOGUE_IMPORT_ARCHIVE_SHA256', 'CATALOGUE_IMPORT_ARCHIVE_SHA256',
      ]],
    }

  secret_references = Hash.new { |hash, key| hash[key] = [] }
  documents.each do |document|
    next unless (pod = pod_spec(document))
    pod_containers(pod).each do |container|
      container.fetch('env', []).each do |entry|
        reference = entry.dig('valueFrom', 'secretKeyRef')
        secret_references[reference['name']] << reference['key'] if reference
      end
    end
    pod.fetch('volumes', []).each do |volume|
      secret = volume['secret']
      next unless secret
      secret.fetch('items', []).each do |item|
        secret_references[secret['secretName']] << item['key']
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

  # The served media root and the import staging directory must be disjoint
  # subtrees of the assets PVC. They were once the same subtree, which made a
  # staged WooCommerce export — customer accounts, sessions and order history —
  # publicly downloadable under /static the moment an import left one behind.
  # Deleting the archive is the other half of that fix; this is the half that
  # holds when a future exit path forgets to.
  documents.each do |document|
    next unless (pod = pod_spec(document))
    name = document.dig('metadata', 'name')
    assets_volumes = pod.fetch('volumes', []).filter_map do |volume|
      volume['name'] if volume.dig('persistentVolumeClaim', 'claimName') == "plepic-assets#{suffix}"
    end
    next if assets_volumes.empty?
    pod_containers(pod).flat_map { |container| container.fetch('volumeMounts', []) }
      .select { |mount| assets_volumes.include?(mount['name']) }
      .each do |mount|
        case mount['mountPath']
        when '/app/static'
          raise "#{name} must serve media from the assets PVC's media subtree" unless
            mount['subPath'] == 'media'
        when '/var/lib/plepic/import'
          raise "#{name} must stage imports in the assets PVC's import subtree" unless
            mount['subPath'] == 'import'
        else
          raise "#{name} mounts the assets PVC at an undeclared path #{mount['mountPath']}"
        end
      end
  end

  # The mount layout alone does not confine the archive: the import reads its
  # staging path from CATALOGUE_IMPORT_ARCHIVE_PATH, so an override could put the
  # export back under the served root while every mount above stays correct.
  # Either the variable is absent, and the application's own default under the
  # staging mount applies, or it resolves inside that mount.
  # Every occurrence, not the first. Kubernetes does not reject a duplicate env
  # name and the later assignment is the effective one, so a guard that stops at
  # the first match reads a value the container will never see.
  import_job = resource(documents, 'Job', "plepic-catalogue-import#{suffix}")
  pod_containers(pod_spec(import_job)).each do |container|
    container.fetch('env', []).each do |entry|
      next unless entry['name'] == 'CATALOGUE_IMPORT_ARCHIVE_PATH'
      declared = entry['value']
      # `$(OTHER)` is expanded from an earlier entry in the same container, so a
      # literal that satisfies the prefix can still resolve outside the mount.
      raise 'the catalogue import archive path must resolve inside the import mount' unless
        declared.is_a?(String) && declared.start_with?('/var/lib/plepic/import/') &&
        !declared.include?('/../') && !declared.end_with?('/..') &&
        !declared.include?('$(')
    end
  end

  # The import's environment identity, which nothing supplied.
  #
  # `readCatalogueImportRuntimeConfig` requires CATALOGUE_IMPORT_ENVIRONMENT to
  # be exactly `live` or `test` and raises the `expected-value-unset` refusal
  # otherwise, so the Job as rendered could not have succeeded in either
  # environment — it would have staged the archive, refused, disposed of it and
  # exited non-zero. It is a per-environment literal with no privacy, credential
  # or cross-repository dimension, exactly the class `DATABASE_NAME` already is,
  # so it belongs here rather than in the deferred set. Its companion
  # CATALOGUE_IMPORT_ARCHIVE_SHA256 does not: that is a per-archive value, and a
  # placeholder for it would be a plausible-looking wrong digest.
  #
  # Asserted as the environment's own name, not merely as one of the two. The
  # value's whole purpose is to refuse an archive recorded for the other
  # environment, so `test` carrying `live` is the mistake worth catching, and it
  # is the one a copied patch block produces.
  import_environment_entries = pod_containers(pod_spec(import_job)).flat_map do |container|
    container.fetch('env', []).select { |entry| entry['name'] == 'CATALOGUE_IMPORT_ENVIRONMENT' }
  end
  raise 'the catalogue import must declare CATALOGUE_IMPORT_ENVIRONMENT exactly once' unless
    import_environment_entries.length == 1
  # The declared values as a list, in the assertion and in its message, so that
  # deleting the count assertion above leaves a clean refusal here rather than a
  # `NoMethodError` on an empty list.
  declared_import_environments = import_environment_entries.map { |entry| entry['value'] }
  raise "catalogue import environment identity mismatch: #{declared_import_environments.inspect}" unless
    declared_import_environments == [environment]

  # `envFrom` would deliver the same variable without ever appearing in `env`,
  # and a `secretRef` would additionally pull every key of a Secret into the pod
  # where the ESO key contract — which walks `env[].valueFrom.secretKeyRef` —
  # cannot see it. Nothing here uses it, so refusing it outright costs nothing.
  workloads(documents).each do |workload|
    pod_containers(pod_spec(workload)).each do |container|
      next if container.fetch('envFrom', []).empty?
      raise "#{workload.dig('metadata', 'name')} must not deliver environment through envFrom"
    end
  end

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
    'plepic-redirect-map' => ['redirect-map.json'],
    'plepic-import-expectation' => ['CATALOGUE_IMPORT_ARCHIVE_SHA256'],
  },
  pvc_sizes: { 'postgresql' => '20Gi', 'redis' => '2Gi', 'assets' => '10Gi' },
  resources: live_resources,
  # Reserved names, and an explicitly empty test-hostname list: live indexes
  # every hostname it answers to. See the block in assert_manifest for why the
  # empty value is declared rather than omitted.
  site_hosts: {
    'SITE_BASE_URL' => 'https://example.com',
    'SITE_CANONICAL_HOST' => 'example.com',
    'SITE_TEST_HOSTNAMES' => '',
  },
}
test_options = {
  environment: 'test', namespace: 'plepic-test', suffix: '-test',
  ports: { 'storefront' => 8111, 'backend' => 8112 }, database: 'plepic_test',
  secrets: {
    'plepic-test-runtime-credentials' => runtime_keys,
    'plepic-test-database-admin' => admin_keys,
    'plepic-test-publishable-key' => ['publishableKey'],
    'plepic-test-redirect-map' => ['redirect-map.json'],
    'plepic-test-import-expectation' => ['CATALOGUE_IMPORT_ARCHIVE_SHA256'],
  },
  pvc_sizes: { 'postgresql' => '5Gi', 'redis' => '1Gi', 'assets' => '2Gi' },
  resources: test_resources,
  # The test environment's canonical host is also the one entry in its own
  # test-hostname list. That identity is what makes isTestHost() true for every
  # request this deployment serves, and therefore what puts `noindex` on it.
  site_hosts: {
    'SITE_BASE_URL' => 'https://test.example.org',
    'SITE_CANONICAL_HOST' => 'test.example.org',
    'SITE_TEST_HOSTNAMES' => 'test.example.org',
  },
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

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'served media root back at the PVC root',
  "must serve media from the assets PVC's media subtree"
) do |documents|
  backend = resource(documents, 'Deployment', 'plepic-backend-test')
  pod_spec(backend).fetch('containers').each do |container|
    container.fetch('volumeMounts', []).each do |mount|
      mount.delete('subPath') if mount['mountPath'] == '/app/static'
    end
  end
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'import staged into the served media subtree',
  "must stage imports in the assets PVC's import subtree"
) do |documents|
  import_job = resource(documents, 'Job', 'plepic-catalogue-import-test')
  pod_spec(import_job).fetch('containers').each do |container|
    container.fetch('volumeMounts', []).each do |mount|
      mount['subPath'] = 'media' if mount['mountPath'] == '/var/lib/plepic/import'
    end
  end
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'archive path overridden into the served media root',
  'archive path must resolve inside the import mount'
) do |documents|
  import_job = resource(documents, 'Job', 'plepic-catalogue-import-test')
  pod_spec(import_job).fetch('containers').first.fetch('env') <<
    { 'name' => 'CATALOGUE_IMPORT_ARCHIVE_PATH', 'value' => '/app/static/catalogue.tar.gz' }
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'archive path duplicated with a hostile second entry',
  'archive path must resolve inside the import mount'
) do |documents|
  import_job = resource(documents, 'Job', 'plepic-catalogue-import-test')
  environment = pod_spec(import_job).fetch('containers').first.fetch('env')
  environment << { 'name' => 'CATALOGUE_IMPORT_ARCHIVE_PATH',
                   'value' => '/var/lib/plepic/import/catalogue.tar.gz' }
  environment << { 'name' => 'CATALOGUE_IMPORT_ARCHIVE_PATH',
                   'value' => '/app/static/catalogue.tar.gz' }
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'archive path escaping through variable expansion',
  'archive path must resolve inside the import mount'
) do |documents|
  import_job = resource(documents, 'Job', 'plepic-catalogue-import-test')
  environment = pod_spec(import_job).fetch('containers').first.fetch('env')
  environment.unshift({ 'name' => 'ESCAPE', 'value' => '../../../app/static' })
  environment << { 'name' => 'CATALOGUE_IMPORT_ARCHIVE_PATH',
                   'value' => '/var/lib/plepic/import/$(ESCAPE)/catalogue.tar.gz' }
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'runtime Secret pulled in wholesale through envFrom',
  'must not deliver environment through envFrom'
) do |documents|
  import_job = resource(documents, 'Job', 'plepic-catalogue-import-test')
  pod_spec(import_job).fetch('containers').first['envFrom'] =
    [{ 'secretRef' => { 'name' => 'plepic-test-runtime-credentials' } }]
end

# The backend in `server` mode is the publisher half of a deliberately split
# topology. Copying the same setting to the worker or either Job is not harmless
# duplication: it changes the command's runtime mode and leaves no consumer.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'server mode leaked from the backend to the worker',
  'MEDUSA_WORKER_MODE must be literal server on the backend only'
) do |documents|
  worker = resource(documents, 'Deployment', 'plepic-worker-test')
  pod_spec(worker).fetch('containers').first.fetch('env') <<
    { 'name' => 'MEDUSA_WORKER_MODE', 'value' => 'server' }
end

# The failure mode the ten paths exist for, in the form it will actually recur:
# a list shortened to what the error log printed. `locking` is one of the two
# entries the log hides behind an earlier sibling, so dropping it is exactly the
# edit a future reader working from the log would make.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a module migrations directory dropped from the mount set',
  'predeploy module migrations mount contract mismatch'
) do |documents|
  predeploy = resource(documents, 'Job', 'plepic-predeploy-test')
  pod_spec(predeploy).fetch('containers').first.fetch('volumeMounts')
    .reject! { |mount| mount['mountPath'] == '/node_modules/@medusajs/locking/dist/migrations' }
end

# Writable directories inside a package tree, for a command that only reads
# them. `db:generate` is the one that writes migrations and it never runs
# in-cluster.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a module migrations mount made writable',
  'predeploy module migrations mount contract mismatch'
) do |documents|
  predeploy = resource(documents, 'Job', 'plepic-predeploy-test')
  pod_spec(predeploy).fetch('containers').first.fetch('volumeMounts')
    .find { |mount| mount['mountPath'] == '/app/src/notifications/migrations' }['readOnly'] = false
end

# Every mount pointed at the same `emptyDir` root. Nothing about the pod's shape
# objects — one volume, ten paths, all read-only — and the migrator would still
# find ten empty directories today. It is refused because they are then one
# directory under ten names, so the first module to ship migrations into its own
# subtree would find another module's.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the module migrations mounts collapsed onto one shared subPath',
  'predeploy module migrations mount contract mismatch'
) do |documents|
  predeploy = resource(documents, 'Job', 'plepic-predeploy-test')
  pod_spec(predeploy).fetch('containers').first.fetch('volumeMounts').each do |mount|
    mount.delete('subPath') if mount['name'] == 'module-migrations'
  end
end

# A backing store that outlives the Job. These directories are scratch by
# definition — they exist so a glob finds nothing — and backing them with the
# assets PVC would put ten empty directories in the volume that serves media and
# stages imports.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the module migrations volume backed by the assets PVC',
  'predeploy module migrations volume contract mismatch'
) do |documents|
  predeploy = resource(documents, 'Job', 'plepic-predeploy-test')
  volume = pod_spec(predeploy).fetch('volumes').find { |candidate| candidate['name'] == 'module-migrations' }
  volume.delete('emptyDir')
  volume['persistentVolumeClaim'] = { 'claimName' => 'plepic-assets-test' }
end

# The copy-paste. The worker runs the same image and never calls the Migrator,
# so this is inert at best; the point is that it stays refused rather than
# becoming the shape every workload drifts towards.
#
# Deep-copied rather than aliased. Appending the predeploy Job's own hashes to
# the worker would make one object appear in two documents, which
# `YAML.dump_stream` writes as an anchor in the first and an alias in the second
# — and anchors do not cross document boundaries, so the reload fails on a
# dangling alias before any assertion here is reached.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the module migrations mounts copied onto the worker',
  'the module migrations volume must reach only the predeploy Job'
) do |documents|
  predeploy_pod = pod_spec(resource(documents, 'Job', 'plepic-predeploy-test'))
  worker_pod = pod_spec(resource(documents, 'Deployment', 'plepic-worker-test'))
  copied = lambda do |value|
    Marshal.load(Marshal.dump(value))
  end
  worker_pod.fetch('volumes') << copied.call(
    predeploy_pod.fetch('volumes').find { |volume| volume['name'] == 'module-migrations' }
  )
  worker_pod.dig('containers', 0, 'volumeMounts').concat(copied.call(
    predeploy_pod.dig('containers', 0, 'volumeMounts')
      .select { |mount| mount['name'] == 'module-migrations' }
  ))
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the redirect map sourced from the runtime credential Secret',
  'storefront redirect-map Secret volume contract mismatch'
) do |documents|
  storefront = resource(documents, 'Deployment', 'plepic-storefront-test')
  volume = pod_spec(storefront).fetch('volumes').find { |candidate| candidate['name'] == 'redirect-map' }
  volume.fetch('secret')['secretName'] = 'plepic-test-runtime-credentials'
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the redirect map Secret exposing every key instead of one projected item',
  'storefront redirect-map Secret volume contract mismatch'
) do |documents|
  storefront = resource(documents, 'Deployment', 'plepic-storefront-test')
  volume = pod_spec(storefront).fetch('volumes').find { |candidate| candidate['name'] == 'redirect-map' }
  volume.fetch('secret').delete('items')
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the redirect map mount made writable',
  'storefront redirect-map mount contract mismatch'
) do |documents|
  storefront = resource(documents, 'Deployment', 'plepic-storefront-test')
  mount = pod_spec(storefront).dig('containers', 0, 'volumeMounts')
    .find { |candidate| candidate['name'] == 'redirect-map' }
  mount['readOnly'] = false
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the redirect-map Secret copied onto the worker under another volume name',
  'redirect-map Secret must reach only the storefront volume'
) do |documents|
  worker = resource(documents, 'Deployment', 'plepic-worker-test')
  pod = pod_spec(worker)
  pod.fetch('volumes') << {
    'name' => 'retired-hosts',
    'secret' => {
      'secretName' => 'plepic-test-redirect-map',
      'items' => [{ 'key' => 'redirect-map.json', 'path' => 'redirect-map.json' }],
    },
  }
  pod.dig('containers', 0, 'volumeMounts') << {
    'name' => 'retired-hosts', 'mountPath' => '/var/run/plepic/retired-hosts', 'readOnly' => true,
  }
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the test redirect map reference left unsuffixed',
  'storefront redirect-map Secret volume contract mismatch'
) do |documents|
  storefront = resource(documents, 'Deployment', 'plepic-storefront-test')
  volume = pod_spec(storefront).fetch('volumes').find { |candidate| candidate['name'] == 'redirect-map' }
  volume.fetch('secret')['secretName'] = 'plepic-redirect-map'
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the catalogue import archive digest embedded as a literal',
  'catalogue import archive digest delivery contract mismatch'
) do |documents|
  import_job = resource(documents, 'Job', 'plepic-catalogue-import-test')
  entry = pod_spec(import_job).dig('containers', 0, 'env')
    .find { |candidate| candidate['name'] == 'CATALOGUE_IMPORT_ARCHIVE_SHA256' }
  entry.delete('valueFrom')
  entry['value'] = '0' * 64
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the catalogue import archive digest read from the runtime Secret',
  'catalogue import archive digest delivery contract mismatch'
) do |documents|
  import_job = resource(documents, 'Job', 'plepic-catalogue-import-test')
  entry = pod_spec(import_job).dig('containers', 0, 'env')
    .find { |candidate| candidate['name'] == 'CATALOGUE_IMPORT_ARCHIVE_SHA256' }
  entry.dig('valueFrom', 'secretKeyRef')['name'] = 'plepic-test-runtime-credentials'
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the test import-expectation reference left unsuffixed',
  'catalogue import archive digest delivery contract mismatch'
) do |documents|
  import_job = resource(documents, 'Job', 'plepic-catalogue-import-test')
  entry = pod_spec(import_job).dig('containers', 0, 'env')
    .find { |candidate| candidate['name'] == 'CATALOGUE_IMPORT_ARCHIVE_SHA256' }
  entry.dig('valueFrom', 'secretKeyRef')['name'] = 'plepic-import-expectation'
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the import-expectation Secret consumed by the worker under another variable name',
  'import-expectation Secret must reach only the catalogue import digest variable'
) do |documents|
  worker = resource(documents, 'Deployment', 'plepic-worker-test')
  pod_spec(worker).dig('containers', 0, 'env') << {
    'name' => 'UNUSED_IMPORT_EXPECTATION',
    'valueFrom' => {
      'secretKeyRef' => {
        'name' => 'plepic-test-import-expectation',
        'key' => 'CATALOGUE_IMPORT_ARCHIVE_SHA256',
      },
    },
  }
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the import expectation Secret pulled in wholesale through envFrom',
  'must not deliver environment through envFrom'
) do |documents|
  import_job = resource(documents, 'Job', 'plepic-catalogue-import-test')
  pod_spec(import_job).fetch('containers').first['envFrom'] =
    [{ 'secretRef' => { 'name' => 'plepic-test-import-expectation' } }]
end

# The state the catalogue import shipped in: no environment identity at all.
# Nothing else in the file reads the variable, and the application's refusal is
# a Job exit nobody watches for a Job that is suspended by default.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the catalogue import missing its environment identity',
  'the catalogue import must declare CATALOGUE_IMPORT_ENVIRONMENT exactly once'
) do |documents|
  import_job = resource(documents, 'Job', 'plepic-catalogue-import-test')
  pod_spec(import_job).fetch('containers').first.fetch('env')
    .reject! { |entry| entry['name'] == 'CATALOGUE_IMPORT_ENVIRONMENT' }
end

# The identity present, well formed, and belonging to the other environment —
# what a copied patch block produces. The application would accept it and refuse
# only on the archive's recorded identity, so the mistake surfaces as a refusal
# about the archive rather than about the Job that is misconfigured.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the test catalogue import claiming the live environment identity',
  'catalogue import environment identity mismatch'
) do |documents|
  import_job = resource(documents, 'Job', 'plepic-catalogue-import-test')
  pod_spec(import_job).fetch('containers').first.fetch('env').each do |entry|
    entry['value'] = 'live' if entry['name'] == 'CATALOGUE_IMPORT_ENVIRONMENT'
  end
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a backend-image workload missing a CORS variable',
  "plepic-worker-test/worker does not supply the backend image's required environment: STORE_CORS"
) do |documents|
  worker = resource(documents, 'Deployment', 'plepic-worker-test')
  pod_spec(worker).fetch('containers').first.fetch('env')
    .reject! { |entry| entry['name'] == 'STORE_CORS' }
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the migration Job missing a session secret',
  'backend-family session secret contract mismatch'
) do |documents|
  predeploy = resource(documents, 'Job', 'plepic-predeploy-test')
  pod_spec(predeploy).fetch('containers').first.fetch('env')
    .reject! { |entry| entry['name'] == 'JWT_SECRET' }
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a session secret read from the wrong Secret',
  'backend-family session secret contract mismatch'
) do |documents|
  import_job = resource(documents, 'Job', 'plepic-catalogue-import-test')
  pod_spec(import_job).fetch('containers').first.fetch('env').each do |entry|
    next unless entry['name'] == 'COOKIE_SECRET'
    entry['valueFrom']['secretKeyRef']['name'] = 'plepic-test-database-admin'
  end
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a CORS origin naming a hostname',
  'must declare ADMIN_CORS as an explicit empty value'
) do |documents|
  backend = resource(documents, 'Deployment', 'plepic-backend-test')
  pod_spec(backend).fetch('containers').first.fetch('env').each do |entry|
    entry['value'] = 'https://admin.example.test' if entry['name'] == 'ADMIN_CORS'
  end
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a CORS origin delivered by reference instead of declared empty',
  'must declare AUTH_CORS as an explicit empty value'
) do |documents|
  backend = resource(documents, 'Deployment', 'plepic-backend-test')
  pod_spec(backend).fetch('containers').first.fetch('env').each do |entry|
    next unless entry['name'] == 'AUTH_CORS'
    entry.delete('value')
    entry['valueFrom'] =
      { 'secretKeyRef' => { 'name' => 'plepic-test-runtime-credentials', 'key' => 'COOKIE_SECRET' } }
  end
end

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a CORS variable duplicated with a non-empty second entry',
  'must declare STORE_CORS exactly once'
) do |documents|
  worker = resource(documents, 'Deployment', 'plepic-worker-test')
  pod_spec(worker).fetch('containers').first.fetch('env') <<
    { 'name' => 'STORE_CORS', 'value' => 'https://store.example.test' }
end

# ---------------------------------------------------------------------------
# Redis reaching the two Jobs.
#
# Each mutation below is reachable by exactly one of the assertions this change
# added or widened. That is the point of writing them one property at a time:
# an assertion whose mutation is also caught by an older guard is one a future
# edit can delete with the suite staying green, which is how a guard in this
# file ended up with no kill test behind it before.
# ---------------------------------------------------------------------------

# The NetworkPolicy half, ingress. Nothing else in the contract reads this list,
# so reverting it to the two Deployments is refused only here — and it is the
# revert that matters, because the Jobs' environment can be perfectly correct
# while the policy silently drops every packet they send.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'Redis ingress that does not admit the migration Job',
  'Redis ingress mismatch'
) do |documents|
  redis = resource(documents, 'NetworkPolicy', 'allow-redis-ingress-test')
  redis.fetch('spec').fetch('ingress').first.fetch('from').reject! do |peer|
    peer.dig('podSelector', 'matchLabels', 'app.kubernetes.io/component') == 'predeploy'
  end
end

# The egress half. Separate policy, separate selector, separate mutation: a
# widened ingress with an unwidened egress is still a Job that cannot connect,
# and one assertion covering both would have let that state through.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'Redis egress that does not admit the two Jobs',
  'Redis egress selector mismatch'
) do |documents|
  redis_egress = resource(documents, 'NetworkPolicy', 'allow-redis-egress-test')
  redis_egress.dig('spec', 'podSelector', 'matchExpressions').first['values'] = %w[backend worker]
end

# The exact state this repository shipped in before the `backup` component was
# added: every workload that talks to the Internet admitted, and the one Job
# whose entire purpose is to upload off-cluster left out. Nothing else notices —
# the backup Jobs are rendered by Orange and appear in no document here, so the
# only trace of them in this repository is the two policy selectors that name
# them, and `allow-postgresql-egress` already named this one.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'HTTPS egress that does not admit the backup Jobs',
  'HTTPS workload selector mismatch'
) do |documents|
  https = resource(documents, 'NetworkPolicy', 'allow-https-egress-test')
  https.dig('spec', 'podSelector', 'matchExpressions').first['values'] =
    %w[backend worker storefront predeploy catalogue-import]
end

# The other direction, and the reason the assertion is written as set equality.
#
# `recovery` is the most plausible name a later author adds here, because it
# already sits beside `backup` in `allow-postgresql-egress` and the symmetry
# looks like an oversight. It is not: the restore object is fetched and
# decrypted on the controller and mounted into the Job from a hostPath, so a
# restore Pod has no reason to reach the Internet, and this rule's peer is
# `0.0.0.0/0`. A membership test would accept this mutation in silence.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'HTTPS egress widened to the restore Jobs',
  'HTTPS workload selector mismatch'
) do |documents|
  https = resource(documents, 'NetworkPolicy', 'allow-https-egress-test')
  https.dig('spec', 'podSelector', 'matchExpressions').first['values'] << 'recovery'
end

# A Job missing REDIS_PASSWORD outright — the state both Jobs shipped in.
#
# The aggregate ESO key contract cannot see this: the backend and the worker
# still reference REDIS_PASSWORD, so the Secret's key set is unchanged and
# stays green. Only the per-workload assertion notices, which is the whole
# reason it is written per workload.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the migration Job missing the Redis credential',
  'backend-family Redis secret contract mismatch'
) do |documents|
  predeploy = resource(documents, 'Job', 'plepic-predeploy-test')
  pod_spec(predeploy).fetch('containers').first.fetch('env')
    .reject! { |entry| entry['name'] == 'REDIS_PASSWORD' }
end

# The same variable, present, from the right Secret, under the wrong key.
#
# Deliberately a key that Secret already projects, so the aggregate contract
# sees a name and key set it expects and reports nothing. The Job would start,
# authenticate to Redis with the database password, and fail at the first
# command — or, worse, succeed if the two ever matched.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the Redis credential read from the wrong key of the right Secret',
  'backend-family Redis secret contract mismatch'
) do |documents|
  import_job = resource(documents, 'Job', 'plepic-catalogue-import-test')
  pod_spec(import_job).fetch('containers').first.fetch('env').each do |entry|
    next unless entry['name'] == 'REDIS_PASSWORD'
    entry['valueFrom']['secretKeyRef']['key'] = 'DATABASE_PASSWORD'
  end
end

# A Job with no REDIS_HOST at all. Before this variable joined the backend
# image's required set, this state reached the Service-endpoint table and died
# on `key not found: "REDIS_HOST"` — the suite went red, but for a lookup rather
# than for the workload that is misconfigured. The mutation is the same; what it
# is now refused by, and what it says, are what changed.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the migration Job missing the Redis host',
  "plepic-predeploy-test/predeploy does not supply the backend image's required environment: REDIS_HOST"
) do |documents|
  predeploy = resource(documents, 'Job', 'plepic-predeploy-test')
  pod_spec(predeploy).fetch('containers').first.fetch('env')
    .reject! { |entry| entry['name'] == 'REDIS_HOST' }
end

# The port, on the other Job, so each of the two entries has a mutation of its
# own and neither can be deleted from the list with the suite staying green.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the catalogue import missing the Redis port',
  "plepic-catalogue-import-test/catalogue-import does not supply the backend image's required environment: REDIS_PORT"
) do |documents|
  import_job = resource(documents, 'Job', 'plepic-catalogue-import-test')
  pod_spec(import_job).fetch('containers').first.fetch('env')
    .reject! { |entry| entry['name'] == 'REDIS_PORT' }
end

# REDIS_HOST declared and pointing somewhere real that is not Redis. Every
# declaration check in this file is satisfied — the variable is present, it has
# a literal value, and it names a Service this overlay renders — so only the
# Service-endpoint table refuses it, on the port not matching.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a Job pointed at a Service that is not Redis',
  'plepic-predeploy-test has dangling REDIS Service endpoint'
) do |documents|
  predeploy = resource(documents, 'Job', 'plepic-predeploy-test')
  pod_spec(predeploy).fetch('containers').first.fetch('env').each do |entry|
    entry['value'] = 'plepic-postgresql-test' if entry['name'] == 'REDIS_HOST'
  end
end

# The other half of the endpoint check, on the other Job and the other field.
# A port that is not the Redis Service's port: the host is right, the variable
# is declared, and only the pairing is wrong — which is what the endpoint table
# compares and nothing else in this file does. Written against the second Job so
# each row of that table has a mutation of its own; a single mutation would have
# left the other row deletable with the suite green.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a Job pointed at the right Redis Service on the wrong port',
  'plepic-catalogue-import-test has dangling REDIS Service endpoint'
) do |documents|
  import_job = resource(documents, 'Job', 'plepic-catalogue-import-test')
  pod_spec(import_job).fetch('containers').first.fetch('env').each do |entry|
    entry['value'] = '6380' if entry['name'] == 'REDIS_PORT'
  end
end

# ---------------------------------------------------------------------------
# The site's host configuration.
#
# The failure these bound is silent by construction: hosts.ts falls back to
# `https://example.com` and to an empty test-hostname list, so every one of
# these mutations produces a storefront that starts and serves.
# ---------------------------------------------------------------------------

# A variable dropped. This is the state the storefront shipped in for all three.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the storefront missing its canonical host',
  'storefront must declare SITE_CANONICAL_HOST exactly once'
) do |documents|
  storefront = resource(documents, 'Deployment', 'plepic-storefront-test')
  pod_spec(storefront).fetch('containers').first.fetch('env')
    .reject! { |entry| entry['name'] == 'SITE_CANONICAL_HOST' }
end

# A duplicate carrying the *same* value, so the value assertion is satisfied and
# only the "exactly once" half objects. It matters because Kubernetes takes the
# last assignment: once duplication is tolerated, a second entry with a
# different value is a one-word edit away and reads as a no-op in review.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a site hostname list duplicated with an identical second entry',
  'storefront must declare SITE_TEST_HOSTNAMES exactly once'
) do |documents|
  storefront = resource(documents, 'Deployment', 'plepic-storefront-test')
  pod_spec(storefront).fetch('containers').first.fetch('env') <<
    { 'name' => 'SITE_TEST_HOSTNAMES', 'value' => 'test.example.org' }
end

# The base URL delivered by reference. The Secret and key are ones this overlay
# already projects, so the aggregate Secret contract is untouched and green; the
# site's public identity would simply have left the manifest, and the storefront
# would fall back to example.com if the projection were ever wrong. The value
# comparison is what refuses it — an entry with a `valueFrom` has no `value` —
# which is why there is no separate literal-delivery assertion above.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the base URL delivered by Secret reference instead of declared',
  'storefront SITE_BASE_URL mismatch'
) do |documents|
  storefront = resource(documents, 'Deployment', 'plepic-storefront-test')
  pod_spec(storefront).fetch('containers').first.fetch('env').each do |entry|
    next unless entry['name'] == 'SITE_BASE_URL'
    entry.delete('value')
    entry['valueFrom'] =
      { 'secretKeyRef' => { 'name' => 'plepic-test-runtime-credentials', 'key' => 'STRIPE_PUBLISHABLE_KEY' } }
  end
end

# The `noindex` regression itself, in the one form every structural check
# accepts: the variable is declared exactly once, as a literal, and is empty —
# which `readEnvList` reads as no test hostnames at all, so isTestHost() answers
# false for the test environment's own hostname and the test site becomes
# indexable. Only the per-environment value refuses it.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the test environment declaring an empty test-hostname list',
  'storefront SITE_TEST_HOSTNAMES mismatch'
) do |documents|
  storefront = resource(documents, 'Deployment', 'plepic-storefront-test')
  pod_spec(storefront).fetch('containers').first.fetch('env').each do |entry|
    entry['value'] = '' if entry['name'] == 'SITE_TEST_HOSTNAMES'
  end
end

# A second home for the site's identity. Harmless-looking, and the reason the
# scoping assertion exists: two places to update is one place to forget, and the
# worker renders no canonical URL for the value to have any effect on.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the base URL copied onto a workload that renders no page',
  'the site host configuration must reach only the storefront'
) do |documents|
  worker = resource(documents, 'Deployment', 'plepic-worker-test')
  pod_spec(worker).fetch('containers').first.fetch('env') <<
    { 'name' => 'SITE_BASE_URL', 'value' => 'https://test.example.org' }
end

# The one line that breaks two Global Constraints at once, in the form it would
# actually be committed. Executed against the previous version of this file, as
# a single `- {name: ANALYTICS_MEASUREMENT_ID, value: ...}` entry in
# `base/storefront.yaml`: `exit=0`, "Plepic manifest contract tests passed", and
# the identifier rendered into *both* overlays — an account identifier in a
# public repository, and analytics reaching the environment the plan says has
# none.
#
# Written on live because that is the environment with a real value to be
# tempted by; the base is shared, so the committed form of this mistake fails
# here and on test alike, and the assertion branches on neither.
#
# The identifier is self-describing rather than plausible. The rule is presence,
# so the value cannot be what makes this mutation fail, and there is no
# reserved-example GA4 ID that would let a realistic one be safe.
assert_mutation_rejected(
  ARGV.fetch(0), live_options,
  'a GA4 measurement ID declared in the tracked manifests',
  'analytics identity must never be tracked here'
) do |documents|
  storefront = resource(documents, 'Deployment', 'plepic-storefront')
  pod_spec(storefront).fetch('containers').first.fetch('env') <<
    { 'name' => 'ANALYTICS_MEASUREMENT_ID', 'value' => 'G-EXAMPLE000' }
end

# ---------------------------------------------------------------------------
# The site's host configuration, one level up: the option table.
#
# Every mutation above rewrites a rendered document and hands it to an unchanged
# option table, so all of them are refused by the exact value comparison. That
# comparison cannot reach the edit these next four are about. Changing a value
# in the overlay *forces* the table to be updated in the same commit, and an
# editor who does both moves the contract with them — which is how a test
# environment could be pointed at a hostname it does not serve `noindex` on, and
# how a real hostname could enter this public repository, with the suite green
# in both cases. Both were executed against this file before these existed.
#
# So this harness mutates the rendered documents and the options together, the
# way that commit would, and the assertions it exercises are the ones written
# over the table rather than over the rendered value.
# ---------------------------------------------------------------------------
def assert_lockstep_mutation_rejected(source_path, options, description, expected_error)
  documents = YAML.load_stream(File.read(source_path)).compact
  # A deep copy, so a mutation cannot leak into the options every later
  # assertion in this file is still using.
  mutated_options = Marshal.load(Marshal.dump(options))
  yield documents, mutated_options
  Tempfile.create(['plepic-manifest-lockstep', '.yaml']) do |temporary|
    temporary.write(YAML.dump_stream(*documents))
    temporary.flush
    begin
      assert_manifest(temporary.path, **mutated_options)
    rescue StandardError => error
      raise "#{description} failed for the wrong reason: #{error.message}" unless error.message.include?(expected_error)
      return
    end
  end
  raise "positive control was accepted: #{description}"
end

# Rewrites one site-host variable on the rendered storefront, so a lockstep
# mutation reads as the pair of edits it is: this line and the table line.
def set_rendered_site_host(documents, workload_name, name, value)
  storefront = resource(documents, 'Deployment', workload_name)
  entries = pod_spec(storefront).fetch('containers').first.fetch('env')
    .select { |entry| entry['name'] == name }
  raise "the mutation targets #{name}, which the rendered storefront does not declare" if entries.empty?
  entries.each { |entry| entry['value'] = value }
end

# The `noindex` regression as an editor would actually commit it: the test
# environment's list points at a hostname it does not answer to, and the table
# says so too. Executed against the previous version of this file — `exit=0`,
# "Plepic manifest contract tests passed", test environment serving no
# `X-Robots-Tag`, an allow-all robots.txt, `index: true` metadata and live
# analytics.
assert_lockstep_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a test-hostname list that omits the hostname the test storefront answers to',
  'the test storefront answers to hostnames its test-hostname list omits'
) do |documents, options|
  options.fetch(:site_hosts)['SITE_TEST_HOSTNAMES'] = 'staging.example.org'
  set_rendered_site_host(documents, 'plepic-storefront-test', 'SITE_TEST_HOSTNAMES', 'staging.example.org')
end

# The mirror, on live, and the reason the empty live value is asserted rather
# than merely explained: a live hostname listed here is a live site telling
# every crawler not to index it, while every page still renders perfectly.
assert_lockstep_mutation_rejected(
  ARGV.fetch(0), live_options,
  'live declaring the hostname it serves unindexable',
  'live declares a hostname it answers to unindexable'
) do |documents, options|
  options.fetch(:site_hosts)['SITE_TEST_HOSTNAMES'] = 'example.com'
  set_rendered_site_host(documents, 'plepic-storefront', 'SITE_TEST_HOSTNAMES', 'example.com')
end

# A real-looking hostname entering a public repository, in lockstep. The name
# below is invented rather than anyone's, for the same reason the address
# controls near the top of this file use invented domains.
#
# Also executed against the previous version of this file, with the actual
# target hostname of this plan, and accepted: `exit=0`. The reserved-name
# exemption did not cover this and never reached it — RESERVED_ADDRESS requires
# a `local-part@`, so no bare hostname is ever tested against it.
assert_lockstep_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the site identity moved to a hostname that is not reserved',
  'site hostnames must be reserved example names'
) do |documents, options|
  hostname = 'test.merchant-domain.com'
  options.fetch(:site_hosts)['SITE_BASE_URL'] = "https://#{hostname}"
  options.fetch(:site_hosts)['SITE_CANONICAL_HOST'] = hostname
  options.fetch(:site_hosts)['SITE_TEST_HOSTNAMES'] = hostname
  set_rendered_site_host(documents, 'plepic-storefront-test', 'SITE_BASE_URL', "https://#{hostname}")
  set_rendered_site_host(documents, 'plepic-storefront-test', 'SITE_CANONICAL_HOST', hostname)
  set_rendered_site_host(documents, 'plepic-storefront-test', 'SITE_TEST_HOSTNAMES', hostname)
end

# Canonical links pointing at one origin while requests canonicalise to another.
# The new canonical host is added to the test-hostname list as well, so the
# `noindex` invariant above is satisfied and this mutation reaches the one
# assertion it is written for.
assert_lockstep_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a canonical host that is not the base URL host',
  "canonical host must be the base URL's host"
) do |documents, options|
  options.fetch(:site_hosts)['SITE_CANONICAL_HOST'] = 'other.example.org'
  options.fetch(:site_hosts)['SITE_TEST_HOSTNAMES'] = 'test.example.org,other.example.org'
  set_rendered_site_host(documents, 'plepic-storefront-test', 'SITE_CANONICAL_HOST', 'other.example.org')
  set_rendered_site_host(documents, 'plepic-storefront-test', 'SITE_TEST_HOSTNAMES',
                         'test.example.org,other.example.org')
end

# A second base URL in a sidecar of the storefront pod. Container 0 still
# carries the expected value, so a guard that read only container 0 saw nothing
# — which is what the storefront assertions used to do and the sibling
# newsletter guards deliberately do not. The sidecar is hardened, resourced and
# digest pinned so the mutation reaches the site-host block rather than dying in
# pod hardening, and it runs an image no census counts.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a storefront sidecar declaring a second base URL',
  'storefront must declare SITE_BASE_URL exactly once'
) do |documents|
  storefront = resource(documents, 'Deployment', 'plepic-storefront-test')
  pod_spec(storefront).fetch('containers') << {
    'name' => 'edge-sidecar',
    'image' => "postgres:17.10-bookworm@sha256:#{'4b7d' * 16}",
    'env' => [{ 'name' => 'SITE_BASE_URL', 'value' => 'https://other.example.org' }],
    'securityContext' => {
      'allowPrivilegeEscalation' => false,
      'capabilities' => { 'drop' => ['ALL'] },
      'readOnlyRootFilesystem' => true,
    },
    'resources' => {
      'requests' => { 'cpu' => '100m', 'memory' => '128Mi' },
      'limits' => { 'cpu' => '500m', 'memory' => '512Mi' },
    },
  }
end

# The same blind spot on the other container-0 read: the publishable key back
# under the name the storefront does not read, in a sidecar. The Secret and key
# are ones this overlay already projects, so the aggregate Secret contract sees
# nothing new.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a storefront sidecar re-declaring the publishable key under the old name',
  'storefront publishable-key variable contract mismatch'
) do |documents|
  storefront = resource(documents, 'Deployment', 'plepic-storefront-test')
  pod_spec(storefront).fetch('containers') << {
    'name' => 'edge-sidecar',
    'image' => "postgres:17.10-bookworm@sha256:#{'4b7d' * 16}",
    'env' => [{
      'name' => 'MEDUSA_PUBLISHABLE_KEY',
      'valueFrom' => { 'secretKeyRef' => { 'name' => 'plepic-test-publishable-key', 'key' => 'publishableKey' } },
    }],
    'securityContext' => {
      'allowPrivilegeEscalation' => false,
      'capabilities' => { 'drop' => ['ALL'] },
      'readOnlyRootFilesystem' => true,
    },
    'resources' => {
      'requests' => { 'cpu' => '100m', 'memory' => '128Mi' },
      'limits' => { 'cpu' => '500m', 'memory' => '512Mi' },
    },
  }
end

# The publishable key under the name these manifests used to give it. The Secret
# name and key are correct and unchanged, so the aggregate Secret contract is
# satisfied exactly as it was while the storefront could not make a single Store
# API call. Only the variable-name contract sees it.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the publishable key under the name the storefront does not read',
  'storefront publishable-key variable contract mismatch'
) do |documents|
  storefront = resource(documents, 'Deployment', 'plepic-storefront-test')
  pod_spec(storefront).fetch('containers').first.fetch('env').each do |entry|
    entry['name'] = 'MEDUSA_PUBLISHABLE_KEY' if entry['name'] == 'MEDUSA_PUBLISHABLE_API_KEY'
  end
end

# A backend-image sidecar named by *tag*. This is the case the replaced sentinel
# counters could not see: they compared exact digest strings, so a tag-form
# reference slipped past them entirely, and the only thing that caught this
# mutation was the sidecar failing to supply the backend image's environment —
# an incidental rejection that said nothing about the tag.
#
# It is now refused on its own terms, and earlier: the digest requirement is a
# property of every container, so an unpinned image is refused for being
# unpinned rather than for whatever else happens to be wrong with it. The
# expected message changed for that reason and only that reason; the mutation is
# unchanged, and the case it covers is now caught by two independent guards,
# since the census counts this container as a fifth backend-image container too.
#
# It stays hardened and resourced so the mutation reaches the image assertions
# rather than dying in pod hardening, and it is appended so the resource contract
# still reads container 0.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a backend-image sidecar referenced by tag',
  'plepic-backend-test/rogue-sidecar must pin its image by digest, ' \
  'not "ghcr.io/hannosirkel/plepic-backend:latest"'
) do |documents|
  backend = resource(documents, 'Deployment', 'plepic-backend-test')
  pod_spec(backend).fetch('containers') << {
    'name' => 'rogue-sidecar',
    'image' => 'ghcr.io/hannosirkel/plepic-backend:latest',
    'securityContext' => {
      'allowPrivilegeEscalation' => false,
      'capabilities' => { 'drop' => ['ALL'] },
      'readOnlyRootFilesystem' => true,
    },
    'resources' => {
      'requests' => { 'cpu' => '100m', 'memory' => '128Mi' },
      'limits' => { 'cpu' => '500m', 'memory' => '512Mi' },
    },
  }
end

# The census above already refuses a fifth backend-image container, so the
# reachable failure for this one is the image landing on a *different* workload
# while the census stays correct — which is what swapping the worker's and the
# storefront's images produces: four backend-image containers and one storefront
# container still, on the wrong two workloads.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'the backend image moving to a workload that is not configured for it',
  'backend-image workload set mismatch'
) do |documents|
  worker = pod_spec(resource(documents, 'Deployment', 'plepic-worker-test')).fetch('containers').first
  storefront = pod_spec(resource(documents, 'Deployment', 'plepic-storefront-test')).fetch('containers').first
  worker['image'], storefront['image'] = storefront['image'], worker['image']
end

# A digest that is the right shape in outline and not a digest. Truncation is the
# form a hand-edit or a truncating template produces, and it is the one a guard
# written as "contains @sha256:" would accept while pinning nothing.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a container pinned to a malformed digest',
  'plepic-storefront-test/storefront must pin its image by digest'
) do |documents|
  storefront = pod_spec(resource(documents, 'Deployment', 'plepic-storefront-test')).fetch('containers').first
  storefront['image'] = "#{STOREFRONT_IMAGE}@sha256:#{'0' * 63}"
end

# The census has to hold against a container the digest requirement is perfectly
# happy with. This sidecar is hardened, resourced and correctly digest pinned, so
# nothing before the census objects to it; only the count does. Without this the
# census could be deleted outright and the digest guard alone would keep the
# suite green.
HARDENED_SIDECAR_SECURITY = {
  'allowPrivilegeEscalation' => false,
  'capabilities' => { 'drop' => ['ALL'] },
  'readOnlyRootFilesystem' => true,
}.freeze
HARDENED_SIDECAR_RESOURCES = {
  'requests' => { 'cpu' => '100m', 'memory' => '128Mi' },
  'limits' => { 'cpu' => '500m', 'memory' => '512Mi' },
}.freeze
# Not the sentinel, deliberately: a plausible promoted digest, so this case also
# demonstrates that a real digest is accepted by everything up to the census.
PLAUSIBLE_DIGEST = "sha256:#{'4b7d' * 16}".freeze

assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a fifth backend-image container that is correctly digest pinned',
  'application image census mismatch'
) do |documents|
  worker = resource(documents, 'Deployment', 'plepic-worker-test')
  pod_spec(worker).fetch('containers') << {
    'name' => 'pinned-sidecar',
    'image' => "#{BACKEND_IMAGE}@#{PLAUSIBLE_DIGEST}",
    'securityContext' => HARDENED_SIDECAR_SECURITY.dup,
    'resources' => HARDENED_SIDECAR_RESOURCES.dup,
  }
end

# The other half of the census: a backend-image container going missing. The
# workload keeps running something legitimate and digest pinned, so again only
# the count notices.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'a backend-image container dropped from the census',
  'application image census mismatch'
) do |documents|
  worker = pod_spec(resource(documents, 'Deployment', 'plepic-worker-test')).fetch('containers').first
  worker['image'] = "postgres:17.10-bookworm@#{PLAUSIBLE_DIGEST}"
end

# A third application repository nobody declared, at a correct digest, leaving
# both existing counts untouched. The two replaced counters asserted only that
# the backend appeared four times and the storefront once; they said nothing
# about anything else under the `plepic-` prefix, so this container would have
# been invisible to them. Comparing the whole tally is what refuses it.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'an undeclared application image alongside a correct census',
  'application image census mismatch'
) do |documents|
  worker = resource(documents, 'Deployment', 'plepic-worker-test')
  pod_spec(worker).fetch('containers') << {
    'name' => 'undeclared-sidecar',
    'image' => "#{APPLICATION_IMAGE_PREFIX}analytics@#{PLAUSIBLE_DIGEST}",
    'securityContext' => HARDENED_SIDECAR_SECURITY.dup,
    'resources' => HARDENED_SIDECAR_RESOURCES.dup,
  }
end

# Two backend containers on two different, individually valid digests — the
# worker running a build the backend it works alongside is not. Nothing earlier
# objects: both references are correctly pinned, the census still tallies four
# backend containers and one storefront, the workload set is untouched, and every
# environment contract still holds. Only the uniformity assertion refuses it,
# which is what keeps that assertion load-bearing rather than ornamental.
assert_mutation_rejected(
  ARGV.fetch(1), test_options,
  'backend-image containers split across two different digests',
  'application image digests diverge'
) do |documents|
  worker = pod_spec(resource(documents, 'Deployment', 'plepic-worker-test')).fetch('containers').first
  worker['image'] = "#{BACKEND_IMAGE}@#{PLAUSIBLE_DIGEST}"
end

# The overlay-level counterpart of assert_mutation_rejected, and the reason
# there has to be one.
#
# assert_mutation_rejected rewrites *rendered documents*. The overlay assertions
# near the top of assert_manifest re-read the kustomization from disk, so no
# document mutation can reach them, and the overlay digest assertion was
# consequently the only guard added by this change that could be deleted outright
# with the suite staying green. This harness mutates the overlay instead and
# hands assert_manifest the unmodified rendered documents alongside it.
#
# The pairing fakes nothing. No assertion ties a rendered image to the digest the
# overlay declares — see the uniformity note in assert_manifest for why that tie
# is deliberately absent — so a mutated overlay next to untouched rendered
# documents is not an input the contract considers inconsistent.
def assert_overlay_mutation_rejected(rendered_path, options, description, expected_error)
  overlay = YAML.load_file("plepic/overlays/#{options.fetch(:environment)}/kustomization.yaml")
  yield overlay
  Tempfile.create(['plepic-overlay-mutation', '.yaml']) do |temporary|
    temporary.write(YAML.dump(overlay))
    temporary.flush
    begin
      assert_manifest(rendered_path, **options, overlay_path: temporary.path)
    rescue StandardError => error
      raise "#{description} failed for the wrong reason: #{error.message}" unless error.message.include?(expected_error)
      return
    end
  end
  raise "positive control was accepted: #{description}"
end

# A tag where the digest belongs. This is the shape a hand edit produces, and
# the one `scripts/update-gitops-digest.sh` owning these lines exists to keep
# anyone from writing.
#
# Losing the digest key also violates the entry shape, so this case is covered
# twice and the message below names whichever assertion is reached first. The
# malformed-digest mutation after it is the one that isolates the digest
# requirement, keeping all three keys and failing only the shape.
assert_overlay_mutation_rejected(
  ARGV.fetch(1), test_options,
  'an overlay image entry pinned by tag instead of digest',
  'overlay images must be pinned by digest'
) do |overlay|
  entry = overlay.fetch('images').find { |image| image['name'] == BACKEND_IMAGE }
  entry.delete('digest')
  entry['newTag'] = 'latest'
end

# A truncated digest at the source: the overlay-level twin of the malformed
# rendered digest above, and the case that separates this assertion from one
# written as "has a digest key".
assert_overlay_mutation_rejected(
  ARGV.fetch(1), test_options,
  'an overlay image entry pinned to a malformed digest',
  'overlay images must be pinned by digest'
) do |overlay|
  overlay.fetch('images').first['digest'] = "sha256:#{'0' * 63}"
end

# A tag *alongside* a valid digest. Everything about the deployed result stays
# correct — the entry renders `…:latest@sha256:…` and the digest is what pins —
# so the digest assertion is satisfied and only the entry-shape assertion
# objects. It is refused because the promotion script cannot rewrite an entry it
# cannot pattern-match, which would leave this overlay deploying correctly and
# unable to be promoted again.
assert_overlay_mutation_rejected(
  ARGV.fetch(1), test_options,
  'an overlay image entry carrying a tag alongside its digest',
  'overlay image entries must carry only name, newName and digest'
) do |overlay|
  overlay.fetch('images').first['newTag'] = 'latest'
end

# The acceptance half, and the reason this file can be trusted not to be sentinel
# equality wearing a regular expression. Every refusal above would still pass if
# the digest requirement had been written as "equals the sentinel"; this is the
# case that separates the two.
#
# It is the state the next successful promotion produces — the rendered
# application images carrying real, non-sentinel digests — asserted through the
# whole of assert_manifest rather than against the shape in isolation. The
# overlay on disk is still on the sentinel while these documents are not, which
# is also the mixed state the environments are in between a test promotion and
# the release that follows it.
def assert_promotion_accepted(source_path, options, description)
  documents = YAML.load_stream(File.read(source_path)).compact
  yield documents
  Tempfile.create(['plepic-manifest-promotion', '.yaml']) do |temporary|
    temporary.write(YAML.dump_stream(*documents))
    temporary.flush
    begin
      assert_manifest(temporary.path, **options)
    rescue StandardError => error
      raise "#{description} was refused: #{error.message}"
    end
  end
end

assert_promotion_accepted(
  ARGV.fetch(1), test_options, 'an overlay promoted to real digests'
) do |documents|
  # Two different digests, because live is rebuilt from merged `main` rather
  # than re-tagged from the tested image, so the two environments never converge
  # on one value and nothing may assume they do.
  promoted = { BACKEND_IMAGE => PLAUSIBLE_DIGEST, STOREFRONT_IMAGE => "sha256:#{'9e02' * 16}" }
  documents.each do |document|
    next unless (pod = pod_spec(document))
    pod_containers(pod).each do |container|
      digest = promoted[image_repository(container['image'])]
      container['image'] = "#{image_repository(container['image'])}@#{digest}" if digest
    end
  end
end

puts 'Plepic manifest contract tests passed'
RUBY
