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
    # T19: sized from measurement, not from a guess. T13 requested 200m (live)
    # and 100m (test) per workload; measured against the running deployment
    # every pod used 1-19m, so ten pods reserved 1700m for 77m of work and the
    # node reached 99% of its twelve allocatable CPUs -- at which point live's
    # predeploy Job could not schedule and live could not adopt a new digest.
    # 50m is a little over twice the highest figure observed. Pinned because a
    # request that drifts back up is invisible until a Job stops scheduling.
    raise "cpu request on #{container['name']} must be 50m, sized by measurement" unless
      container.dig('resources', 'requests', 'cpu') == '50m'
  end
end

BACKEND_IMAGE = 'ghcr.io/hannosirkel/lousydeal-backend'.freeze
STOREFRONT_IMAGE = 'ghcr.io/hannosirkel/lousydeal-storefront'.freeze

# `/32`, not the reference's base `/16`: the reference's `/16` is a
# placeholder each environment's own Orange patch replaces
# (`plepic/base/networkpolicy.yaml:37`), and this policy carries no such
# override, so this base value is what runs on merge. A `/16` base was
# measured to reach `backend:9000` over the WireGuard tunnel directly, never
# through Cloudflare Access -- `192.168.1.0/24` is inside
# `wireguard_peer_allowed_ips`, `wg0` is a trusted interface, and the forward
# chain's policy is `accept`
# (`orange/roles/nftables/templates/nftables.conf.j2:57`). `/32` is the one
# address the Cloudflare Tunnel connector itself reaches this cluster from.
ADMIN_INGRESS_CIDR = '192.168.21.2/32'.freeze

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

# `seed:administrator` runs only inside the predeploy Job's `npm run
# predeploy` chain (`backend/package.json`) -- the API and worker
# Deployments never execute it, and `runtime.ts`'s own header states these
# two names are kept out of `BackendRuntimeConfig` specifically so neither
# Deployment needs this credential to boot. So unlike
# `BACKEND_IMAGE_REQUIRED_ENVIRONMENT`, which every backend-image workload
# must declare, these two are required on the predeploy Job alone -- checked
# below where that requirement is added -- and forbidden on every other
# workload, backend-image or not, by a separate check further down.
ADMINISTRATOR_ENV_NAMES = %w[MEDUSA_ADMIN_EMAIL MEDUSA_ADMIN_PASSWORD].freeze

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
  predeploy = resource(documents, 'Job', "lousydeal-predeploy#{suffix}")

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
  # declares a name this application's code does not read. The predeploy Job
  # is additionally required to carry `ADMINISTRATOR_ENV_NAMES` -- checked
  # here because only backend-image workloads can ever carry it -- keyed on
  # `workload.equal?(predeploy)`, the one `Job` resource already resolved
  # above, not on a name string.
  workloads(documents).each do |workload|
    is_predeploy = workload.equal?(predeploy)
    pod_containers(pod_spec(workload)).each do |container|
      next unless image_repository(container['image']) == BACKEND_IMAGE
      names = container.fetch('env', []).map { |e| e['name'] }
      required = is_predeploy ? BACKEND_IMAGE_REQUIRED_ENVIRONMENT + ADMINISTRATOR_ENV_NAMES : BACKEND_IMAGE_REQUIRED_ENVIRONMENT
      missing = required - names
      raise "#{workload.dig('metadata', 'name')}/#{container['name']} missing #{missing.join(', ')}" unless missing.empty?
      # Each namespace's Application projects its own `*-database-admin`
      # Secret (`orange/roles/argocd/defaults/main.yml` -- the ESO
      # projections live in the argocd role, not the openbao role: the
      # latter (`roles/openbao/defaults/main.yml`) holds only the flat list
      # of registered source names, no namespace and no projection; T14a's
      # own record, `docs/working/ld-01-foundation/journal.md:2270`, is "the
      # argocd role waits for every ExternalSecret to report ready"). A
      # literal `lousydeal-database-admin` reference does not exist as a
      # Kubernetes Secret inside the `lousydeal-test` namespace, only
      # `lousydeal-test-database-admin` does. `suffix` is this same
      # overlay's own name-suffix convention (`assert_manifest`'s caller),
      # so this catches the base's Secret name reaching the test overlay
      # unremapped.
      if is_predeploy
        ADMINISTRATOR_ENV_NAMES.each do |admin_name|
          ref = env_entry(container, admin_name)&.dig('valueFrom', 'secretKeyRef')
          raise "#{admin_name} carries no secretKeyRef" unless ref
          raise "#{admin_name} must be sourced from lousydeal#{suffix}-database-admin, not #{ref['name']}" unless
            ref['name'] == "lousydeal#{suffix}-database-admin"
          raise "#{admin_name} must read key #{admin_name}, not #{ref['key']}" unless ref['key'] == admin_name
        end
      end
      forbidden = names & FORBIDDEN_ENV_NAMES
      raise "#{workload.dig('metadata', 'name')}/#{container['name']} declares unread #{forbidden.join(', ')}" unless forbidden.empty?
      pmc = env_entry(container, 'STRIPE_PAYMENT_METHOD_CONFIGURATION_ID')
      raise 'STRIPE_PAYMENT_METHOD_CONFIGURATION_ID must be declared' unless pmc
      raise 'STRIPE_PAYMENT_METHOD_CONFIGURATION_ID must be optional' unless
        pmc.dig('valueFrom', 'secretKeyRef', 'optional') == true
    end
  end

  # "and nowhere else": every container of every workload, not only the
  # backend-image ones -- the storefront runs a different image entirely and
  # still must not carry these two names -- and not only via `env:`:
  # `envFrom.secretRef` projects every key of a Secret as environment
  # variables, so a workload that `envFrom`s the administrator Secret reads
  # both names without ever naming either one, past a check that only reads
  # `env:`. Scoped per container, not per workload: within the predeploy
  # Job's own pod, only the container actually named `predeploy` is exempt,
  # so an unrelated `initContainer` added to that pod cannot smuggle the
  # credential in under the workload's own exemption.
  workloads(documents).each do |workload|
    pod_containers(pod_spec(workload)).each do |container|
      next if workload.equal?(predeploy) && container['name'] == 'predeploy'
      leaked = container.fetch('env', []).map { |e| e['name'] } & ADMINISTRATOR_ENV_NAMES
      raise "#{workload.dig('metadata', 'name')}/#{container['name']} must not read #{leaked.join(', ')}" unless leaked.empty?
      env_from_secrets = container.fetch('envFrom', []).filter_map { |e| e.dig('secretRef', 'name') }
      raise "#{workload.dig('metadata', 'name')}/#{container['name']} must not envFrom the administrator Secret (#{env_from_secrets.join(', ')})" if
        env_from_secrets.any? { |name| name.end_with?('-database-admin') }
    end
  end

  # Every Secret this repository's manifests reference is one of the
  # environment-scoped `lousydeal{-test}-*` sources T14a registers into this
  # overlay's own namespace -- never a literal `lousydeal-*` name reaching
  # the `-test` namespace because some later variable's overlay patch forgot
  # to remap it. The overlay patches are strategic merges keyed on `name`,
  # so an entry the patch does not list silently keeps the base's live
  # Secret name -- checked here once, generically, on every `secretKeyRef`
  # and `envFrom.secretRef` in the render, rather than re-derived per
  # variable the way `ADMINISTRATOR_ENV_NAMES` is above. Only a prefix
  # check, deliberately: on the live overlay (`suffix` is `""`) every
  # `lousydeal-test-*` name also starts with `lousydeal-`, so this catches
  # the live-into-test direction the review measured, not its mirror.
  workloads(documents).each do |workload|
    pod_containers(pod_spec(workload)).each do |container|
      referenced_secrets = container.fetch('env', []).filter_map { |e| e.dig('valueFrom', 'secretKeyRef', 'name') }
      referenced_secrets += container.fetch('envFrom', []).filter_map { |e| e.dig('secretRef', 'name') }
      referenced_secrets.each do |secret_name|
        raise "#{workload.dig('metadata', 'name')}/#{container['name']} references #{secret_name}, not an environment-scoped lousydeal#{suffix}-* Secret" unless
          secret_name.start_with?("lousydeal#{suffix}-")
      end
    end
  end
  storefront = resource(documents, 'Deployment', "lousydeal-storefront#{suffix}")
  storefront_container = pod_containers(pod_spec(storefront)).first
  storefront_names = storefront_container.fetch('env', []).map { |e| e['name'] }
  raise 'storefront env must be exactly the three names runtime-config.ts reads' unless
    storefront_names.sort == %w[MEDUSA_BACKEND_URL MEDUSA_PUBLISHABLE_API_KEY STRIPE_PUBLISHABLE_KEY].sort

  # Probes.
  backend = resource(documents, 'Deployment', "lousydeal-backend#{suffix}")
  backend_container = pod_containers(pod_spec(backend)).first
  raise 'backend readiness probe must target /health' unless
    backend_container.dig('readinessProbe', 'httpGet', 'path') == '/health'
  raise 'backend liveness probe must target /health' unless
    backend_container.dig('livenessProbe', 'httpGet', 'path') == '/health'

  # T13b: measured directly against `localhost/lousydeal-backend:t11` with
  # `MEDUSA_WORKER_MODE=worker`, a real PostgreSQL and a real Redis (see
  # `lousydeal/README.md`) -- the worker binds :9000 and answers `/health`
  # `200`, every other path tried (`/app` included) answered `404`, and three
  # boot runs reached "Server is ready on port: 9000" in 2.81-2.86s. This
  # asserts the measured shape, not merely that a key named `*Probe` exists.
  worker = resource(documents, 'Deployment', "lousydeal-worker#{suffix}")
  worker_container = pod_containers(pod_spec(worker)).first
  # The readiness comment's rolling-update guarantee holds only at
  # `maxUnavailable: 0` -- pinned explicitly in `worker.yaml` rather than left
  # to the apiserver's 25%/25% default, which happens to round to zero only at
  # this replica count. `maxUnavailable: 1` at `replicas: 1` would let a new,
  # never-Ready pod replace the working one -- exactly what that comment says
  # cannot happen.
  raise 'worker rolling update must keep maxUnavailable at 0' unless
    worker.dig('spec', 'strategy', 'rollingUpdate', 'maxUnavailable') == 0
  raise 'worker readiness probe must target /health on the http port' unless
    worker_container.dig('readinessProbe', 'httpGet', 'path') == '/health' &&
    worker_container.dig('readinessProbe', 'httpGet', 'port') == 'http'
  raise 'worker readiness thresholds must match the measured boot time' unless
    worker_container.dig('readinessProbe', 'initialDelaySeconds') == 10 &&
    worker_container.dig('readinessProbe', 'periodSeconds') == 5
  raise 'worker liveness probe must target /health on the http port' unless
    worker_container.dig('livenessProbe', 'httpGet', 'path') == '/health' &&
    worker_container.dig('livenessProbe', 'httpGet', 'port') == 'http'
  raise 'worker liveness thresholds must match the measured boot time' unless
    worker_container.dig('livenessProbe', 'initialDelaySeconds') == 30 &&
    worker_container.dig('livenessProbe', 'periodSeconds') == 10
  raise 'worker container must declare the port its probes target' unless
    pod_containers(pod_spec(worker)).first.fetch('ports', []).any? { |port| port['name'] == 'http' && port['containerPort'] == 9000 }
  # Judgement call (T13b review): not every probe mutation is worth asserting
  # against -- a test cannot enumerate every misconfiguration, and
  # `failureThreshold`/`timeoutSeconds` are legitimate operational knobs a
  # later row may reasonably tune, with no single bound this contract could
  # pin without becoming the next thing that drifts. `scheme` and `host` are
  # different in kind: this container serves plain HTTP on its own pod IP,
  # always, so neither field has a legitimate value other than absent here --
  # `scheme: HTTPS` is a guaranteed failure against a plaintext server, and
  # any `host:` sends the probe off the pod entirely. Both were measured to
  # pass silently with no assertion in place, so both are asserted; threshold
  # tuning is not.
  %w[readinessProbe livenessProbe].each do |probe_name|
    probe = worker_container.fetch(probe_name)
    raise "worker #{probe_name} must not set host (it would leave the pod)" if
      probe.dig('httpGet', 'host')
    raise "worker #{probe_name} must not override scheme away from plain HTTP" if
      probe.dig('httpGet', 'scheme') && probe.dig('httpGet', 'scheme') != 'HTTP'
  end

  # Exposure: `MEDUSA_WORKER_MODE` is the one line that keeps the Medusa
  # Admin off the worker's HTTP surface -- setting it to `server`, or
  # deleting it, both leave every probe/port/Service assertion above green
  # while `/app` starts answering `200` (measured; see `lousydeal/README.md`).
  # `loadEntrypoints` returns before mounting the admin loader only when
  # `isWorkerMode` is true, and `isWorkerMode` is true only for the literal
  # string `"worker"` (`@medusajs/medusa/dist/loaders/index.js:24-26,51-55`,
  # returning at :53-55 before the admin loader at :78) -- every other value,
  # including an absent variable, resolves to Medusa's own `"shared"` default,
  # which is not worker mode. This is why the check below is a string equality
  # on `worker`, not a presence check.
  raise 'the worker must set MEDUSA_WORKER_MODE to worker, exactly' unless
    env_entry(worker_container, 'MEDUSA_WORKER_MODE')&.fetch('value', nil) == 'worker'
  # Symmetric case: `backend.yaml` already sets this, and `README.md` already
  # claims it -- this is the assertion that makes the claim provable rather
  # than merely stated.
  raise 'the backend must set MEDUSA_WORKER_MODE to server, exactly' unless
    env_entry(backend_container, 'MEDUSA_WORKER_MODE')&.fetch('value', nil) == 'server'

  # The worker takes no traffic (T13a) -- a Service here would be a route this
  # row's own probe comments say does not exist, not a probe requirement. Keyed
  # on the selector, not the name: a Service named anything at all still
  # routes to the worker's pods if its selector matches their labels
  # (measured -- `lousydeal-worker-http` selecting `component: worker` on 9000
  # passed a name-keyed version of this check).
  worker_pod_labels = worker.dig('spec', 'template', 'metadata', 'labels') || {}
  raise 'the worker must carry no Service whose selector matches its pod labels' if
    documents.any? do |document|
      next false unless document['kind'] == 'Service'
      selector = document.dig('spec', 'selector') || {}
      !selector.empty? && selector.all? { |key, value| worker_pod_labels[key] == value }
    end
  raise 'storefront readiness probe must render the real page' unless
    storefront_container.dig('readinessProbe', 'httpGet', 'path') == '/'
  # A TCP check, not an HTTP path -- this repository ships no backend-free
  # liveness route (no `storefront/src/app/robots.ts`); see `base/storefront.yaml`.
  raise 'storefront liveness probe must be a TCP check, not an HTTP path' unless
    storefront_container.key?('livenessProbe') && storefront_container['livenessProbe'].key?('tcpSocket') &&
    !storefront_container['livenessProbe'].key?('httpGet')

  all_policies = documents.select { |document| document['kind'] == 'NetworkPolicy' }

  # Exposure: decision 010 gives the Admin a route in, but the checkbox this
  # row implements is narrower than "a route exists" -- the storefront's own
  # rule must survive at index 0 unmoved, and nothing but the backend pod may
  # gain one. Both properties are asserted against the rendered shape, not
  # merely restated from this row's own diff, so a patch or a future edit
  # that moves the rule, widens its CIDR, retargets its selector or drops its
  # port constraint is caught here.
  backend_service = resource(documents, 'Service', "lousydeal-backend#{suffix}")
  raise 'the backend Service must carry the WireGuard externalIP' unless
    backend_service.dig('spec', 'externalIPs') == ['192.168.21.2']
  storefront_service = resource(documents, 'Service', "lousydeal-storefront#{suffix}")
  raise 'the storefront Service must carry the WireGuard externalIP' unless
    storefront_service.dig('spec', 'externalIPs') == ['192.168.21.2']

  # The half this row actually changed and the review found unasserted: the
  # backend Service's own port and the storefront's `MEDUSA_BACKEND_URL` must
  # agree, derived from the render rather than compared against a constant --
  # a drift here ships a storefront that cannot reach its own backend, or
  # (paired with the cross-overlay check below) two Services claiming the
  # same `192.168.21.2:port`.
  raise 'the backend Service must expose exactly one port' unless backend_service.dig('spec', 'ports')&.length == 1
  backend_port = backend_service.dig('spec', 'ports', 0, 'port')
  raise "the backend Service's targetPort must still name the container's http port" unless
    backend_service.dig('spec', 'ports', 0, 'targetPort') == 'http'
  medusa_backend_url = env_entry(storefront_container, 'MEDUSA_BACKEND_URL')&.fetch('value', nil)
  raise 'MEDUSA_BACKEND_URL must be declared' unless medusa_backend_url
  medusa_backend_url_port = medusa_backend_url[/:(\d+)\z/, 1]&.to_i
  raise "MEDUSA_BACKEND_URL (#{medusa_backend_url}) must name the backend Service's own port (#{backend_port})" unless
    medusa_backend_url_port == backend_port

  backend_ingress = resource(documents, 'NetworkPolicy', "allow-backend-ingress#{suffix}")
  raise 'allow-backend-ingress must still select only the backend pod' unless
    backend_ingress.dig('spec', 'podSelector') == { 'matchLabels' => { 'app.kubernetes.io/component' => 'backend' } }
  raise 'backend ingress must carry exactly two rules' unless backend_ingress.dig('spec', 'ingress')&.length == 2
  raise 'the storefront ingress rule must remain at index 0' unless backend_ingress.dig('spec', 'ingress', 0) == {
    'from' => [{ 'podSelector' => { 'matchLabels' => { 'app.kubernetes.io/component' => 'storefront' } } }],
    'ports' => [{ 'port' => 9000, 'protocol' => 'TCP' }],
  }
  raise 'the admin ingress rule must be the second entry, admitting only the base CIDR on the backend port' unless
    backend_ingress.dig('spec', 'ingress', 1) == {
      'from' => [{ 'ipBlock' => { 'cidr' => ADMIN_INGRESS_CIDR } }],
      'ports' => [{ 'port' => 9000, 'protocol' => 'TCP' }],
    }
  # "and no other workload gains a route": this row's only edit is
  # `allow-backend-ingress`'s own `ingress` list, so the CIDR it admits must
  # not appear as a peer in any other policy -- including one retargeted at
  # the worker or at PostgreSQL by moving the rule rather than editing it in
  # place. Excluded by name, not by selector: `allow-storefront-ingress` and
  # `allow-storefront-backend-egress` share the storefront's `component`
  # selector, so a selector-based exclusion would silently exempt both
  # instead of the one policy (`allow-backend-ingress`) this row actually
  # touches -- reviewed and measured to matter: `allow-storefront-backend-egress`
  # carrying this CIDR as an egress peer previously passed this check.
  leaked = all_policies.reject { |policy| policy.dig('metadata', 'name') == "allow-backend-ingress#{suffix}" }
                        .select { |policy| policy.to_s.include?(ADMIN_INGRESS_CIDR) }
  raise "admin CIDR leaked into #{leaked.map { |p| p.dig('metadata', 'name') }.join(', ')}" unless leaked.empty?

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

# Cross-overlay: every Service on the one shared WireGuard address --
# storefront and backend, live and test -- must claim a mutually distinct
# port on it. This row doubled the port count on that address; the
# per-overlay checks above cannot see the other overlay's render, so a
# collision (backend live reusing storefront live's port, or either
# environment's backend reusing the other's) only shows up here.
live_storefront = live.find { |d| d['kind'] == 'Service' && d.dig('metadata', 'name') == 'lousydeal-storefront' }
test_storefront = test_environment.find { |d| d['kind'] == 'Service' && d.dig('metadata', 'name') == 'lousydeal-storefront-test' }
live_backend = live.find { |d| d['kind'] == 'Service' && d.dig('metadata', 'name') == 'lousydeal-backend' }
test_backend = test_environment.find { |d| d['kind'] == 'Service' && d.dig('metadata', 'name') == 'lousydeal-backend-test' }
wireguard_ports = {
  'live storefront' => live_storefront.dig('spec', 'ports', 0, 'port'),
  'live backend' => live_backend.dig('spec', 'ports', 0, 'port'),
  'test storefront' => test_storefront.dig('spec', 'ports', 0, 'port'),
  'test backend' => test_backend.dig('spec', 'ports', 0, 'port'),
}
raise "192.168.21.2 ports must be mutually distinct: #{wireguard_ports}" unless
  wireguard_ports.values.uniq.length == wireguard_ports.length

puts 'lousydeal/tests/manifests.sh: all assertions passed'
RUBY
