# Lousy Deal GitOps State

This application root contains the namespaced Kubernetes resources for the
Lousy Deal store. Application source and image builds live in the separate
`hannosirkel/lousydeal` repository; Orange/Ansible owns namespaces, Pod
Security labels, External Secrets projections, Argo CD Applications, private
source ranges, and deployment orchestration -- none of that exists for Lousy
Deal yet (T14/T15), so these manifests are inert on merge: files in a
repository, checked by CI, watched by nothing.

`base/` defines the shared PostgreSQL, Redis, Medusa backend and worker,
storefront, migration Job, Services and NetworkPolicies. There is no assets
PVC and no catalogue-import Job -- this application has neither media nor a
catalogue migration. The deployable roots are:

- `overlays/live`, which renders into namespace `lousydeal`;
- `overlays/test`, which renders isolated names, storage, database state and
  Secret references into namespace `lousydeal-test`.

Both the storefront and the backend carry an `externalIP`, the shared
WireGuard address `192.168.21.2` -- the storefront on port 8121 (live) / 8131
(test), the backend on 8122 (live) / 8132 (test), the next free slots after
Plepic's 8101/8102/8111/8112 and Servitium's 8098/8099 on that one shared
address. Decision [`010`](https://github.com/hannosirkel/lousydeal/blob/main/docs/decisions/010-the-admin-is-reachable-and-gated.md)
reverses this root's original no-route shape: the Medusa Admin the backend
image serves on port 9000 is now reachable, gated behind Cloudflare Access
rather than withheld entirely. `allow-backend-ingress` carries the network
half of the same reversal -- a second rule admitting `192.168.21.2/32`, the
shared WireGuard address itself, **added after** the storefront's own
pod-selector rule rather than in place of it.

This is `/32`, not the reference's base `/16`
(`plepic/base/networkpolicy.yaml:37`). The reference's `/16` is a placeholder
each environment's own Orange patch replaces with a narrow
`ingress_source_ranges` list; this application carries no such override for
`allow-backend-ingress`, so the base value here is what runs on merge, not a
value some later row is expected to narrow. A `/16` base would admit all
65,536 addresses of `192.168.0.0/16`, and the operator's own inventory shows
that path never reaches Cloudflare Access at all: `192.168.1.0/24` is inside
`wireguard_peer_allowed_ips`, `wg0` is one of `nftables_trusted_interfaces`,
and the forward chain's policy is `accept`
(`orange/roles/nftables/templates/nftables.conf.j2:57`) -- so a host on that
block reaches `backend:9000` over the tunnel directly, never through the
proxy decision 010's *"reachable only through Cloudflare Access"* describes.
`/32` is the one address that path actually needs.

**That rule carries two entries now, and index 0 is still the storefront pod
selector**, not the reference's shape, where index 0 is the CIDR
(`plepic/base/networkpolicy.yaml:26-44`). Orange's Application for this root
is already wired (`orange` `main` `fc08f33`,
`roles/argocd/templates/lousydeal-application.yaml.j2`) and does not render
the reference template's `replace /spec/ingress/0/from` patch
(`orange/roles/argocd/templates/plepic-application.yaml.j2:53-66`) against
`backend` here; it must continue not to, regardless of what it does at index
1, or it would delete this rule and substitute a private CIDR at index 0.

## CPU requests are measured, memory is not yet

Both overlays request `cpu: 50m` per workload. T13 requested 200m (live) and
100m (test), which was a guess: measured against the running deployment on
2026-09-03, every pod used between 1m and 19m — 38m across live's five and 39m
across test's five, against 1700m reserved. The node reached **99% of its twelve
allocatable CPUs**, live's predeploy Job stopped scheduling with `Insufficient
cpu`, and live could no longer adopt a new digest. `lousydeal/tests/manifests.sh`
pins the value, because a request that drifts back up is invisible until a Job
fails to schedule.

**Memory was not changed, and is under-requested rather than over.** The same
measurement put live's backend at 298Mi against a 256Mi request and test's at
260Mi against 128Mi — so the scheduler underestimates both, test by roughly
half. Node memory was at 37%, so nothing is at risk today, and correcting it is
outside the row that fixed the CPU figures. **It is recorded here rather than
carried silently.**

## PostgreSQL is Lousy Deal's own

Decision [`003`](https://github.com/hannosirkel/lousydeal/blob/main/docs/decisions/003-own-postgresql-per-environment.md)
puts an own StatefulSet per environment in this base -- `lousydeal-postgresql`
and `lousydeal-postgresql-test` -- rather than a database inside a shared
server. There is no shared PostgreSQL service on the cluster to join, and this
store takes payments: coupling its availability to another application's
instance was rejected. Redis is the same shape, for the same reason.

## What the backend image needs, and what it does not

`backend/src/config/runtime.ts` requires, at module scope, the five
`DATABASE_*` parts, the three `REDIS_*` parts, `JWT_SECRET`, `COOKIE_SECRET`,
`STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` on every workload that loads
`medusa-config.ts` -- the API, the worker and the predeploy Job all carry the
full set. `STRIPE_PAYMENT_METHOD_CONFIGURATION_ID` is read through
`optionalEnv`, not `requireEnv` -- it names a Stripe Dashboard object no row
in this plan creates yet -- so its `secretKeyRef` carries `optional: true`,
the same reasoning the reference applies to its own late-bootstrap credential.

**No `STORE_CORS`, `ADMIN_CORS` or `AUTH_CORS`.** Unlike the reference,
`runtime.ts`'s own header states these are not required here ("a later row
may want them required too" -- not this one). Declaring a name nothing reads
is dead configuration copied by habit, not caution, so `tests/manifests.sh`
refuses it as a positive assertion rather than leaving it unstated. The same
is true of every `SITE_*` name and the SMTP block: this storefront reads no
`SITE_*` variable at all, and nothing in this application sends mail, so no
`allow-smtp-submission-egress` policy exists in this base.

**`MERCHANT_*` used to be on that list and is not any more.** The names that
were there were the reference project's -- `MERCHANT_REGISTERED_ADDRESS`,
`MERCHANT_CONTACT_ADDRESS`, `MERCHANT_RETURN_ADDRESS` -- and this storefront
never read any of them, so the prohibition was inherited rather than measured.
It reads five, and LD-09 gave it four legal documents that need them.

**Three are committed and two are not, and the split is the contract's §2b.**
The company, its address and its contact are public business-register facts
that §2b says may be committed; they are also the same in both environments,
because there is one company, so they sit in the base rather than in two
overlays that would drift. A director's name, a registry code, a VAT number and
a bank account are each "their own decision" and are not covered by it, so the
two this storefront reads arrive the way §2b requires -- read server-side at
runtime, never a literal in a repository -- through the sanctioned secrets
path.

Their `secretKeyRef` carries `optional: true`, for the reason
`STRIPE_PAYMENT_METHOD_CONFIGURATION_ID` above carries it: a pod must start
before the key exists. Until the operator supplies them, decision `004`'s
resolver renders each as a named, visible gap and the document says it is
incomplete. **That is the designed behaviour and not a defect** -- but it does
mean the imprint is incomplete in both environments until those two keys are
in OpenBao, which is an operator action outside every repository in this plan.

`tests/manifests.sh` checks how each of the five arrives, not merely that it is
declared: a registry code pasted in as a literal would satisfy a presence check
and would be exactly the thing a public repository must never hold.

## The worker runs the same `args` as the backend

`backend/package.json` declares `build`, `start`, `redis:preflight`,
`configure:commerce`, `seed:administrator`, `seed:product`, `predeploy`,
`typecheck` and `test:unit` -- nine scripts, no `start:worker`. The
reference's own worker names a script
that sets `MEDUSA_WORKER_MODE=worker` inline; this repository has none to
name, so `worker.yaml` runs the identical `[npm, run, start]` and sets
`MEDUSA_WORKER_MODE=worker` as a container `env:` entry instead. Medusa's
framework reads that variable from the process environment regardless of
which script started it, so the two are equivalent -- and `backend.yaml`
states `MEDUSA_WORKER_MODE=server` explicitly for the same reason.

## The worker's probes (T13b)

**The worker binds :9000 and answers `/health`, in `worker` mode, unassisted
by any code this repository writes.** This was not obvious going
in: `worker.yaml` previously stated the worker "serves no HTTP request," and
that sentence was never measured against the built image -- it read
`@medusajs/medusa/dist/commands/start.js:245-248` (`app.get("/health", ...)`
then `http_.listen(port, host)`) as a path both `server` and `worker` share,
with `:284-331` only forking a cluster child differently under `--cluster`,
which this Deployment does not pass. That reading turned out to be right, but
only running the real image settles it.

Measured 2026-08-31 against `localhost/lousydeal-backend:t11` (the only
backend image on this host, predating this row), a real PostgreSQL
17.10-bookworm (the version `base/postgresql.yaml:81` pins) and a
real Redis 7 (`--requirepass` set, matching the shape a cluster Secret
projects), all three on one `podman` network, `npx medusa db:migrate
--execute-safe-links` run once first so the API and Tax/Payment module
loaders had schema to read:

```console
$ podman run -d --name t13b-worker --network t13b-net \
    -e MEDUSA_WORKER_MODE=worker \
    -e DATABASE_URL=postgres://medusa:***@t13b-pg:5432/lousydeal \
    -e JWT_SECRET=*** -e COOKIE_SECRET=*** \
    -e REDIS_HOST=t13b-redis -e REDIS_PORT=6379 -e REDIS_PASSWORD=*** \
    -e STRIPE_SECRET_KEY=sk_test_*** -e STRIPE_WEBHOOK_SECRET=whsec_*** \
    localhost/lousydeal-backend:t11 npm run start
$ podman logs --timestamps t13b-worker | grep "Server is ready"
2026-08-31T18:21:14.575508000Z {"activity_id":"...","duration":1421,"level":"info",
  "message":"Server is ready on port: 9000", ...}
$ curl -s -o /dev/null -w '%{http_code}\n' http://<worker-ip>:9000/health
200
$ curl -s -o /dev/null -w '%{http_code}\n' http://<worker-ip>:9000/app
404
$ curl -s -o /dev/null -w '%{http_code}\n' http://<worker-ip>:9000/admin/users
404
$ curl -s -o /dev/null -w '%{http_code}\n' http://<worker-ip>:9000/store/products
404
```

**The Admin gains no second surface through the worker.** `/health` is the
only path that answers in `worker` mode; `/app` (the Admin bundle, live on
this same port in `server` mode -- the `lousydeal` repository's
`backend/Dockerfile`'s own comment on `EXPOSE 9000`) and every `/admin/*` and
`/store/*` route tried answered `404`. This is not just four sampled paths:
`@medusajs/medusa/dist/loaders/index.js:51-55` returns from `loadEntrypoints`
before it ever reaches `:78` (the Admin loader) or `:79` (the API router),
whenever `isWorkerMode` (`:24-26`) is true -- so in `worker` mode nothing but
`start.js:245`'s `/health` is ever registered, for any path, not only the
four tried above. `isWorkerMode` is exactly `configModule.projectConfig.workerMode
=== "worker"` -- a string equality, not a presence check -- and the framework
defaults an absent `workerMode` to `"shared"`, which is not worker mode. That
is why `MEDUSA_WORKER_MODE: worker` is the one line in `worker.yaml` this
exposure property rests on, and why `tests/manifests.sh` now asserts it is
exactly `worker` on the worker and exactly `server` on `backend.yaml`
(`README.md` above already claimed the latter; the assertion is what makes it
provable rather than merely stated) -- deleting the worker's line, or setting
it to `server`, was measured to leave every other T13b assertion green while
`/app` answers `200`.

The worker gains no share of the reachability decision
[`010`](https://github.com/hannosirkel/lousydeal/blob/main/docs/decisions/010-the-admin-is-reachable-and-gated.md)
now grants the backend: `service.yaml` carries no `externalIP` for the worker, and
`allow-backend-ingress` selects `component: backend`, not `component:
worker`, so neither of that rule's two entries -- the storefront's or the
CIDR's -- ever reaches this pod. This closes the other half of the same
property: there is no route *to* Admin through the worker even from inside
the mesh, because the worker's own HTTP surface does not serve it.

**Boot time, three runs, same image and `args`:** `Server is ready on port:
9000` logged 2.81s, 2.84s and 2.86s after the container's `StartedAt`
timestamp (`podman inspect` vs. `podman logs --timestamps`), each run against
a cold `podman run` on this host with Redis and PostgreSQL already up.

**What `/health` checks, measured directly: nothing but the process being
alive.** `@medusajs/medusa/dist/commands/start.js:245` is
`app.get("/health", (_, res) => res.status(200).send("OK"))` -- unconditional,
and Medusa's own comment, one line above at `:244`, reads "Ideally this also
checks the readiness of the service, rather than just returning a static
response." To confirm rather than take the comment's word for it: with the worker above
still running, `podman stop t13b-redis` was run, and `/health` kept answering
`200` for the following minutes while the container's own logs filled with
`Error: getaddrinfo ENOTFOUND t13b-redis` from the Redis clients underneath.

**That is why both probes point at `/health` rather than nothing.**

- **Readiness gates the Deployment's own rolling update, not traffic.** The
  worker has no Service (T13a) and sits behind no ingress path -- but Argo CD
  does read this condition: it assesses Deployment health from
  `availableReplicas`/the `Available` condition, which is readiness-derived,
  and T15 builds a gated sync on that health assessment. On `replicas: 1`
  with the `strategy:` pinned above (`maxUnavailable: 0`, asserted by
  `tests/manifests.sh`; an unpinned default only reaches the same value
  because 25%/25% of one replica rounds down to zero), a new pod that never
  turns Ready blocks `kubectl`/Argo CD from retiring the old one -- the
  property this buys is that a broken image or a missing dependency cannot
  silently replace a working worker.
- **A liveness probe on `/health` restarts only the wedge case, not a
  crash.** A crashed process needs no probe: the kubelet restarts any
  container that exits on its own regardless of a liveness probe, and this is
  measured, not assumed -- `SIGKILL` on the running `node` child took the
  container down by itself, `Exited (137)`, with no probe involved. The
  probe's only marginal value is the process that neither exits nor answers:
  measured directly, `SIGSTOP` on the same child left the container `Up` and
  silent, `/health` timing out rather than erroring. It cannot fire on a
  Redis outage either way, because it is measured not to read Redis at all --
  so it cannot turn one into the `CrashLoopBackOff` that `redis:preflight`
  (T5) would otherwise cause by refusing every restart while Redis stays
  down. This is the reasoned trade this row makes: a liveness probe wired to
  something that *does* observe Redis (a custom `/ready` reading the
  preflight's own check, for instance) would restart the worker exactly when
  restarting cannot help, since the new container would refuse at the same
  preflight the running one never re-runs. `/health`'s narrowness is what
  keeps this probe honest about what it covers -- a wedged event loop, not
  "the worker can reach its dependencies" or "the worker is alive" (the
  kubelet already guarantees the latter) -- rather than a probe that appears
  to check more than it does.
- **Thresholds match `backend.yaml`'s** (`initialDelaySeconds: 10`/`30`,
  `periodSeconds: 5`/`10`), chosen rather than copied: both Deployments run
  the identical `npm run start` boot chain (`redis:preflight` then `medusa
  start`), and the boot time measured above for the worker -- 2.81-2.86s --
  clears a 10s readiness delay by 3.5x and a 30s liveness delay by ~10x, the
  same margins `backend.yaml`'s own thresholds give its identical chain.

**No NetworkPolicy admits the probe, confirmed against the render rather than
assumed.** `kubectl kustomize` on both overlays renders ten `NetworkPolicy`
resources (`tests/manifests.sh`'s own `expected_policy_names`), and grepping
that render for a rule selecting `app.kubernetes.io/component: worker` on
`Ingress` finds none -- `default-deny` declares `policyTypes: [Ingress,
Egress]` and no rules at all (`base/networkpolicy.yaml:2-9`), and it is the
only policy whose `Ingress` type reaches the worker pod, admitting nothing
from any pod.

That is not a gap this row needs to close, and the reason is documented and
stronger than "`NetworkPolicy` has no field to restrict it with": Kubernetes
states the guarantee directly -- *"traffic to and from the node where a pod
is running is always allowed, regardless of the IP address of the pod or the
node"* (kubernetes.io/docs/concepts/services-networking/network-policies) --
so a `kubelet` probe, which originates from the node, reaches the pod
regardless of what any `NetworkPolicy` in this namespace says. `ipBlock` is
in fact how a `NetworkPolicy` reaches node-sourced traffic when a rule wants
to select it -- `allow-storefront-ingress`, in this same base directory,
admits `192.168.0.0/16` that way -- so the worker's `Ingress` is not
unreachable for lack of a field; it is unreachable because it carries no
rule at all, a stronger absence than "no field could express one."

Nor is this untested against this project's own infrastructure. The
reference application ships the identical `default-deny`
(`plepic/base/networkpolicy.yaml:2-9`) alongside four `httpGet` probes across
two workloads -- `backend.yaml:127` (readiness, with liveness reusing it via
YAML anchor) and `storefront.yaml:166` (readiness) and `:171` (liveness) --
running in the Orange cluster today, and `orange/docs/current/cluster.md:20-29`
records that this K3s server's control plane includes a network policy
controller, i.e. that `default-deny` is actually enforced there, not merely
declared. Kubelet probes keep working against those workloads under that
enforcement.

## SIGTERM: accepted, not fixed here

T11 measured that `npm` as PID 1 does not forward `SIGTERM` to the child it
spawns, so the API and worker Deployments (both `npm run start`) exit **1**,
not 0 or 143, on an ordinary pod termination -- reconfirmed directly against
this row's build (`podman stop --time 30` on the built image completed in
about 1.1 seconds with exit code 1, not the full grace period). The storefront
does not share this problem: its image runs `node server.js` with every
package manager removed, and the same measurement against it produced exit
code 143 -- a normal, signal-forwarded shutdown -- in about 0.6 seconds.

Nothing in this row changes the images or their `args`; both are out of this
row's Files list and were pinned by T11. Given that, and that `npm`'s own
process exits quickly rather than hanging its full grace period regardless of
what `terminationGracePeriodSeconds` says, this base sets no non-default
`terminationGracePeriodSeconds` on `backend.yaml` or `worker.yaml`: raising it
would buy a wait nothing uses, and this build is a single replica behind no
public traffic in LD-01, so the accepted cost of an abrupt in-flight-request
drop is bounded. **This is an explicit acceptance, not an oversight.**

## Ten migration directories, not eleven

The predeploy Job mounts one `emptyDir` at ten paths inside the image, each
with its own `subPath` and each `readOnly` -- `readOnlyRootFilesystem: true`
on this Job's container, and Mikro-ORM's Migrator creates a migrations
directory for every module and provider it loads
(`@mikro-orm/migrations/Migrator.js:377`, `ensureMigrationsDirExists()`)
rather than tolerating a missing one. Measured directly, not copied from the
reference's eleven: `podman run --read-only --user 10001:10001` against
`localhost/lousydeal-backend:t11`, the only backend image on this host --
built before both `714b61d` and `27586a1`, not this row's HEAD -- iterating
the mount set against a real PostgreSQL and Redis until `medusa db:migrate`
stopped raising ENOENT. Eight packages ship no `dist/migrations` on the first
pass (`payment-stripe`, `auth-emailpass`, `fulfillment-manual`,
`notification-local`, `cache-inmemory`, `event-bus-redis`, `locking`,
`file`), and -- exactly as the reference predicts -- `locking` and `file`
each hide a second directory the log names only once the first eight are
mounted: `locking-redis` and `file-local`. Ten in total. `omniva` and the
reference's own SMTP `notifications` provider are absent because this
application registers neither module.

With all ten mounted, `npm run predeploy` clears `db:migrate` and reaches
`configure:commerce`, where it exits 1 on this image -- `27586a1`'s currency
fix, which this build predates, not a mount defect:

```console
$ podman run --rm --read-only --tmpfs /tmp --user 10001:10001 \
    --network <postgresql+redis, no external route> \
    <the ten module-migrations mounts, as in base/predeploy-job.yaml> \
    localhost/lousydeal-backend:t11 npm run predeploy
...
"message":"Migration scripts completed"
...
> configure:commerce
"level":"error","message":"Error running script: The store does not support usd; it cannot price anything this deployment sells"
$ echo $?
1
```

Adding a module or provider whose package ships no migrations directory
reproduces this failure and needs another entry in both
`base/predeploy-job.yaml` and `tests/manifests.sh`.

## Digest promotion

Both overlays begin on the all-zero SHA-256 sentinel, naming an image that was
never built. T12 (`lousydeal` repository, running after this row) has yet to
add `scripts/update-gitops-digest.sh`; when it lands, it is to rewrite the two
`digest:` lines on merge to `main` by matching a literal three-line
`name`/`newName`/`digest` block per image and refuse the whole file if it
cannot find exactly one -- the same shape
the `plepic` (not `deploys/plepic`) repository's `scripts/update-gitops-digest.sh:221-235` already matches for the
reference. That is why each entry here carries those three keys and nothing
else, and `tests/manifests.sh` asserts that shape on both overlays rather than
trusting it. No image assertion in this test
knows or asks which environment it is inspecting, which is what lets the two
overlays be promoted independently -- test on a label, live on merge -- the
same property the reference's own contract states.

## What T14 must inject

Every value below is per-environment configuration this public repository
does not carry. Registered OpenBao source names follow decision
[`006`](https://github.com/hannosirkel/lousydeal/blob/main/docs/decisions/006-two-naming-categories-in-keys.md):
application-first, `lousydeal-…` live and `lousydeal-test-…` test.

| Secret | Keys | Consumed by |
| --- | --- | --- |
| `lousydeal{-test}-database-admin` | `POSTGRES_SUPERUSER_PASSWORD`, `MEDUSA_ADMIN_EMAIL`, `MEDUSA_ADMIN_PASSWORD` | PostgreSQL StatefulSet (first key), predeploy Job (other two) |
| `lousydeal{-test}-runtime-credentials` | `DATABASE_PASSWORD`, `REDIS_PASSWORD`, `JWT_SECRET`, `COOKIE_SECRET`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PAYMENT_METHOD_CONFIGURATION_ID`, `STRIPE_PUBLISHABLE_KEY` | backend, worker, predeploy, storefront |
| `lousydeal{-test}-publishable-key` | `publishableKey` | storefront only |

The publishable key is a staged late-bootstrap value, the same shape as the
reference's: Medusa creates it after the database and backend exist, so it is
its own Secret rather than a key folded into `runtime-credentials`, projected
once the backend has run and issued one.

`STRIPE_PAYMENT_METHOD_CONFIGURATION_ID` may be absent from
`runtime-credentials` for a time -- it is `optional: true` on every
`secretKeyRef` referencing it, precisely so a namespace can start before that
Dashboard object exists.

## Validate locally

```bash
bash lousydeal/tests/manifests.sh
kubectl kustomize lousydeal/overlays/live | kubeconform -strict -summary
kubectl kustomize lousydeal/overlays/test | kubeconform -strict -summary
```

This manifest contract checks isolation, pod hardening, the exact
NetworkPolicy set (including the backend exposure shape above -- the
storefront's rule fixed at index 0, the admin CIDR rule fixed at index 1, that
no other workload's policy carries that CIDR by name, and that the backend
Service's own port and the storefront's `MEDUSA_BACKEND_URL` agree), the
required- and forbidden-environment-variable contracts
(including that `MEDUSA_ADMIN_EMAIL`/`MEDUSA_ADMIN_PASSWORD` reach only the
predeploy Job, sourced from the environment-scoped `*-database-admin`
Secret and from no other Secret name, and never via `envFrom`), digest-pinned
images and their census, the predeploy migration-mount contract, and the
Sync-hook wave ordering. These manifests describe desired state only; their
presence here does not by itself claim that either environment has finished a
sync. An Argo CD Application does reconcile `lousydeal` as of `orange` `main`
`fc08f33` -- that wiring is what makes this claim about intent rather than
about a running cluster, not the absence of an Application.
