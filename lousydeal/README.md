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

Only the storefront carries an `externalIP`, the shared WireGuard address
`192.168.21.2`, on port 8121 (live) / 8131 (test) -- the next free slots after
Plepic's 8101/8102/8111/8112 and Servitium's 8098/8099 on that one shared
address. **The backend Service carries none.** This is the one property that
makes this root's shape differ from the reference's rather than merely copy
it: Target Exposure in `docs/working/ld-01-foundation.md` states the Medusa
Admin the backend image serves on port 9000 carries "no public hostname, in
any encoding, never in LD-01," and the reference's own backend Service exists
specifically to expose Admin to an operator over that same WireGuard address.
A ClusterIP with no external route is what makes the forbidding true rather
than stated, and `allow-backend-ingress` carries the same decision on the
network side: it admits only the storefront's own pod selector on 9000, not
the reference's `192.168.0.0/16` administrative CIDR. Reaching Admin at all
is out of scope for every row in this plan. **`allow-backend-ingress` carries a
single `ingress[].from` rule whose entry is that pod selector, not the
reference's two rules with a CIDR at index 0** (`plepic/base/networkpolicy.yaml:36-44`)
-- so T15's Argo CD Application for this row must not render the reference
template's `replace /spec/ingress/0/from` patch
(`orange/roles/argocd/templates/plepic-application.yaml.j2:53-66`) against
`backend` here, or it would delete this rule and substitute a private CIDR
onto port 9000.

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
is true of every `MERCHANT_*` and `SITE_*` name and the SMTP block: this
storefront reads no `SITE_*` variable at all
(`storefront/src/config/runtime-config.ts`'s own header: "no MERCHANT_* field
-- no row in this slice renders an imprint"), and nothing in this application
sends mail, so no `allow-smtp-submission-egress` policy exists in this base.

## The worker runs the same `args` as the backend

`backend/package.json` declares `build`, `start`, `redis:preflight`,
`configure:commerce`, `seed:product`, `predeploy`, `typecheck` and
`test:unit` -- no `start:worker`. The reference's own worker names a script
that sets `MEDUSA_WORKER_MODE=worker` inline; this repository has none to
name, so `worker.yaml` runs the identical `[npm, run, start]` and sets
`MEDUSA_WORKER_MODE=worker` as a container `env:` entry instead. Medusa's
framework reads that variable from the process environment regardless of
which script started it, so the two are equivalent -- and `backend.yaml`
states `MEDUSA_WORKER_MODE=server` explicitly for the same reason.

The worker carries no readiness or liveness probe. That is T13b, not this
row -- see the plan's second T13 checkbox -- and `tests/manifests.sh` asserts
the absence as a fact this row leaves for that one to change.

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
| `lousydeal{-test}-database-admin` | `POSTGRES_SUPERUSER_PASSWORD` | PostgreSQL StatefulSet |
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
NetworkPolicy set (including the no-externalIP/no-CIDR backend exposure
boundary above), the required- and forbidden-environment-variable contracts,
digest-pinned images and their census, the predeploy migration-mount contract,
and the Sync-hook wave ordering. These manifests describe desired state only;
their presence here does not claim that either environment has been deployed
-- no Argo CD Application points at `lousydeal` yet.
