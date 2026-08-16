# Plepic GitOps State

This application root contains the namespaced Kubernetes resources for the
Plepic site and shop. Application source and image builds live in the separate
`hannosirkel/plepic` repository; Orange/Ansible owns namespaces, Pod Security
labels, External Secrets projections, Argo CD Applications, private source
ranges, and deployment orchestration.

`base/` defines the shared PostgreSQL, Redis, Medusa backend and worker,
storefront, migration and catalogue-import Jobs, storage, Services, and
NetworkPolicies. The deployable roots are:

- `overlays/live`, which renders into namespace `plepic` and exposes only the
  storefront on WireGuard port 8101 and the backend on WireGuard port 8102;
- `overlays/test`, which renders isolated names, storage, database state, and
  Secret references into namespace `plepic-test`, on ports 8111 and 8112.

PostgreSQL, Redis, and assets are namespace-local and have no external address.
The two externally reachable Services remain `ClusterIP` and declare only the
Orange WireGuard address as an `externalIP`; there is no Ingress, NodePort, or
LoadBalancer. Orange supplies the real per-environment ingress and SMTP source
patches without placing live addresses in this public repository.

The base also carries reserved non-secret mail and merchant placeholders. The
SMTP host, envelope sender, contact recipient, merchant legal name, registered
address, legal contact address, and return address must all be replaced by the
private per-environment configuration before deployment. Storefront and every
backend-image workload deliberately receive the same four `MERCHANT_*` values,
because the storefront legal pages and durable order-confirmation email resolve
the same approved withdrawal notice.

`STORE_CORS`, `ADMIN_CORS`, and `AUTH_CORS` are declared on every backend-image
workload with an explicitly empty value, and must stay empty. Nothing reaches
the backend cross-origin: the storefront proxies the allowlisted `/store-api`
prefixes from its own origin and Medusa Admin is served by the backend itself,
so an origin here would be a public hostname this repository must not carry.
They are declared rather than omitted because the image requires all three at
module scope — a workload that simply forgot them must still fail loudly — and
the same reasoning puts `JWT_SECRET` and `COOKIE_SECRET` on the migration and
catalogue-import Jobs, which construct the whole configuration before doing any
work. The contract test asserts the full required set against every workload
running the backend image; that list is declared in `tests/manifests.sh` and
names its source, because the image's repository is not readable at validation
time.

`REDIS_HOST`, `REDIS_PORT`, and `REDIS_PASSWORD` reach **all four** backend-image
workloads, the two lifecycle Jobs included, and `allow-redis-ingress` and
`allow-redis-egress` admit all four. The Jobs are not an exception: `medusa exec`
boots the whole module container — `skipLoadingEntryPoints` skips routes and
subscribers, not modules — so the Redis event bus and workflow engine open a
connection at module load in a Job exactly as they do in a Deployment. A Job
without them does not quietly fall back to an in-process bus; it retries
forever, and for the predeploy Job that is a Sync hook that never completes and
a sync gate that blocks every wave behind it. No `REDIS_URL` is supplied here:
the three parts are what these manifests project and the application composes
the URL, the same split as the five `DATABASE_*` parts.

`SITE_BASE_URL`, `SITE_CANONICAL_HOST`, and `SITE_TEST_HOSTNAMES` are declared on
the storefront in both environments with reserved-name placeholders, and the real
per-environment hostnames are injected from Orange. They are declared rather than
left to the application's defaults because those defaults do not fail:
`storefront/src/config/hosts.ts` falls back to `https://example.com` and to an
empty test-hostname list, so an unconfigured storefront starts and serves while
emitting `example.com` as every canonical URL, `og:url`, sitemap entry and
`hreflang` alternate, and while `isTestHost()` answers false for every request —
which is how a test environment ships without `noindex`.

Live declares `SITE_TEST_HOSTNAMES` **empty** rather than omitting it, on the
same reasoning as the three CORS variables: `readEnvList` cannot tell an empty
value from an absent one, so the declaration costs nothing at runtime and buys
the reviewer the difference between "live has no unindexed hostname" as a stated
decision and as an omission nobody can date. It also lets the contract require
all three in both environments, so the live/test difference is a value
difference a diff shows rather than a presence difference a diff must be read
for. In test, the canonical host and the single test hostname are deliberately
the same string: that identity is what makes `isTestHost()` true for every
request the test environment serves.

The storefront's Medusa credential is `MEDUSA_PUBLISHABLE_API_KEY`. That is the
name `storefront/src/config/runtime-env.ts` lists and `src/lib/medusa-client.ts`
requires; these manifests previously named it `MEDUSA_PUBLISHABLE_KEY`, with the
right Secret and the right key, so External Secrets projected the credential
correctly and every Store API call from the storefront would still have failed.
The Secret name and key are unchanged, and the aggregate Secret contract could
not have caught it, because it compares Secret names and keys and both were
right.

Newsletter API credentials are an existing runtime Secret projection but are
mounted only by the backend API pod; workers and lifecycle Jobs cannot subscribe
addresses. That pod also enforces a deployment-wide limit of 20 valid signup
attempts per 600 seconds with one atomic counter in its environment's existing
authenticated Redis. The key is global: no address, IP, Turnstile token, or
other subscriber-derived value is stored in Redis.

Both overlays intentionally begin with the all-zero SHA-256 sentinel for the
backend and storefront images. It names an image that was never built, so the
sentinel is not deployable in the only sense this repository can guarantee: a
workload that reaches a cluster on it fails to pull rather than running some
wrong version.

Refusing the sentinel *before* an Application is applied is a deployment-time
control, and it does not live here. Servitium is the precedent and splits it the
same way: its manifest contract requires a 64-hex digest and therefore accepts
the all-zero sentinel exactly as this contract does, while the refusal itself
sits in Orange, in `roles/argocd/tasks/servitium.yml`, which fetches each
overlay's `kustomization.yaml` and rejects the sentinel when the rendered
Applications differ. Accepting both shapes here is that precedent, not a
relaxation of it. The Orange half does not exist for Plepic yet — no
`roles/argocd/tasks/plepic.yml`, no Plepic sentinel variable — and writing it is
a Task 6 checkbox. Until then the sentinel's only backstop is the missing image.

After this bootstrap commit, image digest lines are promotion state owned only by
the Plepic repository's reviewed `scripts/update-gitops-digest.sh`: test
promotion updates only `overlays/test`, and release promotion updates only
`overlays/live`. Do not edit those digest lines by hand.

Because that script rewrites a literal `name` / `newName` / `digest` block, the
contract here requires each overlay image entry to carry those three keys and
nothing else. An entry with an extra key can still render and pin correctly — a
`newTag` beside a digest resolves to the digest — but the next promotion into
that overlay would be refused, so it is caught here instead of at the release
that needs it.

The manifest contract therefore asserts a digest *shape*, not a digest value:
every container image in both rendered overlays must carry an
`@sha256:<64 hex>` digest, and the bootstrap sentinel and a promoted digest are
equally valid. That is deliberate. The two overlays are promoted independently —
test on a `deploy-test` label, live on merge to `main` — so between a test
promotion and the release that follows it, one overlay legitimately carries a
real digest while the other is still on the sentinel. An assertion pinned to the
sentinel would have made promotion and the contract mutually exclusive, and did:
the first test promotion was refused by this repository rather than by anything
wrong with the manifests. No image assertion — the digest requirement, the
census, or the per-repository digest uniformity — knows or asks which
environment it is inspecting. The contract as a whole does branch on
environment, for the name suffix, the Secret references and the merchant
values; nothing concerning image pinning does, which is what lets the two
overlays be promoted independently.

Alongside the digest requirement the contract holds a container census — four
containers run the backend image and one runs the storefront image, counted by
image repository so a container naming an application image by tag is counted
rather than invisible. Digest pinning and the census are independent: a fifth
correctly pinned container is refused by the census, and an unpinned container
is refused whether or not the census is right.

The contract also requires the containers running one application image to agree
on one digest, so a lifecycle Job cannot run a different backend build than the
backend it prepares. Sentinel equality forced that implicitly and a per-container
shape requirement does not, so it is asserted directly. It compares the digests
to each other and never to a fixed value, which is why it survives promotion.

Runtime, database-administrator, and Medusa publishable-key Secrets are
projected by External Secrets and are not rendered here. The publishable key is
a staged late-bootstrap value: Medusa creates it after the database and backend
exist, the explicit OpenBao lifecycle imports it separately for test or live,
and ESO then projects `plepic{-test}-publishable-key` for the storefront. The
migration Job has no Kubernetes Secret-write authority and mounts no API token.

The PVC sizes are local-path storage requests, not quotas, replication, or a
backup guarantee. PostgreSQL and assets are durable recovery inputs; Redis AOF
improves crash recovery but Redis remains rebuildable state. Backup, restore,
and cross-resource epoch coordination are owned by Orange and must be in place
and rehearsed before launch.

Validate the rendered contract locally with:

```bash
bash plepic/tests/manifests.sh
kubectl kustomize plepic/overlays/live >/dev/null
kubectl kustomize plepic/overlays/test >/dev/null
```

The manifest contract checks isolation, hardening, ordered Argo CD Sync waves,
network boundaries, Secret names and keys, digest-pinned images and their
census, and the exact external ports. These manifests describe desired state
only; their presence in this repository does not claim that either environment
has been deployed.
