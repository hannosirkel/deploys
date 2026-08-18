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
for.

The rule the contract holds for test is that **`SITE_TEST_HOSTNAMES` contains
every hostname the test storefront answers to** — not that it equals the
canonical host. `isTestHost(host, config)` matches the *incoming request's*
`Host` header against that list and never consults the canonical host; that is
the separate `isCanonicalHost`. The two coincide today only because the test
storefront answers to exactly one name, and stating the coincidence as the
mechanism is how a second hostname later gets added to a deployment and not to
the list, which is a test hostname served without `noindex`. Live carries the
mirror of the same rule: no hostname it answers to — as far as a manifest can
know, which is the host of its base URL and its canonical host — may appear in
its list, or the live site tells every crawler not to index it while every page
still renders perfectly. The further names live answers to, the `www` form and
the retired campaign domains the redirect map serves, are declared in no
manifest here, so this contract cannot see them and does not claim to.

Three properties are asserted over the **option table** in `tests/manifests.sh`
rather than over the rendered values, because the rendered values are compared
to that table for exact equality and an editor who changes a value must change
the table in the same commit. An assertion over a rendered value the equality
already refuses is decoration; the same assertion over the table constrains what
may be written there. They are: every hostname the table names is an RFC 2606
reserved name — the structural boundary the address exemption never reached,
because its pattern requires a `local-part@` and a bare hostname never enters it
— the canonical host is the base URL's host, and the `noindex` rule above.

`CATALOGUE_IMPORT_ENVIRONMENT` is supplied per environment, `live` in the base
and `test` in the test overlay, because the import refuses without it: it
accepts exactly `live` or `test` and compares the value against the identity
recorded for the staged archive, which is what stops a live export being
imported into test or the reverse. Its companion
`CATALOGUE_IMPORT_ARCHIVE_SHA256` is a per-archive value, so no literal
placeholder is tracked. The Job reads it by explicit `secretKeyRef` from the
dedicated one-key `plepic{-test}-import-expectation` Secret instead.

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

Runtime, database-administrator, Medusa publishable-key, redirect-map, and
import-expectation Secrets are projected by External Secrets and are not
rendered here. The publishable key is a staged late-bootstrap value: Medusa
creates it after the database and backend exist, the explicit OpenBao lifecycle
imports it separately for test or live, and ESO then projects
`plepic{-test}-publishable-key` for the storefront. The migration Job has no
Kubernetes Secret-write authority and mounts no API token.

The PVC sizes are local-path storage requests, not quotas, replication, or a
backup guarantee. PostgreSQL and assets are durable recovery inputs; Redis AOF
improves crash recovery but Redis remains rebuildable state. Backup, restore,
and cross-resource epoch coordination are owned by Orange and must be in place
and rehearsed before launch.

## What Task 6 must inject

Every value below is per-environment configuration that this public repository
deliberately does not carry. Static values have reserved placeholders or are
absent, and Orange patches their real values onto the Argo CD `Application` from
the private inventory, exactly as it does for Servitium's source ranges.
Purpose-specific file or cadenced state instead arrives through the dedicated
ESO projections whose Secret names and keys these manifests declare.
**The placeholders in this repository are not defects to be corrected in place**
— replacing one with a real hostname is the thing the contract tests refuse.

*Storefront, live namespace `plepic`:*

| Variable | Value Task 6 supplies |
|---|---|
| `SITE_BASE_URL` | the live public origin: `https://` and the apex hostname, no port, path, query or fragment — `hosts.ts` refuses anything else |
| `SITE_CANONICAL_HOST` | the same apex hostname, bare; it must equal the base URL's host |
| `SITE_TEST_HOSTNAMES` | **empty, and it stays empty.** A live hostname here is a live site serving `noindex` |
| `ANALYTICS_MEASUREMENT_ID` | the GA4 measurement ID. Live only. It is an account identifier, so it reaches a pod only from the inventory and never from a tracked file; absent, the analytics loader never mounts |
| `MERCHANT_REGISTRATION_NUMBER`, `MERCHANT_VAT_NUMBER`, `MERCHANT_PHONE_NUMBER` | the three legally required disclosures no manifest here declares. Absent, each renders as a named visible gap plus a page-level incompleteness notice — which is why they are deferred rather than placeheld, and also why they must not ship missing |
| `MERCHANT_LEGAL_NAME`, `MERCHANT_REGISTERED_ADDRESS`, `MERCHANT_CONTACT_ADDRESS`, `MERCHANT_RETURN_ADDRESS` | the real four, replacing the reserved placeholders these manifests declare |
| `EXTERNAL_URL_CONSUMER_DISPUTES_COMMITTEE` | optional. Absent renders one link fewer and nothing else — no gap marker, no notice. Supply it, but do not hold a release for it |
| `REDIRECT_MAP_PATH` | **already supplied here** as `/var/run/plepic/redirect-map/redirect-map.json`. The file is projected read-only from exactly the `redirect-map.json` key of `plepic-redirect-map` |

*Storefront, test namespace `plepic-test`:*

| Variable | Value Task 6 supplies |
|---|---|
| `SITE_BASE_URL` | the test origin, same shape rule |
| `SITE_CANONICAL_HOST` | the test hostname, bare, equal to the base URL's host |
| `SITE_TEST_HOSTNAMES` | **every hostname the test storefront answers to**, its canonical host among them, as a **comma-separated** list of bare hostnames — no scheme, port or path. Not "the canonical host": `isTestHost()` matches the request's `Host` header against this list, so a second name the deployment answers to and this list omits is a test hostname served without `noindex`. `readEnvList` splits on commas only; any other separator leaves the whole value as one entry, which then fails the bare-hostname check and refuses to start rather than silently matching nothing |
| `ANALYTICS_MEASUREMENT_ID` | **must not be supplied.** One GA property exists with no test data stream, and the test environment has no analytics at all. Absent is the required behaviour, not an omission to be tidied |
| the three `MERCHANT_*` above, and the real four | the test environment renders the same legal pages |
| `EXTERNAL_URL_CONSUMER_DISPUTES_COMMITTEE` | optional, as live |
| `REDIRECT_MAP_PATH` | the same literal path and the same map content as live, projected from `plepic-test-redirect-map`. Supplying it in test makes the retired-domain redirects verifiable before public routing exists |

*Catalogue-import Job, both namespaces:*

| Variable | Value Task 6 supplies |
|---|---|
| `CATALOGUE_IMPORT_ENVIRONMENT` | **already supplied here** — `live` in the base, `test` in the test overlay — and Task 6 must not override it with anything else. The import accepts exactly these two |
| `CATALOGUE_IMPORT_ARCHIVE_SHA256` | the Job already declares an explicit reference to the same-named key in `plepic-import-expectation` or `plepic-test-import-expectation`. Before each import, Orange supplies the bare 64-lowercase-hex digest of the archive actually staged; no `sha256:` prefix and no tracked literal |

*Backend-image workloads:* the SMTP host, envelope sender, contact recipient and
the four merchant values these manifests declare are reserved placeholders on
the same terms — see "The base also carries reserved non-secret mail and
merchant placeholders" above — and the live per-Service ingress source ranges
reach the cluster the same way, as Ansible-rendered patches on the Application.
The backend API alone declares literal `MEDUSA_WORKER_MODE=server`; the worker
and both lifecycle Jobs deliberately do not. This keeps the API a publisher and
the worker the only background consumer.

*Delivery constraints, which are part of the specification:*

- **Static private configuration uses literal `value:` entries, never External
  Secrets.** Site identity, analytics, merchant identity, mail routing, and
  optional external links are Application patches from private inventory. The
  storefront contract independently refuses a site host delivered by reference.
- **Redirect content and the archive expectation use separate, exact ESO
  projections.** Do not add either to the runtime-credential Secret. The
  storefront volume projects only `redirect-map.json`; the import Job references
  only `CATALOGUE_IMPORT_ARCHIVE_SHA256`. Because ESO owns those Secrets and they
  are absent from the Kustomize resource graph, the test overlay explicitly
  replaces both base Secret names; `nameSuffix` cannot do that association.
- **Restart the storefront after changing redirect-map data.** The application
  memoizes the parsed file, so updating the Secret alone does not change redirects
  in an already-running pod. Roll out both storefronts when the shared map changes.
- **Patch by strategic merge on `env`, keyed on `name`** — not by JSON-patch
  index. The Servitium precedent replaces `/spec/ingress/0/from` by index, which
  is brittle here because the index depends on base ordering; the test overlay
  already merges `env` by `name`, which is why a renamed variable had to be
  changed in the base *and* the overlay rather than in one of them.
- Orange's patches are applied to the `Application`, so they never enter this
  repository and the contract tests never see them. Keeping the tracked values
  reserved is what lets both remain true.

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

`plepic-assets` shares sync wave `0` with the backend and worker Deployments
that mount it. K3s `local-path` uses `WaitForFirstConsumer`; placing the claim in
an earlier blocking wave would prevent Argo CD from creating a consumer and
leave the claim Pending indefinitely. PostgreSQL and Redis likewise keep each
claim in the same wave as its consuming StatefulSet.
