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

Both overlays intentionally begin with the all-zero SHA-256 sentinel for the
backend and storefront images. The sentinel is not deployable. After this
bootstrap commit, image digest lines are promotion state owned only by the
Plepic repository's reviewed `scripts/update-gitops-digest.sh`: test promotion
updates only `overlays/test`, and release promotion updates only
`overlays/live`. Do not edit those digest lines by hand.

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
network boundaries, Secret names and keys, sentinel images, and the exact
external ports. These manifests describe desired state only; their presence in
this repository does not claim that either environment has been deployed.
