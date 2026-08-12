# Deploys GitOps State

This shared repository holds deployable GitOps state for multiple applications.
Each application owns a top-level `<app>/` directory containing its base,
overlays, tests, and application-specific documentation. Add future
applications as sibling roots without making the repository root a deployable
Kustomization.

The repository currently has two sibling application roots:

- `servitium/` contains the shared Servitium workload definition and its live
  and test overlays.
- `plepic/` contains the shared Plepic site-and-shop stack and isolated live
  and test overlays. See [`plepic/README.md`](plepic/README.md) for its
  ownership, exposure, secret-bootstrap, promotion, and recovery contracts.

Servitium's two deployable overlays are:

- `servitium/overlays/live` deploys the production `servitium` workload. Its
  state is merge-promoted.
- `servitium/overlays/test` deploys the isolated `servitium-test` workload.
  Its image digest is label-promoted and its overlay is replaceable.

Both overlays start on the known-good Servitium image digest so the test
Application can bootstrap independently. Later promotions update each overlay
without changing the other.

Orange/Ansible owns namespace creation and Restricted Pod Security labels;
these GitOps overlays only contain namespaced workload resources. Both use a
ClusterIP Service that declares only the node's WireGuard address
`192.168.21.2` as an `externalIP`; neither allocates a LoadBalancer or
NodePort. Their NetworkPolicies admit direct WireGuard and administrator-LAN
sources, while host firewalls restrict Mihkel to the declared endpoints and
keep TCP 8098 and 8099 out of the public allow-list. The manifest tests enforce
the environment boundaries, restricted non-root container contract,
default-deny policy, DNS egress, and MySQL-only egress.

Validate Servitium locally with:

```bash
bash servitium/tests/manifests.sh
kubectl kustomize servitium/overlays/live >/dev/null
kubectl kustomize servitium/overlays/test >/dev/null
```

Validate Plepic locally with:

```bash
bash plepic/tests/manifests.sh
kubectl kustomize plepic/overlays/live >/dev/null
kubectl kustomize plepic/overlays/test >/dev/null
```

The `Validate` workflow runs both application roots' checks for pull requests
and pushes to `main`. The repository root remains non-deployable.
