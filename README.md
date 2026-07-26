# Servitium GitOps State

The shared workload definition is in `base/`. Argo CD reconciles either
environment-specific overlay, each of which selects Servitium by immutable
digest:

- `overlays/live` deploys the production `servitium` workload. Its state is
  merge-promoted.
- `overlays/test` deploys the isolated `servitium-test` workload. Its image
  digest is label-promoted and its overlay is replaceable.

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

Validate locally with:

```bash
bash tests/manifests.sh
kubectl kustomize overlays/live >/dev/null
kubectl kustomize overlays/test >/dev/null
```
