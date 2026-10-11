# Lunar Base GitOps State

This application root holds the namespaced Kubernetes resources for the Lunar
Base online card game. The game's source and its image build live in
[`plepicgames/lunar-base`](https://github.com/plepicgames/lunar-base).

These manifests describe desired state only. No Argo CD Application reads this
root yet, so nothing here is deployed.

## What is here

`base/` defines one Deployment, its Service, the claim for the game logs, and
two NetworkPolicies: default-deny, and ingress to the game. The deployable
roots are:

| Overlay | Namespace | Port on the WireGuard address | Jev | Egress |
| --- | --- | --- | --- | --- |
| `overlays/live` | `lunar-base` | 8141 | on, key from the Secret `lunar-base-jev` | DNS, and TCP 443 to public addresses |
| `overlays/test` | `lunar-base-test` | 8151 | off, no Secret reference | none |

The test overlay also adds the name suffix `-test` to every resource.

- **One replica, strategy `Recreate`.** The lobby and every game live in the
  memory of one process. There is no autoscaler and no PodDisruptionBudget.
  Each deployment ends the games in progress. See the application's decision
  [0005](https://github.com/plepicgames/lunar-base/blob/main/docs/decisions/0005-run-one-replica-with-recreate.md).
- **Game logs.** The claim `lunar-base-games` (1Gi) is mounted at
  `/var/lib/lunar-base/games`, the only writable path. The server deletes a
  log after 30 days.
- **The container** runs as user and group 10001 with a read-only root
  filesystem, no privilege escalation, no capabilities and the `RuntimeDefault`
  seccomp profile. The image must run under that numeric user.
- **The Service** is `ClusterIP` and declares only the Orange WireGuard address
  as an `externalIP`. There is no Ingress, NodePort or LoadBalancer.
- **Live HTTPS egress is wide on purpose.** A NetworkPolicy cannot match a host
  name, and the Jev service publishes no fixed range. The rule allows TCP 443
  to any address outside the private and link-local ranges, which hold the
  cluster's own networks.

## What the platform supplies

`orange` owns everything below. The values come from `orange-inventory` and
never enter this repository. The contract test never sees them.

| Supplied | Where | Detail |
| --- | --- | --- |
| Namespaces | `lunar-base`, `lunar-base-test` | With the Restricted Pod Security labels. This root declares no Namespace |
| Jev Secret | namespace `lunar-base` only | An External Secrets projection that creates the Secret `lunar-base-jev` with the key `api-key`. The live Deployment cannot start without it |
| Ingress source ranges | NetworkPolicy `allow-game-ingress`, both environments | JSON patch: replace `/spec/ingress/0/from`. The tracked `192.168.0.0/16` is a placeholder |
| Allowed origins | Deployment `lunar-base`, container `game`, both environments | Strategic-merge patch on `env`, keyed on `name`: `LUNAR_ALLOWED_ORIGINS`, as a literal `value`. The tracked `https://example.com` and `https://test.example.org` are reserved names that match no real browser |
| Ports | 8141 (live), 8151 (test) | Reserved in the platform's port list; the public route points at them |

A patch on the Application names a resource by its base name, without the
`-test` suffix, as the Plepic Applications do.

## Promotion

Both overlays begin on the all-zero SHA-256 sentinel. It names an image that
was never built, so a workload that reaches a cluster on it fails to pull.

The release workflow of `plepicgames/lunar-base` is the only writer of the
digest. It rewrites the one `digest:` line of the `images:` entry for
`ghcr.io/plepicgames/lunar-base`:

- `lunar-base/overlays/live/kustomization.yaml` on a merge to the
  application's `main`;
- `lunar-base/overlays/test/kustomization.yaml` on a `deploy-test` label.

The entry carries exactly `name`, `newName` and `digest`, in that order, and
the contract test refuses a fourth key. Never edit a digest by hand. Roll back
by promoting a known-good digest.

The contract test asserts a digest shape, not a digest value, so the sentinel
and a promoted digest both pass and the two overlays are promoted separately.

## Validate

```bash
bash lunar-base/tests/manifests.sh
kubectl kustomize lunar-base/overlays/live >/dev/null
kubectl kustomize lunar-base/overlays/test >/dev/null
```
