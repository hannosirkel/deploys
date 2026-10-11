# Lunar Base GitOps State

This application root holds the namespaced Kubernetes resources for the Lunar
Base online card game. The game's source and its image build live in
[`plepicgames/lunar-base`](https://github.com/plepicgames/lunar-base).

These manifests describe desired state only. No Argo CD Application reads this
root yet, so nothing here is deployed.

## One environment

The game has one environment, live, by the operator's decision of 2026-10-11.
There is no test overlay, no test namespace and no test promotion. The game's
first run in the cluster is therefore in live. It runs behind an address that
nobody is sent to until the shop page links it.

The contract test refuses a second directory under `overlays/`, so a test
overlay cannot come back without its own assertions.

## What is here

`base/` defines one Deployment, its Service, the claim for the game logs, and
two NetworkPolicies: default-deny, and ingress to the game. `overlays/live` is
the only deployable root:

| Namespace | Port on the WireGuard address | Jev | Egress |
| --- | --- | --- | --- |
| `lunar-base` | 8141 | on, key from the Secret `lunar-base-jev` | DNS, and TCP 443 to public addresses |

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
- **HTTPS egress is wide on purpose.** A NetworkPolicy cannot match a host
  name, and the Jev service publishes no fixed range. The rule allows TCP 443
  to public addresses only: it excludes every special-use IPv4 block, and the
  private-range exclusions cover the cluster's own networks.

## What the platform supplies

`orange` owns everything below. The values come from `orange-inventory` and
never enter this repository. The contract test never sees them.

| Supplied | Where | Detail |
| --- | --- | --- |
| Namespace | `lunar-base` | With the Restricted Pod Security labels. This root declares no Namespace |
| Jev Secret | namespace `lunar-base` | An External Secrets projection that creates the Secret `lunar-base-jev` with the key `api-key`. The Deployment cannot start without it |
| Ingress source ranges | NetworkPolicy `allow-game-ingress` | JSON patch: replace `/spec/ingress/0/from`. The tracked `192.0.2.0/24` is a documentation range (RFC 5737), so an unpatched Application admits nobody |
| Allowed origins | Deployment `lunar-base`, container `game` | Strategic-merge patch on `env`, keyed on `name`: `LUNAR_ALLOWED_ORIGINS`, as a literal `value`. The tracked `https://example.com` is a reserved name that matches no real browser |
| Port | 8141 | Reserved in the platform's port list; the public route points at it |

## Promotion

The overlay begins on the all-zero SHA-256 sentinel. It names an image that
was never built, so a workload that reaches a cluster on it fails to pull.

The release workflow of `plepicgames/lunar-base` is the only writer of the
digest. On a merge to the application's `main` it rewrites the one `digest:`
line of the `images:` entry for `ghcr.io/plepicgames/lunar-base` in
`lunar-base/overlays/live/kustomization.yaml`. There is no other promotion.

The entry carries exactly `name`, `newName` and `digest`, in that order, and
the contract test refuses a fourth key. Never edit a digest by hand. Roll back
by promoting a known-good digest.

The contract test asserts a digest shape, not a digest value, so the sentinel
and a promoted digest both pass.

## Validate

```bash
bash lunar-base/tests/manifests.sh
kubectl kustomize lunar-base/overlays/live >/dev/null
```
