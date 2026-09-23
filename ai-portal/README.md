# AI Portal GitOps state

`overlays/live` is the single production root. Orange owns its `ai-portal`
namespace and the Argo CD Application that will point here. No Application
points at this root yet, so these resources remain inert until the workload
and backup contracts are ready.

The root now includes one authenticated MongoDB StatefulSet with a 5 GiB
persistent volume and a ClusterIP Service. Its root and LibreChat application
passwords must be seeded in OpenBao and projected as the `ai-portal-mongodb`
Secret by Orange's External Secrets contract before the Application is
created. The database is isolated by default-deny NetworkPolicies; only chat,
backup, and recovery pods may connect to it. Add a verified backup and restore
path before the first chat workload deploys.

The first LibreChat chat release has one OpenRouter endpoint. The default
server-enforced model specifications allow `qwen/qwen3.8-flash` and
`~deepseek/deepseek-flash-latest` for `restricted` and `user`. The `admin`
role override disables specification enforcement and fetches OpenRouter's
catalogue. Jev 1.13 belongs to a later Decisions API integration, and Qwen
Image 3 Pro to a separate image feature.

The LibreChat bootstrap must install `admin-override.json` as an active
role-scoped config for `ADMIN` before the chat workload starts. Until then,
the base policy also limits administrators to the two approved chat models.
That fails closed. OIDC role sync will map the Authentik `ai-portal-user`
claim to a LibreChat role of the same name, while `USER` remains the
restricted fallback. `OPENID_ADMIN_ROLE` separately grants `ADMIN` from
the `ai-portal-admin` claim. Local password registration and login are
disabled in the workload environment.

The config files are JSON syntax accepted by LibreChat's YAML parser, so the
policy test can inspect them without another dependency. They hold no
credential; `${OPENROUTER_KEY}` resolves from an ESO-managed Secret.

Validate with `bash ai-portal/tests/policy.sh`,
`bash ai-portal/tests/mongodb.sh`, and
`kubectl kustomize ai-portal/overlays/live`.
