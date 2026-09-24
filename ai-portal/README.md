# AI Portal GitOps state

`overlays/live` is the single production root. Orange owns its `ai-portal`
namespace and the Argo CD Application that points here. The application is
deployed while its public Cloudflare route remains unpublished.

The root now pins the portal's published image by digest. Its Deployment reads
the OIDC client and session key from `ai-portal-runtime`; the public origin,
issuer, and Access audience are reserved placeholders for Orange's live
Application patch. The Service is ClusterIP-only. The namespace remains
default-denied: its current portal egress allows only Authentik and a future
chat pod, plus HTTPS to Cloudflare's published IPv4 ranges for Access signing
keys. The CIDR list was checked against
[Cloudflare's published list](https://www.cloudflare.com/ips-v4) on
2026-09-23 and must be refreshed when that list changes. These ranges are
shared by other Cloudflare-hosted sites, so the rule limits provider IPs and
port, not the hostname. A narrowly sourced
tunnel ingress is still required before activation. Its dedicated policy
starts with an empty ingress list; Orange patches the observed host/node source
range when it activates the Application. Kubernetes cannot distinguish the
host-run cloudflared process from other processes on that node, so this policy
must be paired with Orange's host port boundary and the Cloudflare Access gate.
Orange's exact Authentik hostname split-DNS rewrite supplies the private OIDC
backchannel while preserving the public HTTPS issuer and TLS name.

The root also includes one authenticated MongoDB StatefulSet with a 5 GiB
persistent volume claim template and a ClusterIP Service. Its first pod creates
`data-ai-portal-mongodb-store-0`; the backup runner must use
that exact claim name. Its root and LibreChat application
passwords must be seeded in OpenBao and projected as the `ai-portal-mongodb`
Secret by Orange's External Secrets contract before the first pod starts.
The database is isolated by default-deny NetworkPolicies; only chat,
backup, and recovery pods may connect to it. Backup pods can reach only TCP 443
in [Backblaze's published IPv4 ranges](https://www.backblaze.com/computer-backup/docs/backblaze-ip-addresses),
checked on 2026-09-23. Refresh this list when Backblaze changes it. An
encrypted backup and isolated restore drill passed before the backup schedule
was enabled. The LibreChat Deployment remains at zero replicas.

The first LibreChat chat release has one OpenRouter endpoint. The default
server-enforced model specifications allow `qwen/qwen3.8-flash` and
`~deepseek/deepseek-flash-latest` for `restricted` and `user`. The `admin`
role override disables specification enforcement and fetches OpenRouter's
catalogue. Jev 1.13 belongs to a later Decisions API integration, and Qwen
Image 3 Pro to a separate image feature. The OpenRouter endpoint's file
uploads are disabled for this text-only release; add backed-up storage before
enabling attachments later. LibreChat's speech-to-text route bypasses this
endpoint setting, so the portal proxy must block that upload route before
chat activation.

The LibreChat bootstrap must install `admin-override.json` as an active
role-scoped config for `ADMIN` before the chat workload starts. Until then,
the base policy also limits administrators to the two approved chat models.
That fails closed. OIDC role sync will map the Authentik `ai-portal-user`
claim to a LibreChat role of the same name, while `USER` remains the
restricted fallback. `OPENID_ADMIN_ROLE` separately grants `ADMIN` from
the `ai-portal-admin` claim. Local password registration and login are
disabled in the workload environment.

The pinned v0.8.7 LibreChat Deployment and ClusterIP Service are staged at
zero replicas. Its OIDC URL and public origin are reserved placeholders until
Orange patches them with live values. Existing ESO Secrets supply its
MongoDB, OpenRouter, and OIDC client credentials. A dedicated
`ai-portal-librechat` Secret still needs JWT, refresh, credential-encryption,
and OIDC session keys through OpenBao and ESO. Before raising replicas,
install and verify the role-scoped override, permit only the required OIDC and
OpenRouter egress, and test the `/chat` login and authorization paths over the
unpublished route. Readiness uses LibreChat's `/readyz` endpoint, which waits
for application startup instead of merely accepting a TCP connection. The
default-deny policy currently prevents external chat egress; only the portal
can enter the staged chat Service.

The config files are JSON syntax accepted by LibreChat's YAML parser, so the
policy test can inspect them without another dependency. They hold no
credential; `${OPENROUTER_KEY}` resolves from an ESO-managed Secret.

Validate with `bash ai-portal/tests/policy.sh`,
`bash ai-portal/tests/mongodb.sh`, and
`bash ai-portal/tests/runtime.sh`, then
`kubectl kustomize ai-portal/overlays/live`.
