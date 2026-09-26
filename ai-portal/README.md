# AI Portal GitOps state

`overlays/live` is the single production root. Orange owns its `ai-portal`
namespace and the Argo CD Application that points here. The application is
deployed while its public Cloudflare route remains unpublished.

The live overlay pins the portal's published image by digest. The Deployment
reads
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
backup, recovery, and bootstrap pods may connect to it. Backup pods can reach
only TCP 443 in [Backblaze's published IPv4 ranges](https://www.backblaze.com/computer-backup/docs/backblaze-ip-addresses),
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

LibreChat sends its OpenRouter requests to the fixed in-cluster egress proxy.
The proxy accepts only model catalogue and text-chat paths, verifies
`openrouter.ai` upstream TLS, and streams responses without buffering. The
proxy has provider HTTPS egress within Cloudflare's published IPv4 ranges;
chat pods can reach only the proxy on TCP 8080. These CIDRs are
shared with other Cloudflare sites, so hostname and path enforcement belongs
to the proxy. The proxy has no provider key; LibreChat's ESO Secret supplies it.
If OpenRouter leaves those ranges, egress fails closed until the policy is
reviewed and updated.

The LibreChat bootstrap must install `admin-override.json` as an active
role-scoped config for `ADMIN` before the chat workload starts. Until then,
the base policy also limits administrators to the two approved chat models.
That fails closed. OIDC role sync will map the Authentik `ai-portal-user`
claim to a LibreChat role of the same name, while `USER` remains the
restricted fallback. `OPENID_ADMIN_ROLE` separately grants `ADMIN` from
the `ai-portal-admin` claim. Local password registration and login are
disabled in the workload environment.

The `ai-portal-librechat-bootstrap-v1` Job runs after MongoDB is ready and
before chat starts. It uses the MongoDB app account to reconcile the
restrictive `USER` fallback, ordinary and future restricted roles, and an
active `ADMIN` role config from `admin-override.json`. It is safe to rerun.
Argo CD does not rerun a completed Job when its ConfigMap changes; bump the
versioned Job name and its test when changing the bootstrap policy. Do not
replace this reconciliation with an unrecorded admin-panel edit.

The pinned v0.8.7 LibreChat Deployment and ClusterIP Service are staged at
zero replicas. Its OIDC URL and public origin are reserved placeholders until
Orange patches them with live values. Existing ESO Secrets supply its
MongoDB, OpenRouter, OIDC client, and LibreChat runtime credentials. Before
raising replicas, verify the bootstrap Job and OpenRouter proxy in the live
cluster, promote the portal image that blocks
uploads, and test the `/chat` login and authorization paths over the
unpublished route. Readiness uses LibreChat's `/readyz` endpoint, which waits
for application startup instead of merely accepting a TCP connection. The
chat NetworkPolicy admits only MongoDB, private Authentik HTTPS, DNS, and the
OpenRouter proxy. Only the portal can enter the staged chat Service.

The config files are JSON syntax accepted by LibreChat's YAML parser, so the
policy test can inspect them without another dependency. They hold no
credential; `${OPENROUTER_KEY}` resolves from an ESO-managed Secret.

Validate with `bash ai-portal/tests/policy.sh`,
`bash ai-portal/tests/mongodb.sh`, and
`bash ai-portal/tests/runtime.sh`, then
`kubectl kustomize ai-portal/overlays/live`.

To promote a published portal image, dispatch the `Promote AI Portal image`
workflow on deploys `main` with the AI Portal source commit SHA and the digest
shown by its successful image build. Its `live` environment needs the
`AI_PORTAL_DEPLOYER_CLIENT_ID` and `AI_PORTAL_DEPLOYER_PRIVATE_KEY` secrets for
a GitHub App installed on deploys with contents and pull request write access.
The workflow requires a successful AI Portal image workflow, verifies the
source tag, changes only the live overlay digest, and opens a PR for review.
After merging that PR, pin its deploys merge commit in Orange and reconcile the
AI Portal Application. Keep the public DNS record unpublished until the separate release
gate is approved.
