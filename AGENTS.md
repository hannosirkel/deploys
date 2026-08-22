# deploys

<!-- BEGIN MANAGED ARCHITECTURE BASELINE -->
<!-- Generated from hannosirkel/architecture. Do not edit inside these markers.
     Regenerate with: tooling/universe sync-baseline deploys -->

Governed by [`architecture`](https://github.com/hannosirkel/architecture).

| | |
| --- | --- |
| Profile | `gitops-public` |
| Visibility | declared public, currently public |
| Languages | shell |

**Standards that apply here.** Read a standard before you change something it
governs. They live in a private repository: if a link does not open for you, the
rules stated below and this repository's CI are what bind.

- [Agent operation](https://github.com/hannosirkel/architecture/blob/main/standards/agent-operation.md) — worktrees, branches, multi-agent safety, delegation
- [Security](https://github.com/hannosirkel/architecture/blob/main/standards/security.md) — secrets, public and private boundaries, workflow hardening
- [Code quality](https://github.com/hannosirkel/architecture/blob/main/standards/code-quality.md) — gates, coaching, testing, review cutoff
- [Repository contract](https://github.com/hannosirkel/architecture/blob/main/standards/repository-contract.md) — required files, profiles, skills
- [Work routing](https://github.com/hannosirkel/architecture/blob/main/standards/work-routing.md) — where a change starts, and where a working plan belongs
- [GitOps and deployment](https://github.com/hannosirkel/architecture/blob/main/standards/gitops-and-deployment.md) — promotion by digest, rollback, the sanctioned secrets path
- Language standards: [shell](https://github.com/hannosirkel/architecture/blob/main/standards/languages/shell.md)

**Never commit to a default branch.** Work in `~/app/.worktrees/deploys/<task>`.
Branch from `origin/main`. Open a pull request.

**A working plan for this repository goes in `docs/working/`.** A change
spanning several repositories with no clear owner starts in `architecture`
instead.

**This repository must be safe to publish.** Never commit a password, token, key, kubeconfig,
rendered Secret, or live export. No repository in this universe holds a secret
value, and a private one is no exception.

**Run `habit-hooks` before declaring an edit done.** If it is not on `PATH`:

```bash
uv tool install "habit-hooks[python,typescript]"
```

That command names every language plugin **this universe** uses, not this
repository's. Install it whole: a later install naming fewer extras silently
removes the rest.

<!-- END MANAGED ARCHITECTURE BASELINE -->

## What this repository is

Public deployable desired state, one top-level directory per application, which
Argo CD reconciles into the Orange runtime. The repository root is not a
deployable Kustomization. The application roots today are `plepic/` and
`servitium/`.

## Commands

```bash
bash plepic/tests/manifests.sh
bash servitium/tests/manifests.sh

kubectl kustomize plepic/overlays/live
kubectl kustomize plepic/overlays/test
kubectl kustomize servitium/overlays/live
kubectl kustomize servitium/overlays/test
```

The manifest tests assert the environment boundary, the non-root container
contract, the default-deny policy, and the permitted egress. They are behaviour
tests, not formatting checks.

## This repository must never hold a secret value

It is public. No OAuth credential, no private key, no unrestricted token, no
kubeconfig, no rendered Secret, no private inventory. A secret reaches the
cluster through the sanctioned path only. Do not improvise a second one. See
[GitOps and deployment](https://github.com/hannosirkel/architecture/blob/main/standards/gitops-and-deployment.md).

## `main` receives automated pushes

The `plepic` and `servitium` release workflows push image digests to `main`
directly. Commits appear there that no agent wrote. That is why this repository
carries no pull-request rule, and it is the one place in the universe where a
commit on `main` is expected.

**Never hand-edit an image digest.** A digest reaches an overlay through a
release workflow's promotion, never through an editor.

## Promotion and rollback

- Promote by digest, never by tag. A tag moves; a digest does not.
- A live overlay is merge-promoted. A test overlay is label-promoted, and its
  overlay is replaceable.
- Roll back by promoting a known-good digest. Never edit live cluster state.

## Ownership boundary

| Owner | Holds |
| --- | --- |
| this repository | manifests, overlays, pinned digests |
| `orange` | the Argo CD `Application` objects and the namespaces |
| the application repository | its source, tests, and image build |
| `orange-inventory` | live private values |

## Governance work

A governance or conformance change touches documentation, validation, and
checks only. It never changes a manifest, an overlay's desired state, an image
digest, or Argo CD behaviour.
