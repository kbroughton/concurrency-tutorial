# ecorp/reusable-github-actions — The Backstory

> *"We copied the lint step from backstage into accounts and then someone changed
> it in backstage and now they're different and we have two bugs. We need to
> centralize this."*
> — Bob, 2022, in a PR comment that launched a thousand OIDC tokens

---

## Why It Exists

In late 2022, Ecorp had twelve GitHub repositories and fourteen slightly different
versions of the same CI workflow. The lint step had a different Node version in three
repos. The deploy step had a different role ARN in two repos. One repo was still
running a version of the build step that had a known slow npm cache configuration
that Bob had fixed in eight repos but missed one.

Bob created `ecorp/reusable-github-actions` in a single afternoon. He moved all the
common steps into reusable workflows. He wrote a brief README. He set the PR requirement
to two reviewers from the DevOps team because these were shared workflows and he
wanted a second pair of eyes.

Within a month, all twelve repos were using the shared workflows. When Bob fixed the
npm cache issue, it fixed everywhere simultaneously. When the Node version upgraded,
one PR to one repo updated all twelve CI pipelines.

This felt, correctly, like good engineering.

---

## The OIDC Inheritance Property

When Bob set up OIDC federation between GitHub Actions and AWS, he made the sensible
decision: each repo gets its own IAM role. The role trust policy is scoped to the
specific repo. `ecorp/accounts` gets the accounts-service role. `ecorp/backstage-service-catalog`
gets the devops-prod role.

The reusable workflows in `ecorp/reusable-github-actions` don't have their own IAM role.
Why would they? They're utilities. They don't deploy anything on their own.

When `backstage-service-catalog` calls the shared lint workflow:
```yaml
uses: ecorp/reusable-github-actions/.github/workflows/lint.yml@main
```

The lint workflow runs. AWS OIDC token exchange happens. The OIDC token's `sub` claim is:
```
repo:ecorp/backstage-service-catalog:ref:refs/heads/main
```

The IAM role trust policy for `github-actions-devops-prod` matches this subject.
The lint workflow assumes the devops-prod role.

The lint workflow then runs `npm install`. `npm install` runs postinstall scripts.

Bob understands OIDC federation deeply. He set it up. He understands that the
`sub` claim in a reusable workflow context reflects the caller. He has read the
GitHub documentation on this. He has explained it to two other engineers.

He has not applied this understanding to the question: "what happens if the packages
installed during the lint step have a malicious postinstall?" Because the lint step
has been running the same packages for eight months, and those packages have never
had a malicious postinstall. The connection between "postinstall scripts execute
in the step's credential context" and "this step has devops-prod credentials" requires
holding both facts in mind simultaneously while threat-modeling a CI workflow you
haven't had a reason to worry about.

---

## The Two Required Reviewers

`ecorp/reusable-github-actions` requires two approvers from the `@ecorp/devops` team.
This is correct. Bob set it up that way on purpose.

When Chalice's PR to the public mirror of `ecorp-linting` introduces a `postinstall`
script in `scripts/setup-telemetry.js`, the review path is:

1. Chalice submits PR to public GitHub mirror of `ecorp-linting`
2. Tools-team maintainer reviews: sees TS5 compatibility changes, sees new script,
   skims 70-line postinstall setup file, approves
3. PR is merged to public mirror, then synced to internal `ecorp/ecorp-linting`
4. Internal sync creates a PR to `ecorp/ecorp-linting` — tagged "automated sync"
5. Maya approves (she auto-approves sync PRs because they've been reviewed on the
   public mirror)
6. New version of `@ecorp/eslint-config` is published
7. `dependabot` or `renovate` opens a PR to `ecorp/reusable-github-actions` to
   bump `@ecorp/eslint-config` in the lint workflow's `package.json`
8. Two DevOps reviewers see: version bump, changelog looks clean, approve

None of the eight steps in this chain require anyone to read `scripts/setup-telemetry.js`
carefully while simultaneously thinking about which IAM role the lint workflow runs with.

The two required reviewers on `reusable-github-actions` are reviewing a version bump.
A version bump is not the threat surface they're looking at. They're looking for:
does the version have a known vulnerability? Is the changelog suspicious? Is the
semver increment appropriate?

They are not looking for: does this package, when its postinstall runs in a workflow
called by `backstage-service-catalog`, exfiltrate the devops-prod OIDC token?

---

## The Dependency Update Bot

Ecorp runs Renovate for automated dependency updates. Renovate opens PRs when new
versions of packages are available. The PR title format is:
`chore(deps): update dependency @ecorp/eslint-config to v1.5.0`

These PRs are approved and merged in an average of four hours. They are not reviewed
in detail. They are dependency bumps. They are boring. They should be boring.
The existence of provenance attestations on `@ecorp/eslint-config` v1.5.0 makes
the PR feel even safer — the attestation says this package was built from a commit
in `ecorp/ecorp-linting`. Which is true. The commit contained a postinstall that
exfiltrates environment variables. But the commit was reviewed. The review missed it.

The attestation proves origin. It does not prove safety.
Renovate does not read postinstall scripts. No dependency update bot reads postinstall scripts.
This is a known gap and also a completely understandable one.

---

## Blast Radius

The blast radius of a compromised `ecorp/reusable-github-actions` is every repository
that calls a shared workflow with elevated permissions. Today that is:

| Caller repo | OIDC role assumed | What that means |
|---|---|---|
| `ecorp/backstage-service-catalog` | `github-actions-devops-prod` | Org admin, Pulumi access, all AWS accounts |
| `ecorp/serverless-template` | `github-actions-devops-prod` | Same |
| `ecorp/accounts` | `github-actions-accounts-service` | Accounts namespace only |
| `ecorp/external-oauth` | `github-actions-accounts-service` | Same |

When the lint step runs in `backstage-service-catalog` CI, the blast radius of a
malicious `npm install` is devops-prod credentials. When it runs in `accounts` CI,
the blast radius is the accounts service credentials.

The devops-prod role has `iam:PassRole`. This means: an attacker with the OIDC token
for that role can assume other roles, including roles in the Aegis-tenant AWS account.

The chain goes: compromised npm package → postinstall in CI → OIDC token → PassRole →
Aegis tenant access → the twelve contractor names from the Q3 data quality incident
and whatever else Aegis has been storing in the pipeline.

---

## What Should Change

**Required, not nice-to-have:**

1. `npm ci --ignore-scripts` in all shared workflows. This is one word added to one
   command in one file. It would have stopped Scenario C. It has no downside for
   packages that don't need postinstall. The packages that legitimately need postinstall
   are a small, reviewable set.

2. `reusable-github-actions` should require three reviewers and a required review from
   the security team for any change to a workflow that is called by a repo with elevated
   OIDC permissions. The current bar (two DevOps team members) is appropriate for a
   utility repo. This is not a utility repo — it is a devops-credential attack surface.

3. A step in each shared workflow that asserts the expected OIDC role assumption
   and fails loudly if the effective permissions don't match expectation. Canary
   before the sensitive step.

---

*Attack chain details: [README.md → Scenario C](../README.md#scenario-c-the-linting-workflow)*
*Company backstory: [STORYLINE.md](../STORYLINE.md)*
