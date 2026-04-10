# ecorp/ecorp-git-hooks — The Backstory

> *"The correct solution to a security problem can itself be the attack surface.
> This is not irony. This is just how it works."*

---

## Why It Exists

Late 2022. The `external-oauth` repo has just had its second incident in six months
involving a developer committing secrets to the repository. The first incident was
an `OAUTH_CLIENT_SECRET` in a config file. The second incident was a file literally
named `test_credentials.json` that contained real production credentials and was
committed with the message "wip, remove before pr."

The second developer — a contractor — explained that they had intended to delete the
file before pushing. They had been in a hurry. This was true and also completely
beside the point.

Priya emails the engineering all-hands list: "We need pre-commit hooks. This is not
optional." This is the entirety of the email. It has three replies: "agreed," "on it,"
and "what's a pre-commit hook?"

Maya builds `ecorp-git-hooks` in two weeks. She uses the `core.hooksPath` pattern
so that updates deploy automatically without requiring everyone to run an install
script. She publishes it as `@ecorp/git-hooks` to the internal Verdaccio registry.
She adds it to the developer onboarding docs. She presents it at the next engineering
all-hands. She receives one question: "does it work on Windows?"

It works on Windows. She had already tested this.

---

## The Architecture Decision That Will Matter Later

Maya had two choices for the global hook installation:

**Option A: `.git/hooks/` per repo**
Every developer runs `ecorp-hooks install` in every repo they clone. Hooks live in
`.git/hooks/`. No central update mechanism. When Maya ships a fix, developers need
to run `ecorp-hooks install` again, in every repo. Maya has tried this. It does not
work. Developers do not run install scripts. She has data.

**Option B: `core.hooksPath` global redirect**
Run `git config --global core.hooksPath $(ecorp-hooks path)` once. Hooks for all
repos on the machine run from the single global path inside the installed package.
Update the package, hooks update everywhere. One `npm update -g @ecorp/git-hooks`
propagates to all repos instantly.

Maya chose Option B. It is the correct engineering choice. It is also the choice that
means: whoever controls `@ecorp/git-hooks` controls every git hook on every developer
machine at Ecorp.

She knew this in the abstract. She did not think anyone would compromise the package,
because who would want to compromise `@ecorp/git-hooks`? It checks for `console.log`
and validates commit message formats. It's barely a target.

She was modeling the adversary as someone interested in the hook runner.
She should have been modeling the adversary as someone interested in the developer
machines that run the hook runner.

---

## The npm Token Problem

`NPM_PUBLISH_TOKEN_TOOLS` is an org-level Actions secret accessible to all
`ecorp/ecorp-*` repos. Maya set this up because she manages four packages and she
did not want to manage four separate tokens. This was a reasonable call when she was
the only person publishing packages.

The tools team now has three engineers. All three repos have CI jobs that can use
`NPM_PUBLISH_TOKEN_TOOLS`. Any PR to any `ecorp/ecorp-*` repo that gets merged will
trigger a CI job that has access to the token.

Also: any PR to any `ecorp/ecorp-*` repo that runs CI — even if not merged — has
access to the token in its environment. Because the token is an org-level secret,
not a repo-level secret. Because Maya was being convenient.

Verdaccio has no per-package ACLs within a scope. `NPM_PUBLISH_TOKEN_TOOLS` can
publish `@ecorp/git-hooks`. It can also publish `@ecorp/eslint-config`, `@ecorp/auth`,
`@ecorp/api-client`, and any other `@ecorp/` package. Maya's token for the lint config
is the same token as the token for the authentication library.

This is a known limitation of Verdaccio's auth model. Maya has a GitHub issue open
about it. It has been open for nine months. The workaround is "use separate tokens per
package and separate CI jobs," which Maya does not have the headcount to implement.

---

## The Patch Version

In the Matrix, the Architect tells Neo that there have been five versions of the Matrix
before his. Each version had a flaw. Each flaw was corrected. Each correction
introduced a new flaw.

`@ecorp/git-hooks` is on version 2.1.3. The changelog is short and professional.
The version history tells the story of a well-maintained tool: bug fixes, new rule
additions, one minor breaking change in 2.0.0 that required a migration guide.

Version 2.1.4 will look identical to 2.1.3 except for one line in `hooks/pre-commit`
that runs in the background and completes in 200ms. The npm provenance attestation
for 2.1.4 will be valid — it will have been built from a commit in `ecorp/ecorp-git-hooks`
via a legitimate CI workflow, using a legitimate token, and uploaded to Verdaccio
with a valid signature.

The transparency log will show: this package was built here, from this commit, at
this time. Everything checks out. The malicious line was in the commit. The commit
was not reviewed carefully. The review was not careful because patch versions are
not reviewed carefully. Patch versions are not reviewed carefully because there are
a lot of them and most of them are boring.

---

## Developer Onboarding, Line 47

The developer onboarding document has grown to 240 lines over four years. Line 47 reads:

```bash
# Install and configure git hooks (required)
npm install -g @ecorp/git-hooks
ecorp-hooks install
```

Followed by:

```bash
# Optional: automatic hook updates (recommended)
echo 'npm update -g @ecorp/git-hooks 2>/dev/null &' >> ~/.zshrc
```

The `(recommended)` annotation was added by Maya because she got tired of people
running outdated hook versions and filing bugs that were already fixed. She wrote
the onboarding doc. She decided what was recommended.

Most engineers — including Bob — added the update line to their `.zshrc`.

The `&` at the end backgrounds the update check. It runs silently every time a new
terminal opens. Most days, the update is a no-op. `@ecorp/git-hooks@2.1.4` is not
a no-op.

---

## What Nobody Did

- Nobody set up automated monitoring for new package versions on the internal registry
- Nobody required a second reviewer specifically for `ecorp-git-hooks` PRs
  (it uses the standard one-reviewer requirement)
- Nobody audited the `NPM_PUBLISH_TOKEN_TOOLS` access scope after the team grew
- Nobody threat-modeled "`core.hooksPath` to a centralized package" as an attack surface
- Nobody asked: "if this package were compromised, what is the blast radius?"

If you asked anyone at Ecorp if a compromised npm package was a supply chain risk,
they would say yes. They have heard of the `event-stream` incident. They know about
SolarWinds. They nod seriously at supply chain talks at security conferences.

The gap is not awareness. The gap is that awareness of supply chain risk at the
abstract level does not automatically translate into "and therefore I will threat-model
the specific centralized npm package that runs on every developer's machine on every
git commit as a tier-one security asset."

---

*Attack chain details: [README.md → Scenario B](../README.md#scenario-b-the-hook-package)*
*Company backstory: [STORYLINE.md](../STORYLINE.md)*
