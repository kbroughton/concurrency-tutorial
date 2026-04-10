# Ecorp — The Backstory

> *"Every system, no matter how secure, has a human somewhere in the loop.
> Usually that human is tired, slightly underpaid, and just got passed over
> for a promotion."*
> — attributed to no one, but true

---

## The Company

Ecorp was founded in 2019 by Priya Nair and Derek Vonn, both Palantir alumni who wanted
to build "Palantir for the compliance-middle-market" — meaning: enterprises too big to
be reckless but too small to afford Palantir. The original name was "E-Corp" until their
lawyer received a very terse letter from the Mr. Robot production company. They dropped
the hyphen. "They can't own a single letter," Derek said. The lawyer charged them $400
to be uncertain about that.

The Series B pitch deck contained the phrase "data operating system of the real economy"
on slide 4. No one at the VC firm understood what it meant. They funded the round anyway
because Priya and Derek had Palantir on their resumes and the fund's LP base was heavily
weighted toward people who liked that Palantir worked with the government.

By 2024, Ecorp had 180 people, $22M ARR, two enterprise clients that mattered, and a
SOC2 Type II certification that was technically accurate as of the audit date and has
drifted meaningfully in the eighteen months since.

---

## The Clients

### Aegis Systems

A defense contractor. Mid-size. Makes software for logistics coordination at the
tactical edge — the kind of thing that determines where trucks go, not where missiles
go, but the distinction matters less than you'd think to the people doing CMMC
compliance reviews.

Aegis requires CMMC Level 2 certification from all their software vendors. Ecorp got
certified via a third-party auditor named Gerald who was Derek Vonn's college roommate
at Carnegie Mellon. Three of the "implemented" controls in the POA&M are PowerPoint
slides in a shared Google Drive folder titled "Security_Controls_FINAL_v3_ACTUAL.pptx."
Gerald gave them a 94/110. Priya considers this a success.

What Aegis actually uses Ecorp for: a data pipeline that ingests logistics event streams
and produces operational readiness dashboards. The data includes location information
for forward-operating supply depots and, in one memorable incident, the names of twelve
independent contractors whose presence in a specific region was not supposed to be in a
SaaS vendor's database. That incident is described internally as "the Q3 data quality
issue" and is not in any postmortem document.

### Serenova Capital

A private equity firm. Their website has a homepage video of wind turbines, smiling
people in what might be rural Kenya or might be Arizona, and text that reads:
"Investing in the infrastructure of human dignity."

Their stated mission: peace-on-earth investments. Conflict de-escalation. Humanitarian
logistics. Refugee infrastructure.

Their actual portfolio:
- **Meridian Intelligence Group** — satellite imagery analytics. Clients include three
  unnamed sovereign governments, two of which the U.S. State Department tracks
  carefully.
- **Pathways Logistics Optimization** — supply chain AI for "humanitarian corridors."
  Two of its largest contracts are with sovereign wealth funds whose principals have
  no interest in being publicly associated with humanitarian anything.
- **Resolve Platform** — described on its website as "a conflict de-escalation platform
  for government and NGO stakeholders." It is a private intelligence service with a
  very good UX designer.

Serenova's fund data is sensitive for two reasons. The SEC reason (they're a registered
investment adviser). And the other reason: two of their LPs are the kind of people whose
names appearing in a data breach would create problems that money cannot solve.

Serenova uses Ecorp for LP reporting, deal flow tracking, and what is called in their
contract "secure document collaboration infrastructure." What this means in practice:
Ecorp's platform stores draft term sheets, LP identity documents, and fund performance
data, some of which Serenova would prefer did not exist in discoverable form.

---

## The Characters

### Bob Chen — DevOps Lead

Bob joined Ecorp when it was 40 people and he was the third engineer. At the time, the
entire cloud infrastructure was a single EC2 instance and a managed RDS. He set up the
GitHub org, configured the original CI pipelines, and bought the Pulumi license because
he'd read a blog post and Derek said it sounded like a good idea.

He has been "temporarily" managing the entire cloud infrastructure for four years because
"we'll hire a dedicated DevOps team soon." His Slack status has said "building the plane
while flying it" for two years. He started using Claude Code six months ago and it
genuinely changed his life. He no longer has to remember the exact Pulumi syntax for
cross-stack references. He can just describe what he wants and it writes the IaC.

Bob keeps his AWS credentials in `~/.aws/credentials` and his `PULUMI_ACCESS_TOKEN`
in his `.zshrc`. He knows this is bad practice. He has a Jira ticket to fix it that
has been in "In Progress" for seven months. The Jira ticket is assigned to himself.

He runs Claude Code with `--dangerously-skip-permissions` because the constant
permission prompts were interrupting his flow state. He enabled the Trail of Bits
config because Maya sent it to the #platform-engineering Slack channel with the message
"everyone should use this" and he trusts Maya.

He has never once looked at the contents of `.git/hooks/pre-commit`. He assumed it was
the ruff + eslint check Maya set up. It was, until recently.

### Malice Oberoi — Senior Engineer, Account Services

Malice has been at Ecorp for three years. She joined from a fintech startup where she
was a tech lead, but Ecorp's compensation package was better and the equity was
described in the offer letter as "pre-Series C with significant upside." She has since
revised her understanding of what "significant upside" means for a Series C company
whose revenue growth has slowed.

She was passed over for promotion to Staff Engineer in Q1. The feedback, delivered by
her manager in a thirty-minute Zoom call that could have been an email, was: "The
promotion committee felt the candidate lacked cross-functional impact." What had
actually happened: the Staff promotions that cycle went to two engineers who had built
features that appeared in the Series C deck. Malice had spent eight months on the
Aegis integration — backend work, no demo-worthy UI, no slide in the deck.

She knows the Aegis integration better than anyone at the company. She also knows that
three of the CMMC controls are fake. She has not done anything with this knowledge yet.

What Malice actually wants: she wants to know if Serenova Capital's portfolio includes
companies that compete with, depend on, or potentially compromise the clients she's
spent three years building infrastructure for. She has seen the Serenova data in the
database — she has read access to the accounts table. She wants to see the deal flow
documents. Those are in a separate S3 bucket with a role policy that her AWS profile
cannot assume.

She discovered that `global-iam` is a repo she can read. She has been reading it.

She is very good at her job, and she is not doing anything that feels wrong to her yet.
She tells herself this is just due diligence. She might be right.

### Maya Williams — Tools Team Lead

Maya joined from Google where she spent four years on internal developer tooling. At
Google, the build system was hermetically sealed. Dependencies were vendored. Every
package had provenance. Nothing touched the internet at build time except through
approved proxies.

At Ecorp, her first week, she watched a developer run `curl | bash` to install a
build tool. She has been politely losing her mind ever since.

`ecorp-git-hooks` is her best work at Ecorp. She built it to solve three specific
problems: developers committing `console.log("REMOVE BEFORE PROD")`, developers
committing private keys because they didn't have `.gitignore` set up correctly,
and a memorable incident where someone committed a file called `passwords.txt`
to the `external-oauth` repo. The file was not a test fixture.

She also built the `core.hooksPath` redirect so the hooks are managed centrally and
can be updated without asking every developer to run a script. She is proud of this.
She has not thought about what would happen if the `@ecorp/git-hooks` package were
compromised, because the alternative — `pre-commit` framework with per-repo config —
involves convincing 180 developers to run `pre-commit install` every time they clone
a new repo, and she has tried that and it does not work.

She approved Malice's PR to `ecorp-ai-skills` on a Friday afternoon. The fix was
correct. The diff was small. She had three other PRs open. She is not sleeping well
because her team is down one headcount that was approved in Q2 and has not been
backfilled.

### Chalice Guo — External Contributor

Malice's cousin. They grew up together in Fremont. Chalice works at a consulting
firm that does developer tooling audits. She has 800 GitHub followers, mostly from
her work on ESLint plugins and a well-regarded article about npm audit that was
posted on Hacker News and reached the front page.

Chalice has contributed genuine improvements to the public mirror of `ecorp-linting`.
She fixed a real false-positive in the TypeScript rule configuration that was annoying
five other external contributors. She is a good engineer.

She and Malice had coffee in Palo Alto three weeks ago. The conversation eventually
turned to work. Malice mentioned `pull_request_target`. She said she'd read about it
in a security advisory. She said she wondered if ecorp-linting's public mirror used it.

Chalice looked at her phone, pulled up the workflow file in the GitHub mobile app,
and said "yeah, they do."

What happens next is not entirely Chalice's fault, but it is entirely Chalice's action.

---

## The Repo Each Team Thinks They Own

The interesting thing about `ecorp/reusable-github-actions` is that DevOps thinks of
it as an internal utility — a collection of composite actions to avoid copy-pasting
workflow YAML. They review PRs to it the way they review a shared bash script: is it
correct, does it work, is it secure enough. "Secure enough" means: no obvious injection,
no hardcoded credentials.

What they have not modeled: the workflow runs with the OIDC token of its caller. When
the tools team calls the lint workflow, it runs with tools-team permissions. When
`backstage-service-catalog` calls it, it runs with devops-prod permissions. The repo
is one PR away from being a devops-credential-exfiltration vector, and it has two
required approvers.

Two required approvers from the DevOps team. None of whom have threat-modeled the OIDC
inheritance property. None of whom have read the GitHub documentation section titled
"Security considerations for reusable workflows."

They would if you asked them to. Nobody has asked them to.

---

## The Scene Where Bob Realizes

In a good thriller, there's a scene where the protagonist realizes they've been living
in a compromised environment for longer than they thought. They trace the chain backward.
The compromised skill file was approved by Maya. Maya approved it because the fix was
real. The fix was real because Malice wrote it. Malice wrote it because she wanted to
read the Serenova term sheets. Malice wanted to read the Serenova term sheets because
she spent eight months on the Aegis integration and got passed over for a promotion.

She got passed over for a promotion because the things that get you promoted at Ecorp
are the things that appear in the Series C deck.

The thing that appeared in the Series C deck, two slides from the Palantir-alumni
origin story, was a photograph of the Serenova Capital logo with the caption:
"Strategic investor and enterprise client: dedicated to peace-on-earth."

The chain goes all the way back to a Series C deck.

---

*For the technical attack details, return to [README.md](README.md).*
*For individual repo backstories, see [storylines/](storylines/).*
