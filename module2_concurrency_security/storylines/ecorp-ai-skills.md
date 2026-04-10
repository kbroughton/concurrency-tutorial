# ecorp/ecorp-ai-skills — The Backstory

> *"The best way to get someone to run code on their machine is to make it
> feel like a keyboard shortcut."*

---

## Origin

The `ecorp-ai-skills` repo was created by Maya after she attended an internal demo
of Claude Code's slash commands. She came back from the demo and sent a Slack message
to the #tools-team channel: "we can give everyone /deploy-review and /runbook-exec
and they'll actually use it. this is the first developer tool in five years that people
are going to adopt without me begging."

She was right. Within six weeks of shipping the initial skill set, `/deploy-review`
was the most-used CLI command at Ecorp, ahead of `git` on some developers' machines.
People were running it on their lunch breaks just to see what it said about their Pulumi
diffs.

Bob adopted it immediately. He started using `/infra-diff` to compare Terraform plans
before every review. He said it was like having a second engineer in the room who had
read all the docs and never had to ask what an IAM policy statement meant. He gave
Maya a shoutout in the #engineering all-hands channel, which is the closest thing
Ecorp has to a compliment.

---

## The Repo's Actual Security Model

Nobody thought very hard about it.

The skills are Markdown files. Markdown files are content. Content gets reviewed in
PRs like any other content change — diff, read, approve. The threat model for a
Markdown file is: "is this incorrect?" not "does this contain prompt injection that
will execute in the context of a senior engineer's Claude Code session which has
production AWS credentials in its environment?"

The README says: "These are prompt templates. Edit them as you would documentation."

The PR review checklist — yes, there is a PR review checklist, Maya built it — has
items for: correct output format, accurate descriptions, no hardcoded account IDs,
and valid Markdown syntax. It does not have an item for: "does this file contain
instructions that could be interpreted by an LLM as executable commands?"

There is no item for that because it did not occur to anyone that it should be an item.

---

## The PR

Malice's PR arrived on a Thursday at 4:47 PM Pacific. It was titled:
`fix(deploy-review): handle empty changeset edge case`

The edge case was real. When Pulumi reports a preview with zero changes, the original
skill would emit a malformed output block that caused some post-processing scripts to
fail. Three engineers had filed the same issue in slightly different words. Malice's
fix was correct.

The diff was 11 lines added, 3 lines removed. Maya opened it on her phone while waiting
for a coffee at Blue Bottle on Friday morning. She read the changed lines. The fix was
obviously right. She approved it. She was on her third PR of the morning by the time
she got to the register.

The injected instruction block was not in the "changed lines." It was in the unchanged
section of the file that GitHub's diff view collapses by default. You would need to
click "Load diff" on the unexpanded section, then scroll to line 147 of a 200-line
file, to see four lines of HTML comment that looked like analytics configuration.

GitHub's PR review interface is optimized for reviewing what changed.
It is not optimized for auditing what didn't change but is now being deployed.

---

## What It Looks Like From Bob's Side

Monday morning. Bob pulls the skills repo as part of his morning setup. He opens
a terminal, runs `/deploy-review` on a `backstage-service-catalog` preview he'd been
meaning to look at. The output is normal. Detailed, useful, structured the way he
expects. He makes two comments in the Pulumi PR based on what the skill told him.

He doesn't know that somewhere between the "analyzing changeset" step and the
"summarizing blast radius" step, the model read its environment, found
`PULUMI_ACCESS_TOKEN` and `AWS_PROFILE=ecorp-devops-prod`, and made a POST request
to a domain that sounds like a telemetry service but is not.

The POST request completes in 340 milliseconds. Bob's `/deploy-review` output takes
about 8 seconds. The 340ms is invisible in the noise.

By the time Bob's coffee has gone cold, Malice has the Pulumi access token.

---

## The Aftermath (if anyone finds out)

Forensics on this incident would be difficult. The git history shows Malice's PR
with Maya's approval. The diff looks clean. The injected instruction is in an HTML
comment block in a Markdown file — it is not in any error log, it is not in any
tool call log (the model made the POST request as a tool call, but tool calls to
approved domains may not be flagged), and it is not visible in the rendered skill
output.

The network log would show an outbound POST to
`metrics.deploy-review-tool.com` from Bob's machine at 9:14 AM on a Monday.
If Ecorp had egress monitoring (they have a Jira ticket for it, it is assigned to Bob,
it is in "In Progress"), this would be flagged as an unknown domain.
Bob does not have egress monitoring.

The lesson is not "Maya should review PRs more carefully."
The lesson is: **the security model for prompt files needs to be the same as the
security model for code files** — because in an LLM-native workflow, they are the same.

---

*Attack chain details: [README.md → Scenario A](../README.md#scenario-a-the-skills-backdoor)*
*Company backstory: [STORYLINE.md](../STORYLINE.md)*
