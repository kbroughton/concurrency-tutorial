# ecorp/global-iam — The Backstory

> *"The most dangerous thing in your organization is the thing that
> has read access to everything and nobody thinks of as a target
> because it can't write anything."*

---

## Origin: The Audit Finding

Q4 2023. Ecorp's annual SOC2 audit, conducted by Gerald (Derek's college roommate),
flags a single finding: "IAM policies are not managed as code and lack documented
change review process." The finding is rated Low. Gerald rates it Low because it
would be awkward to rate it Medium given how many lunches they've shared.

Bob treats it as a High. He has wanted to move IAM to IaC for two years. The audit
finding is the political cover he needs to deprioritize the seven other things he was
doing instead.

He creates `ecorp/global-iam` as a Pulumi TypeScript project. Every IAM role, every
policy binding, every service account — if it touches identity, it is defined here.
Changes require two DevOps reviewers and a mandatory security review. It takes him
three months to migrate everything. By the time he is done, Ecorp's entire IAM
structure is 8,400 lines of version-controlled, diff-able, auditable Pulumi TypeScript.

He is proud of this work. It is genuinely good.

---

## The `ai-readonly` / `aiSecurityViewer` Pattern

In early 2024, Ecorp starts expanding its LLM tool usage. Claude Code for developers,
MCP servers for internal workflows, an experimental "ask about your infra" chatbot
that Derek wants for the Series D deck. Bob thinks carefully about access scope.

His design principles:
1. LLM tools should be able to see logs and configs to help with debugging
2. LLM tools should not be able to read secret values
3. LLM tools should not be able to read data belonging to customers
4. Access should be scoped to projects the user already has access to —
   a new project should not automatically be readable by an AI tool until a human
   has been explicitly provisioned there

He builds a custom `aiSecurityViewer` role rather than using any AWS managed policy
or GCP primitive role. `ReadOnlyAccess` is too broad (includes S3 data reads,
DynamoDB data reads, Secrets Manager). `roles/viewer` in GCP is too broad (includes
Cloud Storage object reads). Both would expose customer data.

**The allow list:**

```typescript
// global-iam/src/roles/ai-security-viewer.ts

const AI_SECURITY_VIEWER_AWS = new aws.iam.Policy("aiSecurityViewer", {
  policy: {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "LogsAndAudit",
        Effect: "Allow",
        Action: [
          "logs:GetLogEvents", "logs:FilterLogEvents",
          "logs:DescribeLogGroups", "logs:DescribeLogStreams",
          "cloudtrail:LookupEvents", "cloudtrail:GetTrailStatus",
          "cloudtrail:DescribeTrails", "cloudtrail:GetInsightSelectors",
        ],
        Resource: "*",
      },
      {
        Sid: "SecurityPosture",
        Effect: "Allow",
        Action: [
          "config:DescribeConfigRules", "config:GetComplianceDetailsByConfigRule",
          "securityhub:GetFindings", "securityhub:DescribeHub",
          "guardduty:GetFindings", "guardduty:ListDetectors", "guardduty:GetDetector",
          "iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetRole",
          "iam:GetRolePolicy", "iam:ListRoles", "iam:ListPolicies",
          "iam:ListAttachedRolePolicies",
        ],
        Resource: "*",
      },
      {
        Sid: "InfraTopology",
        Effect: "Allow",
        Action: [
          "ec2:Describe*",
          "ecs:DescribeClusters", "ecs:DescribeServices", "ecs:DescribeTaskDefinitions",
          "eks:DescribeCluster", "eks:ListClusters", "eks:DescribeNodegroup",
          "rds:DescribeDBInstances", "rds:DescribeDBClusters",  // metadata only
          "lambda:ListFunctions", "lambda:GetFunction",         // see caveat
          "elasticloadbalancing:Describe*",
        ],
        Resource: "*",
      },
      // Explicit denies always win, regardless of the above allows
      {
        Sid: "DenySecretValues",
        Effect: "Deny",
        Action: [
          "secretsmanager:GetSecretValue", "secretsmanager:GetRandomPassword",
          "ssm:GetParameter", "ssm:GetParameters",
          "ssm:GetParameterHistory", "ssm:GetParametersByPath",
          "kms:Decrypt", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext",
        ],
        Resource: "*",
      },
      {
        Sid: "DenyDataLayer",
        Effect: "Deny",
        Action: [
          "s3:GetObject", "s3:SelectObjectContent",
          "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:BatchGetItem",
          "rds-data:ExecuteStatement", "rds-data:BatchExecuteStatement",
          "kinesis:GetRecords",
          "sqs:ReceiveMessage",
        ],
        Resource: "*",
      },
    ],
  },
});
```

GCP equivalent as a custom org-level role:
```typescript
const AI_SECURITY_VIEWER_GCP = new gcp.organizations.IAMCustomRole("aiSecurityViewer", {
  orgId: ECORP_ORG_ID,
  roleId: "aiSecurityViewer",
  title: "AI Security Viewer",
  permissions: [
    // Logs
    "logging.logEntries.list", "logging.logs.list", "logging.sinks.list",
    // IAM topology
    "iam.roles.get", "iam.roles.list",
    "iam.serviceAccounts.get", "iam.serviceAccounts.list",
    "resourcemanager.projects.getIamPolicy",
    "resourcemanager.folders.getIamPolicy",
    // Security posture
    "securitycenter.findings.group", "securitycenter.findings.list",
    "securitycenter.sources.list",
    // Infrastructure topology
    "compute.instances.get", "compute.instances.list",
    "compute.firewalls.list", "compute.networks.list",
    "container.clusters.get", "container.clusters.list",
    "run.services.get", "run.services.list",         // see caveat
    "cloudfunctions.functions.get",                  // see caveat
  ],
  // Explicitly NOT included:
  // storage.objects.get, storage.objects.list    (no data-layer reads)
  // bigquery.tables.getData                      (no data-layer reads)
  // secretmanager.versions.access                (no secret values)
  // datastore.entities.get                       (no data-layer reads)
  // spanner.databases.read                       (no data-layer reads)
});
```

---

## The Scoping Mechanism — Two Iterations

### First attempt: single SA bound per project (shipped, then found broken)

Bob's initial implementation used a single global `ai-readonly@ecorp-platform` SA,
bound to each project as humans were provisioned there. The intent: the SA only
reaches projects that humans have touched. New projects stay dark.

```typescript
// global-iam/src/project.ts  — INITIAL VERSION (has a bug)

const AI_READONLY_SA = "serviceAccount:ai-readonly@ecorp-platform.iam.gserviceaccount.com";

export function provisionProject(config) {
  for (const [user, role] of Object.entries(config.members)) {
    new gcp.projects.IAMMember(`${config.id}-${user}-access`, { ... });
  }
  if (Object.keys(config.members).length > 0) {
    // Bind the single SA to this project
    new gcp.projects.IAMMember(`${config.id}-ai-readonly`, {
      project: config.id,
      role: "organizations/ECORP_ORG/roles/aiSecurityViewer",
      member: AI_READONLY_SA,
    });
  }
}
```

This achieves: "new empty projects don't get the SA." It does NOT achieve:
"Malice can only see project1 and not project2."

The SA is a single identity. Its IAM bindings are set globally at provisioning time.
When Malice's Claude Code session impersonates `ai-readonly@ecorp-platform`, it
presents all of the SA's bindings simultaneously — project1 AND project2 AND every
other project with humans. There is no per-session, per-user scoping.

Bob noticed this when a security-minded tools-team engineer asked: "if I have access
to three projects, does the AI SA give me visibility into all thirty?" The answer
was yes. The question was filed as a Medium severity issue in the `global-iam` repo.

### Correct design: per-project SAs with per-user impersonation rights

The fix requires one SA per project, plus granting each user
`roles/iam.serviceAccountTokenCreator` on only the SAs for their projects:

```typescript
// global-iam/src/project.ts  — CURRENT VERSION

export function provisionProject(config: {
  id: string;
  shortId: string;           // short identifier for SA naming (8 chars max)
  members: Record<string, string>;
}) {
  // Per-project AI SA, created in the platform project to centralise SA management
  const aiSA = new gcp.serviceaccount.Account(`${config.id}-ai-sa`, {
    accountId: `ai-rd-${config.shortId}`,
    project: PLATFORM_PROJECT,
    description: `AI readonly for ${config.id}`,
  });

  // Bind the SA to THIS project with the custom viewer role
  new gcp.projects.IAMMember(`${config.id}-ai-sa-binding`, {
    project: config.id,
    role: `organizations/${ECORP_ORG_ID}/roles/aiSecurityViewer`,
    member: pulumi.interpolate`serviceAccount:${aiSA.email}`,
  });

  for (const [user, role] of Object.entries(config.members)) {
    new gcp.projects.IAMMember(`${config.id}-${user}-access`, {
      project: config.id, role, member: `user:${user}`,
    });
    // Grant impersonation rights on THIS project's SA only
    // The user can get tokens for ai-rd-<this-project> but no other ai-rd-* SA
    new gcp.serviceaccount.IAMMember(`${config.id}-${user}-ai-impersonate`, {
      serviceAccountId: aiSA.name,
      role: "roles/iam.serviceAccountTokenCreator",
      member: `user:${user}`,
    });
  }
}
```

Now:
- Malice has `serviceAccountTokenCreator` on `ai-rd-proj1` only
- Her Claude Code session impersonates `ai-rd-proj1` → accesses project1
- `ai-rd-proj2` returns `403 PERMISSION_DENIED` for Malice

The `global-iam` Pulumi state file contains the complete mapping of `(user, project)`
→ `(SA email)` pairs. Claude Code tooling initialization reads this mapping and
presents only the SAs the authenticated user can impersonate.

**AWS analog:** separate `ecorp-ai-readonly-<account-id>` roles per account, with
trust policies granting `sts:AssumeRole` only to users who have been provisioned in
that account. Same principle: one role per account, impersonation rights tied to
per-account provisioning.

### The window between "single SA shipped" and "per-project SA deployed"

`global-iam` is Pulumi-managed. The fix is a refactor: remove the single SA, add
per-project SA creation to `provisionProject()`, migrate existing bindings. The
Pulumi preview for this change shows 32 new SA creations, 30 binding deletions,
32 new per-user impersonation grants. It has been reviewed and approved. It has not
been applied because Bob wants to run it during a maintenance window, and the next
maintenance window is in two weeks.

During the window between "single SA design noticed as broken" and "per-project SA
design applied," the `ai-readonly` SA has `aiSecurityViewer` bindings on all 30
active projects. Any session that can impersonate it sees all 30.

Malice, who has project access and therefore can impersonate the SA (the single SA,
everyone can impersonate), can see all 30 projects' logs, IAM topology, and configs
until the migration runs.

She has been aware of this window for eleven days.

---

## The Known Caveat: Lambda and Cloud Function Env Vars

Both `lambda:GetFunction` (AWS) and `cloudfunctions.functions.get` (GCP) are included
in the allow list because they provide genuinely useful config visibility — understanding
how a function is configured, what memory/timeout/VPC it uses, what its concurrency
settings are — without data reads.

Both also expose environment variable key-value pairs. If a developer puts
`DB_PASSWORD=hunter2` in a Lambda environment variable instead of reading it from
Secrets Manager at runtime, `lambda:GetFunction` will return it.

This is a known gap. The company policy — documented in `global-iam/POLICY.md` —
requires all secrets to be stored in Secrets Manager or GCP Secret Manager and
accessed at runtime, not baked into function configuration. The `aiSecurityViewer`
role is defined assuming this policy is followed.

The policy is not perfectly followed. Bob knows this. There is a Lambda in the
`external-oauth` service that has `OAUTH_CLIENT_SECRET` directly in its environment
variables because the developer who wrote it was working against a deadline and
"meaning to move it to Secrets Manager." That was fourteen months ago.

The Jira ticket to audit all Lambda and Cloud Function env vars for embedded secrets
is assigned to Bob. It has been In Progress for four months. It requires running
`aws lambda get-function-configuration` on every function in every account and
reviewing the output. Bob has a script that does this. He has not run it since Q2.

---

## What `aiSecurityViewer` Actually Exposes

Even correctly implemented, the role is not zero blast radius.

**Logs may contain secrets.** CloudWatch and GCP Cloud Logging aggregate application
logs. If any application has ever logged a token, a session cookie, a database
connection string, or a bearer credential — for debugging, for error reporting, for
request tracing — that string is now in the log retention window and readable by the
AI SA. Bob cannot audit what every application has logged in the past 90 days.

**IAM topology is sensitive.** A complete picture of who has what role where is
operationally useful to an attacker. It tells you: which accounts are high-value
targets, which service accounts have elevated access, which roles can be assumed by
which principals. The `aiSecurityViewer` role provides this picture in full.

**Infrastructure inventory identifies targets.** Knowing the exact set of running
services, their network topology, their EKS cluster configurations, their RDS
endpoints — this is not data exfiltration but it is reconnaissance that meaningfully
accelerates a subsequent attack.

**Security findings are a road map.** `securityhub:GetFindings` and
`securitycenter.findings.list` return current unresolved security findings for every
account and project. This is intended to help AI tools assist with remediation.
It also tells an attacker exactly which known vulnerabilities are currently unpatched
and in which services.

For Malice's purposes, `aiSecurityViewer` access alone — without the devops-prod role
that Scenario A targets — would be sufficient to map the Ecorp IAM topology, identify
the Serenova Capital data pipeline account, and understand its structure well enough
to plan a targeted attack using other vectors.

---

## The Threat Model Bob Built vs. The Threat Model He Needed

Bob modeled the AI tool as an agent that is trying to help and might accidentally
cause harm through incompetence or overly broad capability. He designed against:
destructive writes, expensive operations, data exfiltration through direct reads.

He correctly excluded data-layer access. He correctly excluded secret values.
He correctly scoped to projects with existing human access.

He did not model the AI tool as a vessel running adversary-provided instructions,
with an adversary who wants specifically the information the `aiSecurityViewer` role
exposes: org topology, security posture, unpatched findings, infrastructure inventory,
and whatever secrets are in CloudWatch because of a debug log from Q2 2023.

The `aiSecurityViewer` role is well-designed for the threat model Bob had.
The threat model Bob had is not the threat model Ecorp faces.

---

*Attack chain details: [README.md → Scenario A](../README.md#scenario-a-the-skills-backdoor)*
*Bob's full context: [STORYLINE.md](../STORYLINE.md)*
