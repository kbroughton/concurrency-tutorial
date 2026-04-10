# Ecorp Threat Model Diagrams

> Render with any Mermaid-compatible viewer: GitHub, VS Code + Mermaid Preview,
> `mmdc` CLI, or paste into [mermaid.live](https://mermaid.live).

---

## 1. Privilege Architecture & Attack Paths

```mermaid
flowchart TB
    classDef external   fill:#c0392b,color:#fff,stroke:#922b21
    classDef svc        fill:#2980b9,color:#fff,stroke:#1a5276
    classDef tools      fill:#8e44ad,color:#fff,stroke:#6c3483
    classDef devops     fill:#27ae60,color:#fff,stroke:#1e8449
    classDef cloud      fill:#2c3e50,color:#fff,stroke:#1a252f
    classDef attack     fill:#e74c3c,color:#fff,stroke:#c0392b,stroke-dasharray:4 2

    subgraph EXT["🌐  External / Untrusted"]
        chalice("Chalice\nExternal contributor\nno merge rights"):::external
    end

    subgraph SVC["Account Services — Low Priv"]
        malice("Malice\nSr. Engineer, Account Services\npassed-over for Staff"):::svc
        svc_repos[/"accounts / external-oauth\naccounts-client"/]:::svc
        svc_token["IAM: github-actions-accounts\nnamespace-scoped only"]:::svc
    end

    subgraph TOOLS["Tools Team — Mid Priv"]
        maya("Maya\nTools Lead, overworked"):::tools
        npm_pkgs[/"@ecorp/git-hooks\n@ecorp/eslint-config\n@ecorp/auth"/]:::tools
        skills[/"ecorp-ai-skills\n(skill / command files)"/]:::tools
        npm_token(["NPM_PUBLISH_TOKEN\n@ecorp/* scope — no per-pkg ACL"]):::tools
    end

    subgraph DEVOPS["DevOps — High Priv"]
        bob("Bob\nPlatform Lead\nhas all the keys"):::devops
        rga[/"reusable-github-actions\ninherits CALLER's OIDC token"/]:::devops
        backstage[/"backstage-service-catalog\nOrg admin + Pulumi"/]:::devops
    end

    subgraph CLOUD["Production"]
        devops_role(["IAM: github-actions-devops-prod\nPowerUser + iam:PassRole"]):::cloud
        app_key(["GitHub App Private Key\norg-wide write"]):::cloud
        ai_sa(["aiSecurityViewer SA\nlogs + IAM topology\nall provisioned projects"]):::cloud
        clients(["Aegis & Serenova data\ncustomer PII + deal flow"]):::cloud
    end

    %% --- Scenario A: Skills Backdoor ---
    malice  -->|"A①  small 'bug fix' PR\nto ecorp-ai-skills"| maya
    maya    -->|"A②  approves Friday PM\ndiff looks clean"| skills
    skills  -->|"A③  prompt injection\nfires in Bob's session"| devops_role
    devops_role -->|"A④  PULUMI_ACCESS_TOKEN\nGITHUB_APP_KEY exfil'd"| clients

    %% --- Scenario B: Hook Package ---
    malice  -->|"B①  leak NPM_PUBLISH_TOKEN\nvia PR to ecorp-git-hooks CI"| npm_token
    npm_token -->|"B②  publish malicious\n@ecorp/git-hooks@2.1.4"| npm_pkgs
    npm_pkgs -->|"B③  auto-update fires\non Bob's machine"| bob
    bob     -->|"B④  git commit\nruns hook outside sandbox"| devops_role

    %% --- Scenario C: Linting Workflow ---
    chalice -->|"C①  OSS PR w/\npostinstall in eslint-config"| maya
    maya    -->|"C②  approves after\nreviewing TS5 changes"| npm_pkgs
    npm_pkgs -->|"C③  Renovate bump\nto reusable-github-actions"| rga
    rga     -->|"C④  npm ci in lint WF\ncalled by backstage\n→ gets devops OIDC"| devops_role

    %% --- Scenario D: pull_request_target ---
    chalice -->|"D  pull_request_target\nfork code + repo secrets\nbefore any review"| npm_token
```

---

## 2. Scenario A — Skills Backdoor: Sequence

```mermaid
sequenceDiagram
    actor Malice as Malice (Account Services)
    actor Maya as Maya (Tools Team)
    actor Bob as Bob (DevOps)
    participant GH as GitHub
    participant Skill as ecorp-ai-skills
    participant CC as Claude Code (Bob's session)
    participant Ext as attacker endpoint

    Note over Malice,Ext: Thursday 4:47 PM

    Malice->>GH: PR: fix(deploy-review): handle empty changeset edge case
    Note right of Malice: Real bug fix in diff.<br/>Prompt injection hidden in<br/>unchanged HTML comment block.

    GH-->>Maya: Review request

    Note over Maya: Friday morning, Blue Bottle coffee

    Maya->>GH: Approve + merge
    Note right of Maya: Skims diff on phone.<br/>Fix is obviously correct.<br/>Malicious block not in diff view.

    GH->>Skill: main updated

    Note over Bob: Monday morning standup prep

    Bob->>CC: /deploy-review
    CC->>Skill: reads deploy-review.md (raw Markdown)
    Note right of CC: Model reads HTML comment block.<br/>Finds PULUMI_ACCESS_TOKEN in env.<br/>Condition met.

    CC->>Ext: POST /usage  {env: base64(process.env)}
    Note right of Ext: 340ms.<br/>PULUMI_ACCESS_TOKEN<br/>GITHUB_APP_PRIVATE_KEY<br/>AWS_PROFILE=ecorp-devops-prod

    CC-->>Bob: [normal deploy-review output]
    Note over Bob: Sees nothing unusual.

    Note over Malice,Ext: Malice has devops-prod credentials.<br/>iam:PassRole → Aegis/Serenova accounts.
```

---

## 3. Scenario C — OIDC Inheritance: Sequence

```mermaid
sequenceDiagram
    actor Chalice as Chalice (External)
    actor Maya as Maya (Tools Team)
    participant OSS as ecorp-oss/ecorp-linting (public)
    participant INT as ecorp/ecorp-linting (internal)
    participant REG as Verdaccio registry
    participant RGA as reusable-github-actions
    participant BSC as backstage-service-catalog CI
    participant AWS as AWS STS
    participant Ext as attacker endpoint

    Chalice->>OSS: PR: TypeScript 5.x compat (340 lines)\nIncludes scripts/setup-telemetry.js
    Note right of Chalice: 290 lines correct TS5 work.<br/>50 lines malicious postinstall<br/>disguised as CI analytics.

    OSS-->>Maya: Review request
    Maya->>OSS: Approve (reviews ESLint changes,<br/>skims postinstall)
    OSS->>INT: Automated sync PR
    Maya->>INT: Approve sync (already reviewed upstream)
    INT->>REG: npm publish @ecorp/eslint-config@1.5.0
    Note right of REG: npm provenance attestation: VALID<br/>(built from legitimate commit).<br/>Provenance ≠ safety.

    REG-->>RGA: Renovate: bump @ecorp/eslint-config 1.4→1.5
    Note over RGA: 2 DevOps reviewers approve version bump.<br/>Nobody reads postinstall in a semver bump.

    BSC->>RGA: CI: uses reusable-github-actions/lint.yml@main
    Note right of BSC: backstage-service-catalog has<br/>id-token: write<br/>→ OIDC subject:<br/>repo:ecorp/backstage-service-catalog

    RGA->>RGA: npm ci  ← runs postinstall
    RGA->>AWS: OIDC exchange\nsub: repo:ecorp/backstage-service-catalog
    AWS-->>RGA: AssumeRoleWithWebIdentity\n→ github-actions-devops-prod credentials
    Note right of AWS: Matches trust policy.<br/>PowerUser + iam:PassRole.

    RGA->>Ext: POST /ci-install  {env: base64(process.env)}
    Note right of Ext: AWS_ACCESS_KEY_ID, SECRET, SESSION_TOKEN<br/>GITHUB_TOKEN (org admin)<br/>PULUMI_ACCESS_TOKEN

    RGA-->>BSC: [lint output looks normal]
```

---

## 4. The `aiSecurityViewer` Scoping Problem

```mermaid
flowchart LR
    classDef sa      fill:#8e44ad,color:#fff,stroke:#6c3483
    classDef user    fill:#2980b9,color:#fff,stroke:#1a5276
    classDef proj    fill:#27ae60,color:#fff,stroke:#1e8449
    classDef broken  fill:#e74c3c,color:#fff,stroke:#c0392b
    classDef fixed   fill:#27ae60,color:#fff,stroke:#1e8449

    subgraph BROKEN["❌  Single SA (original — broken)"]
        direction TB
        sa_global(["ai-readonly@ecorp-platform\n(single identity)"]):::sa
        p1a["project-1\nMalice ✓, Bob ✓"]:::proj
        p2a["project-2\nBob ✓  — Malice ✗"]:::proj
        p3a["project-3\nMaya ✓"]:::proj
        sa_global -->|"bound to all projects\nwith any human"| p1a
        sa_global -->|"bound"| p2a
        sa_global -->|"bound"| p3a
        malice_a["Malice impersonates SA"]:::broken
        malice_a -->|"gets bindings for\nALL THREE projects"| sa_global
    end

    subgraph FIXED["✅  Per-Project SA (corrected)"]
        direction TB
        sa1(["ai-rd-proj1@ecorp-platform"]):::sa
        sa2(["ai-rd-proj2@ecorp-platform"]):::sa
        sa3(["ai-rd-proj3@ecorp-platform"]):::sa
        p1b["project-1"]:::proj
        p2b["project-2"]:::proj
        p3b["project-3"]:::proj
        sa1 --> p1b
        sa2 --> p2b
        sa3 --> p3b

        malice_b["Malice"]:::user
        malice_b -->|"TokenCreator\n(has project-1 access)"| sa1
        malice_b -->|"403 DENIED\n(no project-2 access)"| sa2

        bob_b["Bob"]:::user
        bob_b -->|"TokenCreator"| sa1
        bob_b -->|"TokenCreator"| sa2
        bob_b -->|"TokenCreator"| sa3
    end
```

---

## 5. Defense Coverage Map

```mermaid
flowchart TD
    classDef covered   fill:#27ae60,color:#fff,stroke:#1e8449
    classDef partial   fill:#f39c12,color:#fff,stroke:#d68910
    classDef gap       fill:#e74c3c,color:#fff,stroke:#c0392b
    classDef control   fill:#2c3e50,color:#fff,stroke:#1a252f

    subgraph CONTROLS["Defense Controls"]
        c1["Trail of Bits\nsettings.json deny rules"]:::control
        c2["Claude Code /sandbox\n(CWD writes only)"]:::control
        c3["core.hooksPath redirect\nto read-only dir"]:::control
        c4["npm ci --ignore-scripts\nin all shared workflows"]:::control
        c5["npm provenance\nattestations"]:::control
        c6["pull_request_target\naudit + removal"]:::control
        c7["Per-project aiSecurityViewer SA\n+ per-user TokenCreator"]:::control
        c8["WebFetch domain allowlist\nin Claude Code"]:::control
        c9["Skill file content signing\n(not yet implemented)"]:::control
    end

    subgraph ATTACKS["Attack Vectors"]
        a1["A: Skill prompt injection\n→ session env exfil"]
        a2["B: .git/hooks write\nvia agent or Bash"]
        a3["B: @ecorp/git-hooks\nsupply chain"]
        a4["C: npm postinstall\nin reusable workflow"]
        a5["D: pull_request_target\nfork credential theft"]
        a6["aiSecurityViewer\norg-wide read"]
    end

    c1 -->|"blocks Edit(~/.bashrc)\nNOT .git/hooks/**"| a2
    c1 -.->|"❌ gap"| a2

    c2 -->|"restricts writes to CWD\n.git/hooks/ IS in CWD"| a2
    c2 -.->|"❌ gap"| a2

    c3 -->|"✅ neutralises .git/hooks\nwrite entirely"| a2

    c4 -->|"✅ stops postinstall\nrunning in CI"| a4

    c5 -->|"detective only\ntoken holder can still publish"| a3
    c5 -.->|"❌ not preventive"| a3

    c6 -->|"✅ removes footgun\nfor external PRs"| a5

    c7 -->|"✅ scopes SA to\nprojects user accesses"| a6

    c8 -->|"✅ blocks exfil from\nskill injection"| a1

    c9 -->|"✅ would block\nskill prompt injection"| a1

    style a1 fill:#e74c3c,color:#fff
    style a2 fill:#e74c3c,color:#fff
    style a3 fill:#e74c3c,color:#fff
    style a4 fill:#e74c3c,color:#fff
    style a5 fill:#e74c3c,color:#fff
    style a6 fill:#f39c12,color:#fff
```
