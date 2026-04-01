"""
Module 3, File 4: Supply Chain Attacks on AI Agent Tooling
===========================================================

Case study: the axios npm compromise (plain-crypto-js RAT injection)
applied to Claude CLI specifically.

Key insight: supply chain attacks target the INSTALL step, not the runtime.
Most agent-level defenses (hooks, permission systems, downscoping) are not
active at install time. The threat model is fundamentally different.

This file covers:
  1. The attack anatomy — how postinstall hooks are exploited
  2. The install-time environment — what's exposed before your defenses run
  3. Defense layers in order of effectiveness
  4. Where credential downscoping helps (and its limits)
  5. Lockfile integrity as the primary technical control
  6. Detecting compromised packages programmatically
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# 1. Attack Anatomy — Postinstall Hook as Attack Vector
# ---------------------------------------------------------------------------

def explain_postinstall_attack():
    print("=" * 65)
    print("Supply Chain Attack via postinstall Hook")
    print("=" * 65)
    print("""
  npm/bun package install sequence:
  ──────────────────────────────────────────────────────────────
  1. Resolve dependency tree (reads package.json / lockfile)
  2. Download tarballs from registry
  3. Extract to node_modules/
  4. Run lifecycle scripts in dependency order:
       preinstall → install → postinstall   ← ATTACK POINT
  5. Run root package postinstall

  The axios attack:
  ──────────────────────────────────────────────────────────────
  axios@1.14.1 added plain-crypto-js@4.2.1 as a dependency.
  plain-crypto-js/package.json:
    {
      "scripts": {
        "postinstall": "node setup.js"    ← runs automatically
      }
    }

  setup.js (after deobfuscation):
    const os = require('os');
    const { execSync } = require('child_process');

    // Platform detection
    if (process.platform === 'darwin') {
        // Drop C++ RAT binary to /Library/Caches/com.apple.act.mond
        // (mimics a legitimate Apple daemon name)
        // Establish LaunchAgent persistence plist
        // Beacon to 142.11.206.73:8000 every 60s
    }

  What `node setup.js` runs as:
    - User: whoever ran `npm install` (you, or your CI service account)
    - Environment: the FULL environment of the parent shell
      process.env includes: ANTHROPIC_API_KEY, AWS_ACCESS_KEY_ID,
        GITHUB_TOKEN, HOME, PATH, all shell exports
    - File access: read/write anywhere you can
    - Network: outbound to attacker C2

  Timeline of the axios attack:
    T+0min  Malicious plain-crypto-js published to npm
    T+0min  axios@1.14.1 published pulling in the malicious dep
    T+6min  Socket.dev scanner flags it — but npm install takes seconds
            Any developer who ran `npm install` in those 6 minutes
            (or later, before the package was pulled) is compromised
    """)


# ---------------------------------------------------------------------------
# 2. Install-Time Environment Exposure
# ---------------------------------------------------------------------------

def show_install_time_exposure():
    """
    Demonstrate what's visible in the environment at install time.
    This is what a malicious postinstall script can read.
    """
    print("=" * 65)
    print("Install-Time Environment Exposure")
    print("=" * 65)

    # Categorize what's typically in a developer's environment
    sensitive_patterns = [
        ("ANTHROPIC_API_KEY",   "Anthropic API — billing, model access, conversation data"),
        ("OPENAI_API_KEY",      "OpenAI API — same risks"),
        ("GITHUB_TOKEN",        "GitHub — push to repos, read private repos, create releases"),
        ("AWS_ACCESS_KEY_ID",   "AWS — scope depends on IAM policy"),
        ("AWS_SECRET_ACCESS_KEY","AWS secret — useless without key ID, but often paired"),
        ("GCLOUD_*",            "GCP credentials"),
        ("NPM_TOKEN",           "npm publish token — can publish packages (supply chain!)"),
        ("CI",                  "Reveals CI environment — may have broader service account"),
        ("HOME",                "Home directory path — guides file exfiltration"),
        ("SSH_AUTH_SOCK",       "SSH agent socket — can sign arbitrary SSH operations"),
    ]

    print("\n  Environment variables a malicious postinstall can read:")
    print(f"  {'Variable':30s}  {'Risk if exfiltrated':40s}  Present")
    print(f"  {'-'*30}  {'-'*40}  -------")

    for var, risk in sensitive_patterns:
        var_name = var.rstrip("*")
        # Check for any matching env vars
        present = any(k.startswith(var_name) for k in os.environ)
        marker = "YES ⚠" if present else "no"
        print(f"  {var:30s}  {risk:40s}  {marker}")

    print(f"""
  Total env vars in current shell: {len(os.environ)}
  These are ALL readable by `node setup.js` during postinstall.

  Critical point: the postinstall hook runs SYNCHRONOUSLY during
  `npm install`. Your hooks, downscoping rules, and permission
  systems are not yet active. Claude Code hasn't started.
  You haven't reviewed anything. The RAT is installed before
  you run a single command.
    """)


# ---------------------------------------------------------------------------
# 3. Where Credential Downscoping Helps
# ---------------------------------------------------------------------------

def analyze_downscoping_effectiveness():
    print("=" * 65)
    print("Credential Downscoping vs. Supply Chain Attack")
    print("=" * 65)
    print("""
  The downscoping-mcp architecture (from ~/projects/downscoping-mcp):

    Claude Code tool call
         │
         ▼
    PreToolUse hook (hook_handler.py)
         │ intercepts, rewrites token
         ▼
    subprocess(gh/aws/gcloud with scoped token)

  The RAT's access path:

    RAT binary (persistent, runs as you)
         │
         ├─ os.environ   — reads ALL env vars directly
         ├─ file reads   — reads ~/.claude/, ~/.aws/credentials, etc.
         ├─ subprocess   — executes arbitrary commands as you
         └─ network      — exfiltrates to C2

  The RAT NEVER goes through Claude's hook system.

  ┌─────────────────────────────────┬────────────────┬───────────────┐
  │ Credential / Action             │ Without DS-MCP │ With DS-MCP   │
  ├─────────────────────────────────┼────────────────┼───────────────┤
  │ ANTHROPIC_API_KEY exfiltrated   │ Full API access│ Full API      │
  │                                 │                │ (no downscope │
  │                                 │                │  for Anthropic│
  │                                 │                │  API)         │
  ├─────────────────────────────────┼────────────────┼───────────────┤
  │ GITHUB_TOKEN exfiltrated        │ Push, delete,  │ If only       │
  │                                 │ private reads  │ GITHUB_TOKEN  │
  │                                 │                │ _READONLY     │
  │                                 │                │ exported →    │
  │                                 │                │ read-only     │
  ├─────────────────────────────────┼────────────────┼───────────────┤
  │ AWS STS token exfiltrated       │ Full IAM perms │ Scoped token  │
  │                                 │                │ restricted by │
  │                                 │                │ STS server-   │
  │                                 │                │ side (cannot  │
  │                                 │                │ be upgraded)  │
  ├─────────────────────────────────┼────────────────┼───────────────┤
  │ GCP CAB token exfiltrated       │ Full project   │ Resource+perm │
  │                                 │ permissions    │ restricted    │
  │                                 │                │ by Google STS │
  │                                 │                │ (server-side) │
  ├─────────────────────────────────┼────────────────┼───────────────┤
  │ File system read (workspace,    │ Everything     │ Everything    │
  │ ~/.claude/, ~/.aws/credentials) │                │ (RAT bypasses │
  │                                 │                │ hooks)        │
  ├─────────────────────────────────┼────────────────┼───────────────┤
  │ Arbitrary command execution     │ Full RCE       │ Full RCE      │
  │                                 │                │ (hook system  │
  │                                 │                │ not in path)  │
  └─────────────────────────────────┴────────────────┴───────────────┘

  Key takeaway:
  Downscoping helps for AWS/GCP because restrictions are server-side.
  An exfiltrated GetFederationToken credential literally cannot be used
  for operations outside its policy, even with full local RCE.

  It does NOT help for:
    - ANTHROPIC_API_KEY (no server-side downscoping mechanism)
    - File system access (RAT has full OS permissions)
    - Persistent backdoor (once installed, it runs as you always)
    """)


# ---------------------------------------------------------------------------
# 4. Defense Layers — In Order of Effectiveness
# ---------------------------------------------------------------------------

def show_defense_layers():
    print("=" * 65)
    print("Defense Layers Against Supply Chain Attacks")
    print("=" * 65)
    print("""
  Layer 1: LOCKFILE INTEGRITY (stops dependency injection)
  ─────────────────────────────────────────────────────────
  A lockfile (package-lock.json, bun.lock, yarn.lock) pins the exact
  version AND content hash of every dependency, transitively.

  npm:  "integrity": "sha512-abc123..."  (SHA-512 of tarball)
  bun:  packages stored with content hash in bun.lock

  The axios attack would be stopped by a lockfile IF:
    - Your lockfile was committed and CI uses `npm ci` (not `npm install`)
    - `npm ci` refuses to install if lockfile doesn't match package.json
    - The malicious axios@1.14.1 would only affect you on fresh installs
      without a lockfile, or if you ran `npm update` without auditing

  Command: npm ci  (not npm install — ci is strict about lockfile)
  CI check:
    git diff --exit-code package-lock.json  # Fail if lockfile changed

  Layer 2: REGISTRY SCANNING (catches malicious packages early)
  ─────────────────────────────────────────────────────────────
  Socket.dev caught the axios attack in 6 minutes.
  Integration:
    npm install @socket.dev/cli -g
    npx socket npm install <package>  # wrapped npm with Socket scanning

  GitHub: install the Socket GitHub App — PRs that add malicious
          deps are automatically flagged before merge.

  Layer 3: DISABLE POSTINSTALL SCRIPTS (nuclear option)
  ─────────────────────────────────────────────────────
  npm config set ignore-scripts true  # Breaks packages that need build
  npm install --ignore-scripts        # Per-install override

  Better: use an allowlist approach:
    .npmrc:
      ignore-scripts=true
  Then explicitly re-enable for packages that need it.

  Caveat: many legitimate packages need postinstall (native modules,
  prisma, electron, etc.). This will break things.

  Layer 4: INSTALL IN AN ISOLATED ENVIRONMENT
  ─────────────────────────────────────────────
  Never run `npm install` as your primary user with all credentials
  in the environment.

  Option A: Container with no credentials mounted
    docker run --rm -v $(pwd):/app -w /app node:22 npm ci
    # Container has no AWS, GitHub, Anthropic credentials

  Option B: Separate shell session for installs
    env -i HOME=$HOME PATH=$PATH npm install  # strips most env vars
    # env -i starts with empty environment

  Option C: macOS Sandbox (for high-security workflows)
    sandbox-exec -f npm-profile.sb npm install
    # sandbox profile denies network except to npm registry

  Layer 5: CREDENTIAL HYGIENE (limits blast radius if breached)
  ─────────────────────────────────────────────────────────────
  This is where downscoping-mcp fits:
  - Never export high-privilege tokens in your interactive shell
  - Only export scoped tokens (GITHUB_TOKEN_READONLY, not GITHUB_TOKEN)
  - Use AWS STS GetFederationToken / GCP CAB for dynamically scoped creds
  - Store high-privilege creds in a secrets manager, not shell exports
    """)


# ---------------------------------------------------------------------------
# 5. Lockfile Integrity Check (runnable)
# ---------------------------------------------------------------------------

def demo_lockfile_integrity():
    """
    Show how a lockfile protects against dependency injection,
    and how to detect tampering.
    """
    print("=" * 65)
    print("Lockfile Integrity Demo")
    print("=" * 65)

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)

        # Simulate a package-lock.json with integrity hashes
        lockfile = {
            "name": "my-project",
            "lockfileVersion": 3,
            "packages": {
                "node_modules/axios": {
                    "version": "1.13.0",  # pinned version
                    "resolved": "https://registry.npmjs.org/axios/-/axios-1.13.0.tgz",
                    "integrity": "sha512-" + "a" * 86 + "==",  # SHA-512
                },
                "node_modules/plain-crypto-js": {
                    # This should NOT exist in a healthy lockfile
                    "version": "4.2.1",
                    "resolved": "https://registry.npmjs.org/plain-crypto-js/-/plain-crypto-js-4.2.1.tgz",
                    "integrity": "sha512-MALICIOUS" + "b" * 77 + "==",
                }
            }
        }

        lockfile_path = d / "package-lock.json"
        lockfile_path.write_text(json.dumps(lockfile, indent=2))

        print("\n  Scanning lockfile for suspicious packages...")

        KNOWN_MALICIOUS = {
            "plain-crypto-js",
            "colors2",       # historical: colors@1.4.44-liberty-2 attack
            "event-stream",  # historical: event-stream attack 2018
            "node-ipc",      # historical: protestware 2022
        }

        packages = lockfile["packages"]
        findings = []

        for pkg_path, meta in packages.items():
            pkg_name = pkg_path.replace("node_modules/", "").split("/")[0]
            version = meta.get("version", "?")

            if pkg_name in KNOWN_MALICIOUS:
                findings.append(("KNOWN_MALICIOUS", pkg_name, version))
                continue

            # Flag packages with unusual patterns
            integrity = meta.get("integrity", "")
            if "MALICIOUS" in integrity:  # obviously synthetic
                findings.append(("SUSPICIOUS_INTEGRITY", pkg_name, version))

            # In production: check against Socket.dev or OSV.dev API
            # GET https://api.osv.dev/v1/query
            # {"package": {"name": pkg_name, "ecosystem": "npm"}, "version": version}

        if findings:
            print(f"\n  ⚠ FINDINGS:")
            for severity, name, version in findings:
                print(f"    [{severity}] {name}@{version}")
        else:
            print("  No known-malicious packages found")

        print(f"\n  Total packages in lockfile: {len(packages)}")
        print("""
  Production lockfile audit approach:
    1. Use `npm audit` (free, npm registry advisories)
    2. Use `socket npm install` (catches novel packages, not just known CVEs)
    3. Use `osv-scanner` (Google's open-source vulnerability scanner)
    4. Check for new packages in lockfile diffs on PRs:
         git diff HEAD~1 package-lock.json | grep '"node_modules/' | grep '^+'
         ^ any new dependency in a PR should be manually reviewed
        """)


# ---------------------------------------------------------------------------
# 6. The `env -i` Install Isolation Technique
# ---------------------------------------------------------------------------

def demo_env_isolation():
    """
    Show how env -i strips credentials from the install environment.
    """
    print("=" * 65)
    print("Install Isolation with env -i")
    print("=" * 65)

    # Show what a normal subprocess inherits
    print(f"\n  Normal subprocess inherits {len(os.environ)} env vars")
    sensitive = [k for k in os.environ if any(
        pat in k.upper() for pat in
        ["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH"]
    )]
    print(f"  Sensitive-looking vars in current env: {len(sensitive)}")
    for s in sensitive[:5]:
        print(f"    {s}")
    if len(sensitive) > 5:
        print(f"    ... and {len(sensitive)-5} more")

    # Show what env -i passes
    minimal_env = {
        "HOME": os.environ.get("HOME", ""),
        "PATH": os.environ.get("PATH", ""),
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }
    print(f"\n  With env -i (minimal environment): {len(minimal_env)} vars")
    for k, v in minimal_env.items():
        print(f"    {k}={v[:50]}{'...' if len(v) > 50 else ''}")

    print(f"""
  A malicious postinstall running in this minimal env sees:
    - No API keys
    - No cloud credentials
    - No tokens
    - Still has HOME (can read ~/.aws/credentials if it exists)

  Shell command for isolated installs:
    env -i HOME=$HOME PATH=$PATH npm ci

  Or as a Makefile rule:
    install:
        env -i HOME=$(HOME) PATH=$(PATH) npm ci

  Note: still doesn't protect ~/.aws/credentials or ~/.config/gcloud/
  For full isolation, use a container or a separate user account.
    """)


# ---------------------------------------------------------------------------
# 7. What an Anthropic Security Engineer Should Recommend
# ---------------------------------------------------------------------------

def security_recommendations():
    print("=" * 65)
    print("Recommended Controls for Claude CLI Supply Chain Security")
    print("=" * 65)
    print("""
  For Anthropic (shipping Claude CLI):
  ──────────────────────────────────────────────────────────────
  1. Pin ALL transitive dependencies in bun.lock / package-lock.json
     and ship with `npm ci` in install docs (not `npm install`)

  2. Enable GitHub's dependency review action on the claude-code repo:
       uses: actions/dependency-review-action@v4
     → PRs that introduce vulnerable or newly-published packages are blocked

  3. Enable Socket.dev GitHub App on the repo
     → Detects new behaviors (network access, env access) in PRs

  4. Publish via trusted publishing (GitHub OIDC → npm)
     → Eliminates long-lived npm tokens (the exact vector used in the attack)
     → `npm publish` only works from CI with a short-lived OIDC token

  5. Add a postinstall check that hashes all scripts before running:
     (controversial — breaks the fix by requiring install to verify)

  For users of Claude CLI:
  ──────────────────────────────────────────────────────────────
  1. Never export ANTHROPIC_API_KEY in your default shell profile
     (use a secrets manager or export only in sessions that need it)

  2. Use downscoping-mcp for AWS/GCP — the server-side enforcement
     survives even full local compromise

  3. Run `npm ci` not `npm install` — respects the lockfile strictly

  4. Consider running Claude CLI in a Docker container with only the
     credentials it needs bind-mounted, and network policy controlling
     outbound connections to anthropic.com only

  5. Use Socket.dev CLI wrapper:
       npx @socket.dev/cli npm install @anthropic-ai/claude-code

  The fundamental gap — ANTHROPIC_API_KEY:
  ──────────────────────────────────────────────────────────────
  AWS has STS downscoping. GCP has CAB. GitHub has fine-grained PATs.
  Anthropic currently has no equivalent for API keys.

  A scoped Anthropic API key that could only:
    - Read conversation history
    - Make completions up to N tokens/day
    - Call specific models only

  ...would dramatically reduce the blast radius of key exfiltration.
  This is a product/security gap worth raising in the interview.
    """)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    explain_postinstall_attack()
    show_install_time_exposure()
    analyze_downscoping_effectiveness()
    show_defense_layers()
    demo_lockfile_integrity()
    demo_env_isolation()
    security_recommendations()
