"""
Module 3, File 3: Software Distribution Security — What Obfuscation Actually Protects
=======================================================================================

A case study comparing two real-world CLI tool distribution strategies:
  - Claude Code: TypeScript → Bun-bundled JS monolith (12.5 MB)
  - OpenAI Codex: Rust core → compiled native binary + thin JS wrapper

This matters for security engineers because:
  1. Distribution architecture determines RE difficulty
  2. Source maps are a common accidental secret exposure vector
  3. The "it's obfuscated" assumption is often false for JS

Run this file to see concrete demonstrations of what minification
actually hides vs. what remains fully visible.
"""

import ast
import dis
import re
import textwrap


# ---------------------------------------------------------------------------
# 1. What Minification Actually Does (and Doesn't) Hide
# ---------------------------------------------------------------------------

ORIGINAL_CODE = '''
async function validatePermissions(sessionContext, requestedPermission) {
    // Check if the user has elevated access for this session
    const userRole = await getUserRole(sessionContext.userId);
    const isElevated = sessionContext.flags.includes("KAIROS_MODE");

    if (!hasPermission(userRole, requestedPermission) && !isElevated) {
        auditLog.warn("Permission denied", {
            user: sessionContext.userId,
            requested: requestedPermission,
            role: userRole,
        });
        return { granted: false, reason: "insufficient_role" };
    }

    return { granted: true, expiresAt: Date.now() + SESSION_TTL_MS };
}
'''

MINIFIED_CODE = '''
async function a(b,c){const d=await e(b.f);const g=b.h.includes("KAIROS_MODE");if(!i(d,c)&&!g){j.k("Permission denied",{l:b.f,m:c,n:d});return{o:false,p:"insufficient_role"}}return{o:true,q:Date.now()+r}}
'''

MINIFIED_NO_STRINGS = '''
async function a(b,c){const d=await e(b.f);const g=b.h.includes(s1);if(!i(d,c)&&!g){j.k(s2,{l:b.f,m:c,n:d});return{o:false,p:s3}}return{o:true,q:Date.now()+r}}
'''


def analyze_obfuscation():
    print("=" * 70)
    print("What Minification Hides vs. Reveals")
    print("=" * 70)

    print("""
  ORIGINAL (with source map):
  ──────────────────────────
""")
    print(textwrap.indent(ORIGINAL_CODE.strip(), "  "))

    print("""
  MINIFIED (name-mangled, comments stripped):
  ───────────────────────────────────────────
""")
    print(textwrap.indent(MINIFIED_CODE.strip(), "  "))

    print("""
  What minification HIDES:
    ✗ Function name: validatePermissions → a
    ✗ Parameter names: sessionContext → b, requestedPermission → c
    ✗ Variable names: userRole → d, isElevated → g
    ✗ Helper names: getUserRole → e, hasPermission → i, auditLog.warn → j.k
    ✗ Comments (the "KAIROS_MODE" intent explanation)
    ✗ Object property names: userId → f, flags → h, granted → o

  What minification CANNOT HIDE:
    ✓ String literals: "KAIROS_MODE", "Permission denied", "insufficient_role"
    ✓ Control flow: the if/else structure, early return
    ✓ Algorithm: check role, check flag, log on denial, return TTL on success
    ✓ API shape: what the function takes and returns
    ✓ The existence of a special "KAIROS_MODE" flag (the feature name!)
    ✓ SESSION_TTL_MS constant (even if renamed to r)

  KEY INSIGHT:
    A skilled reverse engineer reading minified JS sees the logic clearly.
    They lose names but retain semantics. With a tool like Ghidra's JS
    decompiler or manual analysis + renaming, recovery to 60-70% of
    original clarity takes hours, not days.

    The source map adds: naming (huge for intent), file structure,
    and build-time constants like feature flags.
    """)


# ---------------------------------------------------------------------------
# 2. What a Source Map Exposes
# ---------------------------------------------------------------------------

def explain_source_maps():
    print("=" * 70)
    print("What a .map File Actually Contains")
    print("=" * 70)
    print("""
  A TypeScript source map (*.js.map) is a JSON file containing:

  {
    "version": 3,
    "sources": [
      "src/entrypoints/cli.tsx",
      "src/core/permissions.ts",
      "src/features/kairos/autonomous_mode.ts",   ← feature name in PATH
      "src/utils/audit_log.ts",
      ...
    ],
    "sourceRoot": "/internal/claude-code/",       ← internal path prefix!
    "names": [
      "validatePermissions", "sessionContext", "requestedPermission",
      "getUserRole", "userRole", "isElevated", "KAIROS_MODE",
      "SESSION_TTL_MS", "auditLog", "hasPermission",
      ...                                          ← ALL original names
    ],
    "mappings": "AAAA,SAAS..."                   ← position mapping (VLQ)
  }

  What this adds beyond minified JS:
  ┌─────────────────────────────────┬──────────┬──────────────────────────┐
  │ Information                     │ Minified │ + Source Map             │
  ├─────────────────────────────────┼──────────┼──────────────────────────┤
  │ Algorithm/logic                 │ VISIBLE  │ VISIBLE                  │
  │ String literals                 │ VISIBLE  │ VISIBLE                  │
  │ API endpoints                   │ VISIBLE  │ VISIBLE                  │
  │ Control flow                    │ VISIBLE  │ VISIBLE                  │
  │ Function/variable names         │ HIDDEN   │ EXPOSED (all of them)    │
  │ Original file structure         │ HIDDEN   │ EXPOSED (full tree)      │
  │ Internal directory layout       │ HIDDEN   │ EXPOSED (with root path) │
  │ Feature flag names (strings)    │ VISIBLE! │ VISIBLE + context        │
  │ Feature flag names (constants)  │ HIDDEN   │ EXPOSED                  │
  │ Code comments                   │ HIDDEN   │ EXPOSED                  │
  │ TypeScript types/interfaces     │ HIDDEN   │ EXPOSED (via .d.ts)      │
  └─────────────────────────────────┴──────────┴──────────────────────────┘

  The accident: shipping cli.js.map is like publishing your entire
  commented TypeScript source alongside the minified bundle.
  It's not a partial leak — it's essentially full source exposure.

  HOW TO PREVENT:
    In your bundler config, set:
      Webpack:  devtool: false  (production)  or  'source-map'  (dev only)
      Bun:      --sourcemap=none  (default for production builds)
      esbuild:  --sourcemap=false

    Add to .npmignore:
      *.map
      *.js.map
      *.ts.map

    CI check (add to your pipeline):
      if find . -name "*.map" | grep -q .; then
          echo "ERROR: source maps found in package"
          exit 1
      fi
    """)


# ---------------------------------------------------------------------------
# 3. Rust Binary vs. JS Bundle — RE Difficulty
# ---------------------------------------------------------------------------

def compare_re_difficulty():
    print("=" * 70)
    print("RE Difficulty: Compiled Rust Binary vs. JS Bundle")
    print("=" * 70)
    print("""
  JAVASCRIPT BUNDLE (Claude Code approach):
  ──────────────────────────────────────────
  Format:       Text (UTF-8 source code, just whitespace-compressed)
  Semantics:    Fully preserved — it's still JS, just hard to read
  Tools needed: A text editor + Prettier to format
  Time to RE:   Hours to days for a skilled JS developer
  What you get: Complete logic, all string literals, full API surface
  Residual protection: Variable/function name obfuscation only

  Sample output after `prettier cli.js`:
    async function a(b, c) {
      const d = await e(b.f);         // getUserRole(session.userId)
      const g = b.h.includes("KAIROS_MODE");  // ← feature name is RIGHT THERE
      ...
    }

  COMPILED RUST BINARY (Codex approach):
  ───────────────────────────────────────
  Format:       Machine code (ELF/Mach-O/PE binary)
  Semantics:    Largely lost — variable names, types, structure gone
  Tools needed: Ghidra, Binary Ninja, IDA Pro ($3500/seat)
  Time to RE:   Weeks to months for a skilled reverse engineer
  What you get: Approximate C pseudocode with no names, mangled types
  Residual protection: Everything except broad algorithmic patterns

  Sample Ghidra decompile output:
    undefined8 FUN_00123456(long param_1, undefined8 param_2) {
      long lVar1;
      lVar1 = FUN_00098765(*(long *)(param_1 + 0x18));
      if ((*(int *)(param_1 + 0x30) & 4) == 0) {
          FUN_00045678(0, param_2, lVar1);
          return 0;
      }
      return *(undefined8 *)(lVar1 + 8) + 0x927c0;
    }

  COMPARISON:
  ┌─────────────────────────────┬───────────┬──────────────┐
  │ Metric                      │ JS Bundle │ Rust Binary  │
  ├─────────────────────────────┼───────────┼──────────────┤
  │ RE time (expert)            │ Days      │ Months       │
  │ Logic recovery              │ ~90%      │ ~30%         │
  │ Name recovery               │ ~5%       │ ~0%          │
  │ String literal visibility   │ 100%      │ 100%         │
  │ Algorithm comprehension     │ High      │ Low          │
  │ Feature flag discovery      │ High*     │ Low          │
  │ Architectural intent        │ Medium    │ Very low     │
  └─────────────────────────────┴───────────┴──────────────┘
  * Strings are always visible in both, but JS preserves context

  PRACTICAL IMPLICATION:
    Anthropic's choice to ship a JS monolith means a determined attacker
    can understand Claude Code's architecture in a weekend.
    Shipping a Rust binary (like Codex) would raise that to months.

    This is a genuine security trade-off: TypeScript is faster to develop,
    easier to iterate, easier to hire for — but distributing it as JS
    offers thin protection compared to a compiled language.
    """)


# ---------------------------------------------------------------------------
# 4. Python Analogy — What .pyc Protects
# ---------------------------------------------------------------------------

def python_obfuscation_analogy():
    print("=" * 70)
    print("Python Analogy: What .pyc / Cython / Nuitka Actually Protect")
    print("=" * 70)

    # Show what dis.dis reveals from bytecode
    def secret_function(x: int, y: int) -> int:
        """This function computes something 'secret'."""
        threshold = 42
        if x > threshold:
            return x * y + threshold
        return x + y

    print("\n  Original Python source:")
    import inspect
    src = inspect.getsource(secret_function)
    for line in src.splitlines():
        print(f"    {line}")

    print("\n  Bytecode (what .pyc contains — fully decompilable):")
    for instr in dis.get_instructions(secret_function):
        print(f"    {instr.offset:4d}  {instr.opname:25s}  {str(instr.argval or '')}")

    print("""
  .pyc files are trivially decompilable with tools like `decompile3` or `uncompyle6`.
  They provide NO meaningful protection — slightly harder than source, but minutes of work.

  For Python, real protection options (in order of effectiveness):
  ┌──────────────────┬─────────────┬──────────────────────────────────┐
  │ Approach         │ RE Difficulty│ Notes                            │
  ├──────────────────┼─────────────┼──────────────────────────────────┤
  │ .pyc bytecode    │ Minutes     │ Decompiles perfectly              │
  │ PyArmor          │ Hours       │ Obfuscates bytecode; not strong   │
  │ Cython → .so     │ Days        │ Compiles to C; Ghidra needed      │
  │ Nuitka → binary  │ Weeks       │ Full Python→C compilation         │
  │ Server-side only │ N/A         │ Best: never distribute logic      │
  └──────────────────┴─────────────┴──────────────────────────────────┘

  KEY LESSON FOR SECURITY ENGINEERS:
    The only true protection is never distributing logic to untrusted clients.
    Any code that runs on the client WILL be readable by a determined attacker.
    Design your system assuming the client-side code is fully known.

    This applies directly to Claude Code's security model:
    - All security enforcement should happen server-side (Anthropic's API)
    - Client-side safety checks (hooks, permission prompts) are UX, not security
    - The real security boundary is the API key and server-side policy enforcement
    """)


# ---------------------------------------------------------------------------
# 5. Detecting Accidental Source Map Shipping in CI
# ---------------------------------------------------------------------------

def source_map_ci_check():
    print("=" * 70)
    print("CI/CD Check: Prevent Accidental Source Map Shipping")
    print("=" * 70)
    print('''
  Add this to your release pipeline (bash):

  #!/bin/bash
  # check_no_sourcemaps.sh — run before `npm publish`

  set -euo pipefail

  PACKAGE_DIR="${1:-.}"
  ERRORS=0

  echo "Checking for source maps in package..."

  # Check for .map files
  while IFS= read -r -d "" mapfile; do
      echo "ERROR: Source map found: $mapfile"
      ERRORS=$((ERRORS + 1))
  done < <(find "$PACKAGE_DIR" -name "*.map" -not -path "*/node_modules/*" -print0)

  # Check for sourceMappingURL comments in JS files
  while IFS= read -r jsfile; do
      if grep -q "sourceMappingURL=" "$jsfile"; then
          echo "ERROR: sourceMappingURL reference in: $jsfile"
          ERRORS=$((ERRORS + 1))
      fi
  done < <(find "$PACKAGE_DIR" -name "*.js" -not -path "*/node_modules/*")

  if [ "$ERRORS" -gt 0 ]; then
      echo "FAILED: $ERRORS source map issue(s) found"
      exit 1
  fi

  echo "OK: No source maps found"

  Also add to .npmignore:
    **/*.map
    **/*.js.map
    **/*.ts.map
    **/*.d.ts.map
    tsconfig.json
    src/
    *.ts
    !*.d.ts

  And to bun/esbuild/webpack config (enforce at build time, not just .npmignore):
    # bun build
    bun build src/cli.ts --outfile cli.js --minify --no-source-maps

    # esbuild
    esbuild src/cli.ts --bundle --minify --outfile=cli.js
    # (omit --sourcemap flag entirely for production)
    ''')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    analyze_obfuscation()
    explain_source_maps()
    compare_re_difficulty()
    python_obfuscation_analogy()
    source_map_ci_check()

    print("=" * 70)
    print("Summary: What This Means for the Interview")
    print("=" * 70)
    print("""
  The question you raised — "how good is the obfuscation?" — is exactly
  the right question for a security engineer to ask about any distribution.

  The answer for Claude Code: not very strong.
    - JS bundles are readable with standard tools
    - String literals (including feature names) are always visible
    - The .map accident exposed what little name obfuscation remained
    - The real security boundary was always the API, not the client bundle

  OpenAI Codex made a different trade-off:
    - Rust core → compiled binary → orders of magnitude harder to RE
    - Open-sourced the result anyway (Apache-2.0), so moot point
    - But the architecture would be defensible if kept closed-source

  For Anthropic's new KAIROS-style autonomous agent mode:
    - If deployed as a client-side JS tool, the same exposure applies
    - Safety-critical logic (permission checks, action limits) should be
      server-enforced, not client-side JS that any user can read
    - The circuit breaker and reversibility budget patterns (Module 2)
      are only meaningful if they can't be bypassed by reading the source

  Interview angle: "What's your threat model for the client binary?"
  is a strong question that shows you understand the security boundaries.
    """)
