"""
Module 3, File 1: Structured Threat Model for Adversarial Web Search
=====================================================================

This file implements a structured threat model using the STRIDE framework
applied to an AI agent's web search + content fetch pipeline.

STRIDE:
  S — Spoofing       (attacker pretends to be a legitimate source)
  T — Tampering      (attacker modifies data in transit or at rest)
  R — Repudiation    (no audit trail; attacker can deny)
  I — Info Disclosure (agent reveals sensitive context to attacker)
  D — Denial of Service (attacker starves agent of valid information)
  E — Elevation of Privilege (agent executes attacker-controlled instructions)

For a security engineer interview at Anthropic, you should be able to:
  1. Draw the agent's data flow diagram
  2. Identify trust boundaries
  3. Apply STRIDE to each component
  4. Propose mitigations
"""

from dataclasses import dataclass, field
from enum import Flag, auto
from typing import Optional


# ---------------------------------------------------------------------------
# 1. Data Flow Model
# ---------------------------------------------------------------------------

@dataclass
class DataFlow:
    """Represents a flow of data between components in the agent pipeline."""
    source: str
    destination: str
    data_type: str
    crosses_trust_boundary: bool
    notes: str = ""


@dataclass
class Component:
    """A component in the agent's architecture."""
    name: str
    trust_level: str  # "trusted", "semi-trusted", "untrusted"
    description: str


AGENT_PIPELINE_COMPONENTS = [
    Component("User",              "trusted",     "Human user issuing queries"),
    Component("Agent Core (LLM)",  "trusted",     "Claude model processing queries"),
    Component("Search API",        "semi-trusted", "Google/Bing API — returns rankings"),
    Component("Web Pages",         "untrusted",   "Fetched HTML/text from arbitrary URLs"),
    Component("Code Executor",     "trusted",     "Sandbox executing fetched code"),
    Component("File System",       "trusted",     "Agent's workspace files"),
]

AGENT_PIPELINE_FLOWS = [
    DataFlow("User",              "Agent Core",  "query string",     False),
    DataFlow("Agent Core",        "Search API",  "search query",     True,  "Agent identity may be detectable"),
    DataFlow("Search API",        "Agent Core",  "URL list + titles",True,  "Attacker can influence rankings"),
    DataFlow("Agent Core",        "Web Pages",   "HTTP GET request", True,  "Trust boundary: internet"),
    DataFlow("Web Pages",         "Agent Core",  "HTML/text content",True,  "UNTRUSTED: injection vector"),
    DataFlow("Agent Core",        "Code Executor","code string",     False, "Code sourced from web pages"),
    DataFlow("Agent Core",        "File System", "file operations",  False, "Writes influenced by web content"),
]


def print_data_flow_diagram():
    print("=" * 60)
    print("Agent Web Search — Data Flow Diagram")
    print("=" * 60)
    print()
    print("  Components:")
    for c in AGENT_PIPELINE_COMPONENTS:
        trust_icon = {"trusted": "✓", "semi-trusted": "~", "untrusted": "✗"}[c.trust_level]
        print(f"  [{trust_icon}] {c.name:30s} ({c.trust_level})")

    print()
    print("  Data Flows:")
    for f in AGENT_PIPELINE_FLOWS:
        boundary = "⚠ TRUST BOUNDARY" if f.crosses_trust_boundary else ""
        print(f"  {f.source:25s} → {f.destination:25s} [{f.data_type}] {boundary}")
        if f.notes:
            print(f"    Note: {f.notes}")


# ---------------------------------------------------------------------------
# 2. STRIDE Threat Enumeration
# ---------------------------------------------------------------------------

class STRIDECategory(Flag):
    SPOOFING           = auto()
    TAMPERING          = auto()
    REPUDIATION        = auto()
    INFO_DISCLOSURE    = auto()
    DENIAL_OF_SERVICE  = auto()
    ELEVATION          = auto()


@dataclass
class Threat:
    id: str
    title: str
    categories: STRIDECategory
    component: str
    attack_description: str
    concurrency_angle: Optional[str]
    mitigations: list[str]
    severity: str  # "Critical", "High", "Medium", "Low"


THREATS = [
    Threat(
        id="T-01",
        title="Prompt Injection via Search Result Content",
        categories=STRIDECategory.TAMPERING | STRIDECategory.ELEVATION,
        component="Web Pages → Agent Core",
        attack_description=(
            "Attacker places an adversarially crafted webpage that ranks highly for "
            "common developer queries. The page contains natural-language instructions "
            "embedded in HTML comments, invisible text, or at the end of legitimate "
            "documentation. When the agent fetches and processes the page, the injected "
            "instructions are treated as agent directives."
        ),
        concurrency_angle=(
            "With parallel fetching, a malicious page arriving late may bypass "
            "a validation check that ran on earlier, clean results. The aggregated "
            "context is assembled from multiple concurrent fetches, and re-validation "
            "of the assembled context may not occur."
        ),
        mitigations=[
            "Clearly delimit fetched content from system instructions in the prompt",
            "Run content classification on each fetched document before including in context",
            "Implement a 'contamination score' for each content chunk; refuse to act on "
            "high-scoring chunks",
            "Never execute code fetched from web search without human approval",
            "Use provenance tags: mark all web-sourced content with [EXTERNAL_CONTENT]",
        ],
        severity="Critical",
    ),
    Threat(
        id="T-02",
        title="Adversarial SEO / Dynamic Content Serving",
        categories=STRIDECategory.SPOOFING | STRIDECategory.TAMPERING,
        component="Search API → Agent Core",
        attack_description=(
            "Attacker optimizes a page to rank highly for terms developers commonly "
            "search while using AI agents (e.g., 'python jwt decode example', "
            "'how to write async file io python'). The page serves different content "
            "to automated clients (detected via missing JS execution, bot User-Agent, "
            "high request frequency) vs. human browsers."
        ),
        concurrency_angle=(
            "An agent fetching search results concurrently may fetch pages in an order "
            "the attacker can influence. By serving clean content to early requests "
            "(which establish trust) and malicious content to later requests, the "
            "attacker exploits the temporal ordering of parallel fetches."
        ),
        mitigations=[
            "Randomize User-Agent and request timing to reduce fingerprinting",
            "Compare cached vs. live content; flag large divergences",
            "Use multiple independent fetches (from different IPs/agents) and compare",
            "Weight search result trust by domain reputation and age",
            "Prefer official documentation sources over tutorials/blogs for code",
        ],
        severity="High",
    ),
    Threat(
        id="T-03",
        title="Malicious Code via Fetched Snippet",
        categories=STRIDECategory.ELEVATION,
        component="Web Pages → Code Executor",
        attack_description=(
            "Agent fetches a code snippet (GitHub gist, Stack Overflow answer, "
            "documentation example) containing malicious code. The malicious payload "
            "may be obfuscated (base64, unicode homoglyphs, hidden in rarely-executed "
            "branches) or appear innocuous (a 'logging' call that exfiltrates data)."
        ),
        concurrency_angle=(
            "A code fetch and a subsequent safety check run concurrently. If the "
            "safety checker runs on the raw fetch result but execution runs on a "
            "decoded/deobfuscated version, a deobfuscation step between check and "
            "execute can introduce malicious payload."
        ),
        mitigations=[
            "Never auto-execute code fetched from the internet",
            "Present fetched code to the user with a diff view before running",
            "Run static analysis (bandit, semgrep) on any fetched Python code",
            "Execute in a sandbox with network isolation, restricted syscalls (seccomp)",
            "Check fetched URLs against known-malicious domain lists",
        ],
        severity="Critical",
    ),
    Threat(
        id="T-04",
        title="Race Condition in Parallel Fetch Validation",
        categories=STRIDECategory.TAMPERING | STRIDECategory.ELEVATION,
        component="Parallel fetch pipeline",
        attack_description=(
            "Agent fetches N search results concurrently using asyncio.gather(). "
            "Validation runs per-result as results arrive. A slow, malicious response "
            "arrives after the agent has already begun processing validated results. "
            "The late-arriving response is appended to the context without re-running "
            "the full context-level validation."
        ),
        concurrency_angle=(
            "This is the core concurrency vulnerability. The race is between: "
            "(a) validation of individual chunks, and "
            "(b) assembly of the final context. "
            "Fix: validate the ASSEMBLED context, not just individual chunks."
        ),
        mitigations=[
            "Always validate the fully assembled context, not just individual chunks",
            "Use a two-phase fetch: (1) fetch all, (2) validate all, (3) assemble",
            "Set a strict timeout on fetches; drop late arrivals",
            "Treat any content that arrives after a validation checkpoint as untrusted",
        ],
        severity="High",
    ),
    Threat(
        id="T-05",
        title="Information Disclosure via Query Content",
        categories=STRIDECategory.INFO_DISCLOSURE,
        component="Agent Core → Search API",
        attack_description=(
            "Search queries can contain sensitive information from the agent's context: "
            "filenames, error messages with stack traces, internal project names, "
            "partial secrets. This information is sent to a third-party search provider "
            "and may appear in access logs, query analytics, or be used to profile "
            "the user/organization."
        ),
        concurrency_angle=(
            "In a multi-agent system, multiple agents making concurrent queries "
            "can collectively reveal more information than any single agent would "
            "(correlation attack across queries)."
        ),
        mitigations=[
            "Sanitize queries: remove file paths, error details, project-specific terms",
            "Use a local/private search index for sensitive codebases",
            "Rate-limit and deduplicate concurrent queries to reduce correlation risk",
            "Never include raw stack traces or file contents in search queries",
        ],
        severity="Medium",
    ),
]


def print_threat_model():
    print("\n" + "=" * 60)
    print("STRIDE Threat Model")
    print("=" * 60)

    by_severity = {}
    for t in THREATS:
        by_severity.setdefault(t.severity, []).append(t)

    for severity in ["Critical", "High", "Medium", "Low"]:
        threats = by_severity.get(severity, [])
        if not threats:
            continue
        print(f"\n  [{severity}]")
        for t in threats:
            categories = [c.name for c in STRIDECategory if c in t.categories]
            print(f"\n  {t.id}: {t.title}")
            print(f"    STRIDE: {', '.join(categories)}")
            print(f"    Component: {t.component}")
            print(f"    Attack: {t.attack_description[:120]}...")
            if t.concurrency_angle:
                print(f"    Concurrency: {t.concurrency_angle[:120]}...")
            print(f"    Mitigations:")
            for m in t.mitigations[:2]:  # print top 2 for brevity
                print(f"      • {m}")


# ---------------------------------------------------------------------------
# 3. Attack Tree for T-04 (Race Condition in Parallel Fetch)
# ---------------------------------------------------------------------------

ATTACK_TREE = {
    "goal": "Inject malicious instruction into agent context",
    "conditions": "OR",
    "children": [
        {
            "goal": "Exploit parallel fetch race (T-04)",
            "conditions": "AND",
            "children": [
                {"goal": "Achieve high search ranking for target query",
                 "method": "adversarial SEO or Google Ads"},
                {"goal": "Serve clean content to fast requests",
                 "method": "CDN cache warming"},
                {"goal": "Serve malicious content to slow/late requests",
                 "method": "dynamic page serving based on request timing"},
                {"goal": "Late response arrives after validation checkpoint",
                 "method": "artificially slow server response (429 → retry)"},
            ],
        },
        {
            "goal": "Direct prompt injection (T-01)",
            "conditions": "AND",
            "children": [
                {"goal": "Control webpage content",
                 "method": "own a high-ranking domain OR exploit open redirect"},
                {"goal": "Agent fetches the page",
                 "method": "rank for likely agent query"},
                {"goal": "Injection bypasses content filter",
                 "method": "encode injection in unicode homoglyphs or zero-width chars"},
            ],
        },
    ],
}


def print_attack_tree(node: dict, depth: int = 0):
    indent = "  " * depth
    print(f"{indent}[{node.get('conditions', 'LEAF')}] {node['goal']}")
    if "method" in node:
        print(f"{indent}  Method: {node['method']}")
    for child in node.get("children", []):
        print_attack_tree(child, depth + 1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print_data_flow_diagram()
    print_threat_model()

    print("\n" + "=" * 60)
    print("Attack Tree: Inject Instruction into Agent Context")
    print("=" * 60)
    print()
    print_attack_tree(ATTACK_TREE)

    print("\n" + "=" * 60)
    print("Key Interview Points")
    print("=" * 60)
    print("""
  1. The fundamental problem: agents conflate data and instructions.
     A webpage is data, but contains text the LLM may treat as instructions.
     Solution: explicit data/instruction boundary in prompts + validation layer.

  2. The concurrency amplifier: parallel fetching creates a race between
     individual-chunk validation and whole-context assembly.
     Solution: validate assembled context, not just chunks.

  3. The adversarial SEO angle: ranking above legitimate results is achievable
     with a modest budget via Google Ads. Defender can't control search rankings.
     Solution: prefer known-good domains; require human approval for code execution.

  4. Defense in depth is required: no single mitigation is sufficient.
     Layer: prompt hardening + content classification + provenance tracking +
     sandboxed execution + human-in-the-loop for high-risk actions.
    """)
