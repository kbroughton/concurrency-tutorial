# Module 2: Concurrency as an Attack Surface

## Why Concurrency Creates Security Bugs

Most security vulnerabilities in concurrent systems arise from one root cause:
**the programmer assumes an operation is atomic when it isn't.**

A concurrent security audit asks: *Between any two lines of code, can another thread/process
run and invalidate an assumption?*

---

## Recommended Coordination Patterns

Before studying what goes wrong, know the two patterns Claude Code recommends
to avoid shared-filesystem conflicts by construction:

**Git worktrees** — `git worktree add ../agent-1-workspace -b agent/task-1`

Each agent gets an independent working directory backed by the same repo.
Separate index, separate HEAD, separate files on disk. Agents can't race
on workspace files because they're literally in different directories.
They reconcile via normal git merge/rebase when done.

```
repo/.git  (shared object store, history)
    │
    ├── repo/           (main worktree — human or coordinator)
    ├── ../agent-1/     (worktree 1 — branch agent/task-1)
    └── ../agent-2/     (worktree 2 — branch agent/task-2)
```

**Agent teams** — a coordinator agent spawns sub-agents with non-overlapping
task assignments. Agents communicate through structured tool calls and defined
output schemas, not by reading each other's files.

**What these patterns do NOT eliminate** (still relevant to study):
- `~/.claude/` state files are shared across all worktrees — the race from Module 1 persists
- External shared resources (databases, APIs, shared config endpoints) hit the same races at a higher abstraction level
- Understanding *why* worktrees work requires understanding what they isolate and what they don't

---

## The Threat Model: Multi-Agent Systems

Claude Code (and AI agent systems generally) create new concurrency threat models:

```
Agent A ──┐
          ├──► Shared Filesystem ──► Agent B
Agent C ──┘         │
                     └──► Shared ~/.claude/ State Files
                               (NOT isolated by worktrees)
```

With worktrees, workspace file races are eliminated. What remains:
- `~/.claude/security_warnings_state_*.json` — shared across all sessions
- GitHub / cloud API rate limits — shared across all agents using the same key
- External databases or services agents write to concurrently
- The git object store itself (though git handles concurrent writes safely)

Each of these still creates race windows.

---

## Key Vulnerability Classes

### 1. Read-Modify-Write Races
An agent reads state, computes a new value, writes back.
If two agents do this simultaneously, one update is silently lost.

*Example*: Two Claude Code sessions both updating `memory.json`.

### 2. TOCTOU (Time-of-Check / Time-of-Use)
Security check happens at T1, protected operation at T2.
Attacker changes the resource between T1 and T2.

*Example*: `if path.is_safe(): open(path)` — attacker swaps path to symlink.

### 3. Deadlock
Two agents each hold a resource the other needs.
Both wait forever; the system hangs.

*Example*: Agent A holds lock on `config.json`, waits for `state.json`.
         Agent B holds lock on `state.json`, waits for `config.json`.

### 4. Livelock
Agents keep changing state in response to each other, but make no progress.
Like two people in a hallway both stepping aside — repeatedly.

### 5. ABA Problem
Agent reads value A, another agent changes A→B→A, first agent reads A again
and assumes nothing changed — but the intermediate state B had side effects.

### 6. Signal/Interrupt Races
Signal handlers that modify shared state can run between any two instructions
in the main thread.

---

## Multi-Agent File Write Scenarios

```
T=0  Agent A: read workspace/plan.md  → "Step 1: ..."
T=1  Agent B: read workspace/plan.md  → "Step 1: ..."
T=2  Agent A: write "Step 1 complete\nStep 2: ..."
T=3  Agent B: write "Step 1 complete\nStep 3: ..."
                                        ^^ Agent A's Step 2 is gone
```

This is exactly the race that happens when multiple Claude Code sessions
operate on the same project directory without coordination.

---

## Files in This Module

| File | Topic |
|------|-------|
| `01_race_conditions.py` | Read-modify-write, ABA, signal races |
| `02_multi_agent_workspace.py` | Agent-vs-agent file conflicts |
| `03_deadlocks.py` | Deadlock creation and detection |
| `04_atomicity.py` | What's actually atomic in Python? |
| `05_secure_patterns.py` | Safe patterns for concurrent agent code |
| `exercises.py` | Practice problems |

---

## Interview Talking Points

- "TOCTOU is especially dangerous in agentic systems because agents have broad
  filesystem access and operate at high speed — the race window is small but the
  blast radius is large."

- "The GIL does NOT protect you from race conditions in Python. `+=` on a list
  counter is still a race when threads hold the GIL on different bytecode lines."

- "For multi-agent coordination, the safest primitive is an atomic filesystem
  operation (rename, link) or a proper lock server — not application-level checks."

- "Signal handlers in Python run between arbitrary Python bytecodes, making any
  shared mutable state in a signal handler a race condition."
