# Module 1: Concurrency in Claude Code

## What We're Studying

Claude Code (github.com/anthropics/claude-code) is primarily a TypeScript CLI, but it ships
Python hooks for pre/post tool-use events, security reminders, and rule evaluation.

The public repo reveals a **sequential-first architecture** — most operations block, most
loops process one item at a time. This is a deliberate choice (simpler, safer) but creates
measurable opportunities and a few real vulnerabilities when multiple sessions run concurrently.

---

## Architecture Overview

```
User Terminal
     │
     ▼
Claude Code CLI (TypeScript / Node.js)
     │
     ├── Tool execution (BashTool, ReadTool, WriteTool …)
     │        └── Each tool → subprocess or fs call
     │
     └── Hook pipeline (Python subprocesses)
              ├── PreToolUse hook  ─┐
              ├── PostToolUse hook  ├─ JSON stdin/stdout, sequential
              ├── Stop hook        ─┘
              └── UserPromptSubmit hook
```

**Key insight for interviews**: The hook system runs Python as isolated subprocesses.
This buys process-level isolation (memory safety, crash containment) at the cost of
no shared in-process state and higher spawn overhead.

---

## Concurrency Patterns Found

### What's there
- `@lru_cache` on regex compilation (memoization, thread-safe)
- Async/await in TypeScript automation scripts (but used sequentially!)
- Subprocess isolation for hooks (process-level concurrency boundary)

### What's missing (and why it matters)
- No file locks on shared state files (`~/.claude/security_warnings_state_*.json`)
- No async I/O in Python hooks (blocking reads/writes throughout)
- No parallel hook execution (pipeline is strictly sequential)
- No timeout guards on blocking I/O

---

## The Real Vulnerability: State File Races

The security reminder hook writes session state to:
```
~/.claude/security_warnings_state_{session_id}.json
```

When two Claude Code sessions run simultaneously (common in tmux/multi-terminal
workflows), both can:
1. Read the file (check-then-act)
2. Compute new state
3. Write back — **last writer wins, silently dropping the other's update**

This is a classic **read-modify-write race condition** on the filesystem.

---

## Interview Talking Points

- "The hook system trades in-process shared state for process isolation — a sound
  security decision, but it means coordination requires IPC or filesystem, both of
  which need their own synchronization."

- "I noticed the state files use no locking. On Linux you'd use `fcntl.flock()`;
  on cross-platform you'd use `filelock` or write-then-rename atomic patterns."

- "The TypeScript automation code uses `async/await` sequentially within a session.
  In practice, users get process-level parallelism by running separate Claude Code
  sessions across different repos simultaneously — each is an independent OS process
  with its own V8 heap and event loop. This is architecturally sounder than
  in-process `Promise.all()` for isolation, but still shares API rate limits and
  hits the state file race condition described above."

- "`Promise.all()` would speed up per-issue API calls within a session, but it
  carries its own security trade-offs: unbounded fan-out can exhaust GitHub rate
  limits and trigger abuse detection; partial success leaves state inconsistent
  with no transactional rollback; and results arriving simultaneously remove the
  natural checkpoint between fetch and context assembly — amplifying the prompt
  injection window covered in Module 3. `Promise.allSettled()` with a concurrency
  limiter (e.g. `p-limit(5)`) is the safer formulation."

---

## Files in This Module

| File | What It Demonstrates |
|------|---------------------|
| `01_overview.py` | Architecture walkthrough, hook lifecycle |
| `02_race_condition_demo.py` | Reproduces the state-file race with threads |
| `03_fixing_races.py` | Three fix strategies: flock, atomic rename, sqlite |
| `04_hook_isolation.py` | Subprocess isolation pattern, stdin/stdout JSON |
| `exercises.py` | Practice problems |
