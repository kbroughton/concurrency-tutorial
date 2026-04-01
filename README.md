# Python Concurrency for Security Engineers
### Anthropic Interview Prep

A hands-on tutorial covering Python concurrency through a security lens.
Built around real patterns from the Claude Code codebase and adversarial threat models.

---

## Modules

| Module | Topic | Key Skills |
|--------|-------|-----------|
| [Module 1](module1_claude_code_analysis/) | Concurrency in Claude Code | Async patterns, race condition auditing |
| [Module 2](module2_concurrency_security/) | Concurrency as an Attack Surface | TOCTOU, deadlocks, multi-agent races |
| [Module 3](module3_adversarial_search/) | Adversarial Web Search Injection | Threat modeling, prompt injection, defense |
| [Module 4](module4_concurrency_primitives/) | Build Your Own Concurrency Library | CPython internals, event loops, coroutines |

## How to Use

Work through modules in order. Each module contains:
- `README.md` — concept overview and interview talking points
- Numbered Python files — runnable demonstrations with inline commentary
- `exercises.py` — problems to solve independently (solutions in `exercises_solutions.py`)

```bash
# Run any demo directly
python module1_claude_code_analysis/02_race_condition_demo.py

# Check your exercise solutions
python module4_concurrency_primitives/exercises.py
```

## Prerequisites

- Python 3.11+
- No external dependencies (stdlib only) except where noted
- Familiarity with basic Python; no prior concurrency knowledge required

## Interview Focus Areas

1. **GIL awareness** — when threads help, when they don't, and why
2. **Race condition identification** — spotting TOCTOU and atomicity violations in code review
3. **Async vs threaded I/O** — tradeoffs for security tooling
4. **Subprocess isolation** — why hooks/agents run in separate processes
5. **Threat modeling concurrent systems** — how concurrency creates security surface area
