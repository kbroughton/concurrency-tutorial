# Interview Questions: Python Concurrency for Security Engineers

Questions are grouped by level. Each entry has:
- **The question** — what you'll be asked
- **What's being tested** — the interviewer's real goal
- **Strong answer** — key points a good answer hits
- **Trap / common mistake** — what trips candidates up

---

## Beginner

---

**B1. What is the GIL, and what does it actually protect?**

*What's being tested:* Whether you understand the difference between "thread-safe" and "correct."

*Strong answer:*
The GIL (Global Interpreter Lock) is a mutex in CPython that ensures only one thread executes Python bytecode at a time. It exists primarily to protect CPython's reference counting — incrementing and decrementing `ob_refcnt` is not atomic at the hardware level, so without the GIL two threads could corrupt an object's reference count and cause a use-after-free. It also makes non-thread-safe C extensions safe by default.

What it does *not* do: protect application-level invariants. `counter += 1` is still a race condition because it compiles to three bytecodes (LOAD, ADD, STORE) and the GIL can be released between any two of them.

*Trap:* Saying "the GIL makes Python threads safe." It makes the interpreter safe, not your code.

---

**B2. What's the difference between `threading`, `multiprocessing`, and `asyncio`? When would you use each?**

*What's being tested:* Understanding the CPU-bound vs I/O-bound distinction and the GIL's practical impact.

*Strong answer:*

| | threading | multiprocessing | asyncio |
|---|---|---|---|
| Parallelism | No (GIL) | Yes (separate processes) | No (single thread) |
| Best for | I/O-bound tasks | CPU-bound tasks | High-concurrency I/O |
| Overhead | Low (~10µs) | High (~50ms, IPC cost) | Very low |
| Shared state | Yes (with locks) | No (need Queue/Pipe) | Yes (no locks needed) |

Use `threading` for I/O-bound work where you need shared state (e.g., a web scraper with a shared results list). Use `multiprocessing` for CPU-bound work that needs true parallelism (e.g., hashing a million files). Use `asyncio` for high-concurrency I/O where you control the code (e.g., an async web server or agent tool runner).

*Trap:* Saying asyncio is faster than threading. For a small number of tasks, threading is often simpler and comparably fast. asyncio shines at scale (thousands of concurrent connections).

---

**B3. What is a race condition? Give a concrete Python example.**

*What's being tested:* Can you identify one in code, not just define it.

*Strong answer:*
A race condition occurs when the correctness of a program depends on the relative timing or ordering of operations by two or more threads, and that ordering is not enforced.

```python
# Two threads both do this:
count = shared_counter["value"]   # read
count += 1                         # modify
shared_counter["value"] = count   # write

# Thread A reads 5, Thread B reads 5, both write 6 → lost update
# Expected: 7. Actual: 6.
```

A real-world example: two Claude Code sessions simultaneously reading and writing `~/.claude/security_warnings_state.json`. Both read the current warning count, both increment it, both write back — one update is lost silently.

*Trap:* Giving a toy example but not explaining the consequences. Show you understand what breaks.

---

**B4. What are the four Coffman conditions for deadlock?**

*What's being tested:* Can you apply the conditions to reason about whether a system can deadlock.

*Strong answer:*
1. **Mutual exclusion** — at least one resource is non-shareable (only one thread can hold it)
2. **Hold and wait** — a thread holds one resource while waiting for another
3. **No preemption** — resources are released only voluntarily
4. **Circular wait** — a circular chain of threads each waiting for the next

All four must hold simultaneously for deadlock. Break *any one* to prevent it:
- Break circular wait → always acquire locks in a consistent global order
- Break hold and wait → use non-blocking `acquire(timeout=0)` with rollback
- Break no preemption → design for lock cancellation (asyncio `CancelScope`)

*Trap:* Listing the conditions but not knowing how to break them. The practical fix is always the interesting part.

---

**B5. What does `await` actually do at the Python level?**

*What's being tested:* Do you know the generator protocol underneath async/await.

*Strong answer:*
`await expr` is syntactic sugar for `yield from expr.__await__()`. The `__await__` method returns an iterator. When the coroutine hits an `await`, it yields a value (usually a `Future` object) to the event loop, suspending execution. The event loop registers a callback on that future; when the future resolves (I/O ready, timer expired), the coroutine is rescheduled and `send(result)` is called to resume it past the `await` point.

So `await asyncio.sleep(1.0)` ultimately:
1. Creates a Future, schedules a timer callback for 1s
2. Yields the Future to the event loop
3. Event loop runs other coroutines for 1s
4. Timer fires → `future.set_result(None)` → coroutine is re-queued
5. Event loop calls `coro.send(None)` → coroutine resumes

*Trap:* Saying "await pauses the coroutine." It does, but the precise mechanism — `yield from` + generator protocol + event loop scheduling — is what the question is probing.

---

## Intermediate

---

**I1. Why is `counter += 1` not thread-safe even though CPython has the GIL?**

*What's being tested:* Deep understanding of when the GIL is released.

*Strong answer:*
`counter += 1` compiles to three bytecodes:
```
LOAD_FAST   counter     # read value
LOAD_CONST  1
INPLACE_ADD             # compute new value
STORE_FAST  counter     # write new value  ← GIL can be released AFTER this
```
The GIL is released every `sys.getswitchinterval()` seconds (default 5ms), which can happen between any two bytecodes. Thread A can LOAD the value (5), get preempted, Thread B runs its full `+= 1` cycle (reads 5, writes 6), Thread A resumes and writes 6 again — lost update.

Additionally, Python 3.2+ uses a "new GIL" based on a condition variable, not a simple timer, which means the GIL can be requested and granted between any bytecode boundary, not just on a fixed interval.

*Trap:* Thinking `list.append()` has the same problem. It doesn't — `list.append` is a single C-level operation that holds the GIL throughout. But don't rely on this in production code; it's an implementation detail that PEP 703 (free-threaded CPython) could break.

---

**I2. What is TOCTOU? Give an example in an agent context and explain the fix.**

*What's being tested:* Security reasoning about filesystem races, applied to real systems.

*Strong answer:*
TOCTOU (Time-of-Check / Time-of-Use) is a class of race condition where a security-relevant check happens at time T1 and the protected action at T2, but the condition checked at T1 can change between T1 and T2.

Agent example:
```python
# VULNERABLE
if config_path.exists() and config_path.is_file():  # T1: check
    # attacker replaces config_path with symlink to /etc/passwd
    with open(config_path) as f:                     # T2: use
        config = json.load(f)
```

Fix — open first, ask questions after:
```python
# SAFE
fd = os.open(str(config_path), os.O_RDONLY | os.O_NOFOLLOW)  # refuses symlinks
with os.fdopen(fd) as f:
    config = json.load(f)
```
`O_NOFOLLOW` raises `OSError` if the path is a symlink at open time, eliminating the window entirely.

In an agent context this matters because agents have broad filesystem access and operate at machine speed — the race window is microseconds, but with thousands of operations per second, it's reliably exploitable.

*Trap:* Only describing the attack without the fix, or not knowing `O_NOFOLLOW` exists.

---

**I3. Explain `asyncio.gather()` vs `asyncio.wait()`. When would you use each?**

*What's being tested:* Practical async API knowledge and understanding of failure handling.

*Strong answer:*
Both run multiple coroutines concurrently, but they differ in how they handle completion and errors:

`gather(*coros, return_exceptions=False)`:
- Returns results in the same order as inputs (not completion order)
- By default, cancels all tasks on the first exception
- With `return_exceptions=True`, exceptions are returned as values instead of raised
- Simpler; use when you need all results and consistent ordering

`wait(tasks, return_when=...)`:
- Returns two sets: `done` and `pending`
- `return_when` controls when it returns: `FIRST_COMPLETED`, `FIRST_EXCEPTION`, `ALL_COMPLETED`
- Does not cancel remaining tasks automatically
- Use when you want to process results as they arrive, or stop on first success

Security relevance: in a parallel web fetch pipeline, `gather` with `return_exceptions=True` means a malicious slow response can arrive last and its exception won't stop processing of earlier results — you must re-validate the assembled output regardless.

---

**I4. How does `fcntl.flock` work, and what are its limitations?**

*What's being tested:* Knowledge of cross-process synchronization on Unix.

*Strong answer:*
`fcntl.flock(fd, operation)` applies an advisory lock to an open file descriptor. `LOCK_EX` acquires an exclusive lock (one writer at a time); `LOCK_SH` acquires a shared lock (multiple readers); `LOCK_UN` releases. `LOCK_NB` makes the call non-blocking (raises `BlockingIOError` if the lock is held).

Key properties:
- **Advisory**: only processes that also call `flock` are protected. A process that ignores `flock` can still write.
- **Associated with the open file description** (not the fd number): if two fds refer to the same open file (via `dup`), they share the lock. This means `flock` on a lock file works correctly across processes.
- **Automatically released** when the fd is closed or the process dies — no stale lock.
- **Not inherited across `fork`** in the way you might expect: child gets a copy of the fd, which shares the lock with the parent.

Limitations:
- Not available on Windows (use `msvcrt.locking` or the `filelock` package)
- Network filesystems (NFS, CIFS) may not honor `flock` reliably
- Does not prevent the same process from deadlocking itself on a non-reentrant lock

---

**I5. What concurrency risks arise when multiple AI agents share a workspace directory?**

*What's being tested:* Applied threat modeling — taking concurrency primitives and applying them to a real AI system architecture.

*Strong answer:*
Three primary classes:

1. **Lost updates on shared files**: Agent A reads `plan.md`, Agent B reads `plan.md`, both append different content and write back — one agent's changes overwrite the other's. Fix: optimistic concurrency control (hash-based version check + atomic rename) or serialized access via a workspace lock.

2. **Torn reads**: Agent B reads a large JSON state file while Agent A is mid-write. Agent B sees partial JSON, fails to parse, or worse, processes inconsistent intermediate state. Fix: write-to-temp + `os.rename()` (atomic on POSIX), so readers always see a complete file.

3. **Causal ordering violations in audit logs**: Two agents write to a shared log concurrently. The log shows entries in arrival order, which may not match causal order — Agent B's action that *depends on* Agent A's result might appear first. Fix: Lamport timestamps. Each entry includes `max(local_clock, received_clock) + 1`, guaranteeing causal ordering when sorted.

The deeper issue: agents have no built-in coordination protocol. They're designed to operate independently. Concurrent operation on shared state requires explicit synchronization that agent frameworks don't currently provide by default.

---

**I6. What's the difference between `threading.Lock` and `asyncio.Lock`, and can you use them interchangeably?**

*What's being tested:* Understanding the threading model difference between thread-based and cooperative concurrency.

*Strong answer:*
`threading.Lock` blocks the OS thread. When a thread calls `acquire()` and the lock is held, the thread is descheduled by the OS — it cannot run at all until the lock is released. This is correct for multi-threaded code.

`asyncio.Lock` suspends the coroutine, not the thread. When a coroutine `await`s `acquire()` and the lock is held, it yields control back to the event loop, which can run other coroutines on the same thread. The OS thread continues running.

They are **not interchangeable**:
- Using `threading.Lock` in an async context and calling `.acquire()` (blocking) will block the *entire event loop thread* — no other coroutines can run. This is a common bug.
- Using `asyncio.Lock` in a multi-threaded context provides no protection, because two threads can both be "in" the event loop concurrently if you're mixing threading and asyncio.

The rule: if you're inside `async def`, use `asyncio` synchronization primitives. If you're in regular threads, use `threading` primitives. Never mix without explicit bridging (`loop.call_soon_threadsafe`, `asyncio.run_coroutine_threadsafe`).

---

## Advanced

---

**A1. You're reviewing a PR that adds parallel web fetching to an agent. The author validates each fetch result individually before adding it to the context. What's wrong, and how do you fix it?**

*What's being tested:* Security-oriented code review — spotting the race between per-chunk validation and assembled-context use.

*Strong answer:*
The vulnerability is a **validation gap at the assembly boundary**. Per-chunk validation checks individual results in isolation, but the assembled context is never re-validated as a whole. An attacker can:

1. Serve clean content to the fast requests (which pass per-chunk validation)
2. Serve malicious content (prompt injection payload) to a slow request that arrives after the "all-chunks-validated" checkpoint
3. The malicious chunk is appended to an already-"validated" context without re-checking

Fix — two-phase architecture:
```python
# Phase 1: fetch ALL concurrently
results = await asyncio.gather(*[fetch(url) for url in urls],
                                return_exceptions=True)

# Phase 2: validate ALL individually, filter failures
clean = [r for r in results if not isinstance(r, Exception)
         and passes_injection_check(r)]

# Phase 3: assemble and RE-VALIDATE the full context
assembled = assemble_context(clean)
if not passes_injection_check(assembled):   # ← the missing step
    raise SecurityError("Injection detected in assembled context")
```

The additional fix: set a strict fetch timeout and drop late arrivals entirely — don't process results that exceed a deadline, since delay is itself a signal that something unusual is happening.

---

**A2. Design a safe, concurrent state store for autonomous agents sharing a workspace. State can include task assignments, file ownership, and progress. Multiple agents read and write concurrently.**

*What's being tested:* System design under concurrency constraints; understanding of isolation levels.

*Strong answer:*
Use SQLite with WAL mode. It's the right tool for this problem:

```python
# Schema
CREATE TABLE agent_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    version    INTEGER NOT NULL DEFAULT 1,
    agent_id   TEXT,
    updated_at REAL DEFAULT (unixepoch('now', 'subsec'))
);
```

WAL mode (`PRAGMA journal_mode=WAL`) allows concurrent readers while a writer is active — reads never block writes, and writes never block reads (only block other writers).

For optimistic concurrency control, use version columns:
```sql
UPDATE agent_state
SET value = ?, version = version + 1, agent_id = ?
WHERE key = ? AND version = ?   -- fails if someone else wrote first
```
If `rowcount == 0`, another agent updated first — re-read and retry.

For the file ownership use case specifically, add:
```sql
-- Claim a file atomically (INSERT OR IGNORE)
INSERT OR IGNORE INTO file_locks (path, agent_id, claimed_at)
VALUES (?, ?, unixepoch());
-- Returns rowcount=0 if already claimed
```
`INSERT OR IGNORE` is atomic at the SQLite level — no external lock needed.

Trade-off I'd flag: SQLite is single-writer. For extremely high write throughput across many agents, you'd want a proper database (PostgreSQL with `FOR UPDATE SKIP LOCKED` for work queue patterns). But for a developer workstation with 2-5 agents, SQLite WAL is the right call — it avoids a server dependency and handles crashes gracefully.

---

**A3. Walk me through implementing `asyncio.Lock` from scratch using only generators and a scheduler. No `asyncio` imports.**

*What's being tested:* Deep primitives knowledge — do you understand what asyncio actually does.

*Strong answer:*
An `asyncio.Lock` needs two things: a flag (locked/unlocked) and a queue of waiters. Each waiter is a Future — when the lock is released, the first waiter's Future is resolved, re-scheduling that coroutine.

Without asyncio, we replace `Future` with a simple flag and use cooperative yielding:

```python
import collections

class CoopLock:
    def __init__(self):
        self._locked = False
        self._waiters = collections.deque()  # deque of [resolved_flag]

    def acquire(self):
        """Generator: yields until lock is acquired."""
        while self._locked:
            flag = [False]
            self._waiters.append(flag)
            while not flag[0]:
                yield  # give control back to scheduler
        self._locked = True

    def release(self):
        self._locked = False
        if self._waiters:
            self._waiters.popleft()[0] = True  # wake next waiter
```

The scheduler calls `next(coro)` to advance coroutines. A coroutine inside `acquire()` yields `None` each iteration until its flag is set by `release()`, at which point it exits the loop and the caller holds the lock.

This is exactly what asyncio does, replacing our flag with `asyncio.Future` and the scheduler's `next()` call with the event loop's `Task.__step()`. The `yield` in our implementation is the `yield self` in `Future.__await__()`.

The key insight: a lock is just a flag plus a notification mechanism. The notification mechanism in asyncio is `future.set_result()` → callback → task re-queued in event loop. In our version it's a shared mutable flag polled on each scheduler tick.

---

**A4. An autonomous agent mode (like a KAIROS-style task runner) is being designed. What concurrency and safety properties must the system enforce, and how?**

*What's being tested:* Synthesis — applying all the concurrency security concepts to a real product problem.

*Strong answer:*
Six properties, each requiring an explicit implementation:

**1. Permission atomicity**: The agent must hold a permission grant for the entire duration of an action, not just check-then-act. Race: permission is revoked between check and execution. Fix: a context manager that locks the permission state for the action's duration, with a version counter to detect ABA (permission revoked and re-granted with different scope).

**2. Memory snapshot isolation**: When an agent reads its working memory to make a decision, it must act on a consistent snapshot. Fix: version-numbered reads + conditional writes (`WHERE version = expected`). If the write fails, the decision is stale — re-read and reconsider.

**3. Cooperative cancellation**: A kill switch must fire at defined safe points, not at arbitrary bytecodes. Fix: `CancellationToken.check()` called at the start and end of each action. This guarantees state is always consistent when the agent stops — no half-executed actions.

**4. Causally ordered audit**: Concurrent agents writing to a shared audit log must produce a log that accurately reflects causal order, not arrival order. Fix: Lamport timestamps on every entry. Post-incident forensics is only meaningful if the log is causally consistent.

**5. Circuit breaker**: An autonomous agent that encounters errors must self-throttle, not compound damage. Fix: circuit breaker with failure threshold; after N consecutive failures the agent halts and requires human re-authorization before continuing.

**6. Reversibility budget**: Autonomous authorization is implicitly bounded. An agent authorized to "deploy a feature" is not authorized to delete 50 files, send 20 emails, and drop a database table — even if each individual action seems necessary. Fix: explicit reversibility budget with a hard cap on irreversible actions per authorization, enforced with a mutex so concurrent sub-agents can't each consume the full budget.

The meta-point: these aren't nice-to-haves — they're the difference between an autonomous agent that can be trusted and one that can't. Each corresponds to a specific failure mode that has happened in real systems.

---

**A5. You discover that `ANTHROPIC_API_KEY` is the only major cloud credential with no server-side downscoping mechanism. Design a scoped API key system for Anthropic's platform.**

*What's being tested:* Product security thinking — identifying a gap and designing a solution that works within real API constraints.

*Strong answer:*
The model is AWS IAM scoped credentials or GitHub fine-grained PATs. A scoped Anthropic key would have:

**Scope dimensions:**
- `models`: allowlist of model IDs (`claude-opus-4-6`, `claude-haiku-4-5`, not `claude-opus-4-6`)
- `max_tokens_per_request`: hard cap per API call
- `daily_spend_limit_usd`: rate limit by cost
- `allowed_system_prompts`: hash-allowlist of permitted system prompts (prevents using a dev key for jailbreak attempts)
- `ip_allowlist`: CIDR ranges permitted to use this key
- `expiry`: short-lived tokens (1h for CI, 30d for developers)

**Implementation at Anthropic's API gateway:**
1. Key is a JWT signed by Anthropic, containing scope claims
2. Gateway validates signature and enforces scope before routing to model
3. Parent key can create child keys with equal or lesser scope (delegation)
4. Child key cannot escalate beyond parent's scope

**Why this matters for supply chain attacks specifically:**
If a malicious postinstall script exfiltrates `ANTHROPIC_API_KEY`, the attacker has:
- Full API access on the developer's billing account
- Ability to probe Anthropic's models at the developer's cost
- Access to potentially sensitive conversation data

With a scoped key for Claude CLI usage:
- Attacker gets a key that can only call the models the developer uses, within their daily budget, from their IP range
- Cannot be used to exfiltrate historical conversations
- Cannot be used for bulk inference on the attacker's behalf
- Auto-expires, limiting the window of abuse

The right ask: "Anthropic should offer short-lived, scoped tokens via an STS-equivalent endpoint, with the master API key stored in a secrets manager and never in the environment."

---

## Rapid-Fire (for closing minutes of interview)

- What's the switch interval in Python's GIL, and what triggers an early switch? *(5ms default; blocked I/O, explicit `Py_BEGIN_ALLOW_THREADS`, signals)*
- What does `os.rename()` guarantee that `shutil.copy()` + `os.remove()` does not? *(Atomicity — rename is a single syscall)*
- Name three operations that are atomic in CPython but not in free-threaded Python. *(`list.append`, `dict[k]=v`, reference assignment — all rely on GIL for atomicity)*
- What does `select.epoll` give you that `select.select` doesn't? *(No 1024 fd limit, O(1) ready notification vs O(n) scanning)*
- In a Lamport clock, if event A causally precedes B, what's the relationship between their timestamps? *(ts(A) < ts(B), but the converse is not necessarily true)*
- What's the difference between a livelock and a deadlock? *(Deadlock: no progress, threads blocked. Livelock: no progress, threads actively running — e.g., two threads each detect a conflict and both back off simultaneously, repeatedly)*
- Why is `yaml.safe_load()` important and what does `yaml.load()` allow? *(`yaml.load` with untrusted input allows arbitrary Python object construction, including `!!python/object/apply:os.system` — RCE)*
- What is the self-pipe trick and why do signal handlers use it? *(Write one byte to a non-blocking pipe in the signal handler; the event loop watches the read end. Signal handlers can only safely do async-signal-safe operations; writing to a pipe is one of them)*
