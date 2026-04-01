"""
Module 2, File 4: Autonomous Agent Safety Patterns
===================================================

When an agent moves from "human approves each step" to "autonomous multi-step
execution," the concurrency threat model changes fundamentally.

In interactive mode: a human reviews each tool call — races affect individual ops.
In autonomous mode: the agent chains N actions without human checkpoints — a race
in step 3 can corrupt state that every subsequent step builds on.

This file covers:
  1. The autonomous threat model — what's new vs. interactive mode
  2. Permission state races — TOCTOU on capability checks
  3. Memory consistency — atomic read-decide-act for long-running agents
  4. Cooperative cancellation — safe kill switches
  5. Causally ordered audit logs — detecting and preventing concurrent corruption
  6. Circuit breakers — stopping cascading autonomous failures
  7. Reversibility budget — preferring undoable actions under concurrency

Interview context: An "autonomous agent mode" means these patterns aren't
theoretical — they're the difference between a useful agent and a dangerous one.
"""

import threading
import time
import json
import hashlib
import heapq
import collections
import fcntl
import tempfile
import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Callable, Any


# ---------------------------------------------------------------------------
# 1. The Autonomous Agent Threat Model
# ---------------------------------------------------------------------------

def explain_threat_model():
    print("=" * 60)
    print("Autonomous Agent Threat Model")
    print("=" * 60)
    print("""
  Interactive mode (human in the loop):
    User → [approve] → Tool_1 → [approve] → Tool_2 → [approve] → Tool_3
    Race window: small (bounded by human review latency)
    Blast radius: single approved action

  Autonomous mode (KAIROS-like):
    User → [approve start] → Tool_1 → Tool_2 → ... → Tool_N → [report]
    Race window: entire task duration (minutes to hours)
    Blast radius: all N actions, including actions that depend on prior state

  New threat classes in autonomous mode:
  ─────────────────────────────────────────────────────────────────────
  1. Permission drift  — agent acquires/loses permissions mid-task;
                         decisions made before drift are stale
  2. Memory staleness  — agent's working memory diverges from world state
  3. Action entanglement — two concurrent sub-agents take individually-safe
                          actions that are unsafe in combination
  4. Audit gaps        — concurrent writes to audit log lose causal ordering
  5. Runaway execution — an error triggers more actions, not fewer
  6. Irreversible cascade — autonomous agent chains irreversible actions;
                           stopping it halfway leaves worse state than
                           never starting

  For each: we need a programming pattern, not just a policy.
    """)


# ---------------------------------------------------------------------------
# 2. Permission State Race — TOCTOU on Capability
# ---------------------------------------------------------------------------

class Permission(Enum):
    READ        = auto()
    WRITE       = auto()
    EXECUTE     = auto()
    NETWORK     = auto()
    ELEVATED    = auto()


@dataclass
class PermissionSet:
    granted: set[Permission] = field(default_factory=set)
    version: int = 0  # monotonic counter — used to detect mid-task revocation


class VulnerablePermissionCheck:
    """
    Dangerous pattern: check permission, then act.
    If permissions are revoked between check and act, the action runs anyway.
    """

    def __init__(self, perms: PermissionSet):
        self._perms = perms

    def write_file(self, path: str, content: str) -> bool:
        # TIME-OF-CHECK
        if Permission.WRITE not in self._perms.granted:
            return False
        # ← RACE: another agent or the user revokes WRITE here
        # TIME-OF-USE
        print(f"  [agent] writing to {path} (may be unauthorized!)")
        return True


class SafePermissionCheck:
    """
    Safe pattern: check permission AND version atomically, then act.
    If anything changes between check and act, abort.
    Uses a lock to make check-then-act a single atomic operation.
    """

    def __init__(self, perms: PermissionSet):
        self._perms = perms
        self._lock = threading.Lock()

    def revoke(self, perm: Permission) -> None:
        with self._lock:
            self._perms.granted.discard(perm)
            self._perms.version += 1  # increment version on any change

    def grant(self, perm: Permission) -> None:
        with self._lock:
            self._perms.granted.add(perm)
            self._perms.version += 1

    @contextmanager
    def require(self, *permissions: Permission):
        """
        Context manager that holds the permission lock for the entire operation.
        Prevents permission changes from racing with the action.
        """
        with self._lock:
            missing = [p for p in permissions if p not in self._perms.granted]
            if missing:
                raise PermissionError(f"Missing permissions: {[p.name for p in missing]}")
            yield self._perms.version
            # Re-check version on exit — if it changed, permissions may have been
            # revoked and re-granted (ABA problem on permissions)

    def write_file(self, path: str, content: str) -> bool:
        with self.require(Permission.WRITE):
            print(f"  [agent] safely writing to {path} (permission held throughout)")
            return True


def demo_permission_race():
    print("\n" + "=" * 60)
    print("Permission State Race Demo")
    print("=" * 60)

    perms = PermissionSet(granted={Permission.WRITE, Permission.READ})
    safe = SafePermissionCheck(perms)

    revoke_happened = [False]

    def permission_revoker():
        """Simulates the user revoking write permission mid-task."""
        time.sleep(0.01)
        safe.revoke(Permission.WRITE)
        revoke_happened[0] = True
        print("  [user] WRITE permission revoked!")

    # Long-running operation that holds the permission lock
    def autonomous_write():
        try:
            with safe.require(Permission.WRITE):
                print("  [agent] acquired WRITE permission, starting long write...")
                time.sleep(0.05)  # simulate slow disk write
                # Revocation attempt during this block will wait for us to finish
                print("  [agent] write complete")
        except PermissionError as e:
            print(f"  [agent] blocked: {e}")

    revoker = threading.Thread(target=permission_revoker)
    writer = threading.Thread(target=autonomous_write)

    writer.start()
    revoker.start()
    writer.join()
    revoker.join()

    print(f"\n  Revoke happened: {revoke_happened[0]}")
    print("  Outcome: write either completes fully or is blocked before starting")
    print("  (No partial-permission execution possible)")


# ---------------------------------------------------------------------------
# 3. Memory Consistency — Read-Decide-Act Atomicity
# ---------------------------------------------------------------------------

class AgentMemory:
    """
    An agent's working memory store with snapshot isolation.

    The core invariant: when an agent reads memory to make a decision,
    it should act on a consistent snapshot — not a mix of before/after
    states from concurrent updates.

    This is the same problem as database transaction isolation.
    We implement MVCC (Multi-Version Concurrency Control) lite.
    """

    def __init__(self):
        self._store: dict[str, tuple[Any, int]] = {}  # key → (value, version)
        self._global_version = 0
        self._lock = threading.Lock()

    def write(self, key: str, value: Any) -> int:
        with self._lock:
            self._global_version += 1
            self._store[key] = (value, self._global_version)
            return self._global_version

    def read(self, key: str) -> tuple[Any, int]:
        with self._lock:
            return self._store.get(key, (None, 0))

    def snapshot(self) -> tuple[dict, int]:
        """Read all memory as a consistent snapshot at a point in time."""
        with self._lock:
            version = self._global_version
            data = {k: v for k, (v, _) in self._store.items()}
            return data, version

    def conditional_write(self, key: str, value: Any, expected_version: int) -> bool:
        """
        Write only if the global version hasn't changed since we read.
        This is optimistic concurrency control for agent memory.
        """
        with self._lock:
            if self._global_version != expected_version:
                return False  # Memory changed — our decision may be stale
            self._global_version += 1
            self._store[key] = (value, self._global_version)
            return True


def demo_memory_consistency():
    print("\n" + "=" * 60)
    print("Agent Memory: Read-Decide-Act with Snapshot Isolation")
    print("=" * 60)

    memory = AgentMemory()
    memory.write("task_status", "pending")
    memory.write("file_count", 0)

    conflict_count = [0]
    success_count = [0]

    def autonomous_agent(agent_id: str):
        """Agent reads memory, makes a decision, writes result."""
        for attempt in range(10):
            # Read consistent snapshot
            snapshot, version = memory.snapshot()
            status = snapshot.get("task_status")
            count = snapshot.get("file_count", 0)

            if status != "pending":
                break

            # Simulate decision-making based on snapshot
            time.sleep(0.005)

            # Write result — only succeeds if memory hasn't changed
            new_count = count + 1
            if memory.conditional_write("file_count", new_count, version):
                success_count[0] += 1
                if new_count >= 5:
                    memory.write("task_status", "complete")
                break
            else:
                conflict_count[0] += 1
                # Memory changed — retry with fresh snapshot

    agents = [threading.Thread(target=autonomous_agent, args=(f"Agent_{i}",))
              for i in range(4)]
    for a in agents: a.start()
    for a in agents: a.join()

    final_snapshot, _ = memory.snapshot()
    print(f"\n  Final file_count: {final_snapshot['file_count']}")
    print(f"  Final status:     {final_snapshot['task_status']}")
    print(f"  Successful writes: {success_count[0]}")
    print(f"  Conflicts (retried): {conflict_count[0]}")
    print("  Consistency: each agent acted on a valid snapshot, no phantom reads")


# ---------------------------------------------------------------------------
# 4. Cooperative Cancellation — Safe Kill Switch
# ---------------------------------------------------------------------------

class CancellationToken:
    """
    A token passed to autonomous task chains.
    Any step can check is_cancelled() and abort cleanly.

    This is equivalent to asyncio's CancelScope / Task.cancel(),
    but explicit — the agent checks at defined safe points rather
    than receiving an async exception at any await.

    Why explicit is safer for autonomous agents:
    - The agent controls WHEN cancellation takes effect
    - Cancellation only fires at "safe points" where state is consistent
    - Cleanup code always runs (no exception interleaving)
    """

    def __init__(self):
        self._cancelled = threading.Event()
        self._cancel_reason = ""
        self._lock = threading.Lock()

    def cancel(self, reason: str = "user requested") -> None:
        with self._lock:
            self._cancel_reason = reason
        self._cancelled.set()
        print(f"  [killswitch] cancellation requested: {reason}")

    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()

    def check(self) -> None:
        """Call at safe points. Raises if cancelled."""
        if self._cancelled.is_set():
            raise InterruptedError(f"Task cancelled: {self._cancel_reason}")

    @property
    def reason(self) -> str:
        return self._cancel_reason


def autonomous_task_chain(token: CancellationToken, steps: list[str]) -> list[str]:
    """
    A multi-step autonomous task that respects cancellation.
    Each step is a 'safe point' — if cancelled here, state is consistent.
    """
    completed = []
    for step in steps:
        # Check at the START of each step (safe point)
        token.check()

        print(f"  [agent] executing: {step}")
        time.sleep(0.05)  # simulate work

        # Simulate a side effect (file write, API call, etc.)
        completed.append(step)
        print(f"  [agent] completed: {step}")

        # Check AFTER completing (before moving to next step)
        # This ensures we don't start an action we can't finish
        token.check()

    return completed


def demo_cancellation():
    print("\n" + "=" * 60)
    print("Cooperative Cancellation (Safe Kill Switch)")
    print("=" * 60)

    token = CancellationToken()
    steps = [f"step_{i}" for i in range(8)]
    shared = {"result": [], "error": []}

    def run_task():
        try:
            shared["result"].extend(autonomous_task_chain(token, steps))
        except InterruptedError as e:
            shared["error"].append(str(e))
            print(f"  [agent] cleanly stopped: {e}")

    t = threading.Thread(target=run_task)
    t.start()

    # Cancel after 2 steps have run
    time.sleep(0.12)
    token.cancel("user pressed Ctrl+C")
    t.join()

    print(f"\n  Steps completed before cancel: {result}")
    print(f"  Cancelled at a safe point: {bool(error)}")
    print("  State is consistent — partial execution didn't leave corrupt state")


# ---------------------------------------------------------------------------
# 5. Causally Ordered Audit Log
# ---------------------------------------------------------------------------

class CausalAuditLog:
    """
    An audit log where each entry includes a Lamport timestamp,
    ensuring causal ordering even when entries arrive from concurrent agents.

    Problem without this: two agents write concurrently, the log shows
    entries in arrival order (wall-clock) not causal order. If Agent B's
    action causally depends on Agent A's, but B's entry arrives first,
    the log is misleading.

    Lamport clocks: each event gets max(local_clock, received_clock) + 1.
    This guarantees: if A → B (A happens before B causally), then ts(A) < ts(B).
    """

    def __init__(self, path: Path):
        self.path = path
        self._local_clock = 0
        self._lock = threading.Lock()
        self.path.write_text("")

    def _tick(self, received: int = 0) -> int:
        """Advance Lamport clock. Returns new timestamp."""
        with self._lock:
            self._local_clock = max(self._local_clock, received) + 1
            return self._local_clock

    def log(self, agent_id: str, action: str, causal_clock: int = 0) -> int:
        """
        Append an audit entry.
        causal_clock: the clock of the event this action causally follows.
        Returns the assigned Lamport timestamp.
        """
        ts = self._tick(causal_clock)
        entry = {
            "lamport_ts": ts,
            "wall_clock": time.time(),
            "agent": agent_id,
            "action": action,
        }
        # Atomic append via lock + line write (each line is one JSON entry)
        with self._lock:
            with open(self.path, "a") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()
        return ts

    def read_ordered(self) -> list[dict]:
        """Read log entries sorted by Lamport timestamp (causal order)."""
        entries = []
        for line in self.path.read_text().splitlines():
            if line.strip():
                entries.append(json.loads(line))
        return sorted(entries, key=lambda e: e["lamport_ts"])


def demo_audit_log():
    print("\n" + "=" * 60)
    print("Causally Ordered Audit Log")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as d:
        log = CausalAuditLog(Path(d) / "audit.jsonl")

        def agent_a():
            ts1 = log.log("Agent_A", "read_config")
            time.sleep(0.02)
            ts2 = log.log("Agent_A", "write_plan", causal_clock=ts1)
            time.sleep(0.01)
            log.log("Agent_A", "execute_plan", causal_clock=ts2)

        def agent_b():
            time.sleep(0.01)  # starts slightly after A
            ts1 = log.log("Agent_B", "read_plan")
            time.sleep(0.02)
            log.log("Agent_B", "validate_plan", causal_clock=ts1)

        threads = [threading.Thread(target=agent_a),
                   threading.Thread(target=agent_b)]
        for t in threads: t.start()
        for t in threads: t.join()

        ordered = log.read_ordered()
        print("\n  Audit log in causal order:")
        for entry in ordered:
            print(f"  [{entry['lamport_ts']:3d}] {entry['agent']:10s}: {entry['action']}")

        print("""
  Lamport timestamps guarantee: if A causally precedes B, ts(A) < ts(B).
  Even if B's write arrived at the log before A's, the sorted view is correct.
  This is critical for post-incident forensics on autonomous agent actions.
        """)


# ---------------------------------------------------------------------------
# 6. Circuit Breaker — Stop Cascading Autonomous Failures
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """
    Prevents an autonomous agent from compounding errors by executing more
    actions after a failure threshold is reached.

    States:
      CLOSED   → normal operation, requests pass through
      OPEN     → failure threshold hit, all requests rejected immediately
      HALF_OPEN → cooldown expired, testing with one request

    In autonomous agent context: if the agent's actions are failing
    (files not found, API errors, unexpected state), stop taking more
    actions before the damage compounds.
    """

    class State(Enum):
        CLOSED    = "CLOSED"
        OPEN      = "OPEN"
        HALF_OPEN = "HALF_OPEN"

    def __init__(self, failure_threshold: int = 3, cooldown_s: float = 1.0):
        self._state = self.State.CLOSED
        self._failures = 0
        self._threshold = failure_threshold
        self._cooldown_s = cooldown_s
        self._opened_at = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> 'CircuitBreaker.State':
        return self._state

    @contextmanager
    def call(self, action_name: str):
        """Wrap an agent action. Raises if circuit is open."""
        with self._lock:
            if self._state == self.State.OPEN:
                if time.monotonic() - self._opened_at > self._cooldown_s:
                    self._state = self.State.HALF_OPEN
                    print(f"  [circuit] HALF_OPEN — testing with: {action_name}")
                else:
                    raise RuntimeError(
                        f"Circuit OPEN — rejecting action '{action_name}' "
                        f"(cooldown: {self._cooldown_s - (time.monotonic()-self._opened_at):.1f}s remaining)"
                    )

        try:
            yield
            # Success
            with self._lock:
                self._failures = 0
                self._state = self.State.CLOSED
        except Exception:
            with self._lock:
                self._failures += 1
                print(f"  [circuit] failure {self._failures}/{self._threshold}")
                if self._failures >= self._threshold:
                    self._state = self.State.OPEN
                    self._opened_at = time.monotonic()
                    print(f"  [circuit] OPENED — autonomous execution halted")
            raise


def demo_circuit_breaker():
    print("\n" + "=" * 60)
    print("Circuit Breaker — Stopping Cascading Failures")
    print("=" * 60)

    cb = CircuitBreaker(failure_threshold=3, cooldown_s=0.5)
    actions_attempted = 0
    actions_rejected = 0

    def risky_action(name: str, should_fail: bool):
        nonlocal actions_attempted, actions_rejected
        try:
            with cb.call(name):
                actions_attempted += 1
                if should_fail:
                    raise OSError(f"Action '{name}' failed: file not found")
                print(f"  [agent] {name}: SUCCESS")
        except RuntimeError as e:
            actions_rejected += 1
            print(f"  [agent] {name}: REJECTED by circuit breaker")
        except OSError as e:
            print(f"  [agent] {name}: FAILED — {e}")

    # First 3 actions fail → opens circuit
    for i in range(3):
        risky_action(f"write_step_{i}", should_fail=True)

    # Next 3 actions are rejected without even attempting
    for i in range(3):
        risky_action(f"write_step_{3+i}", should_fail=False)

    print(f"\n  Actions attempted: {actions_attempted}")
    print(f"  Actions rejected (circuit open): {actions_rejected}")
    print("  Circuit prevented 3 additional (potentially damaging) actions")


# ---------------------------------------------------------------------------
# 7. Reversibility Budget
# ---------------------------------------------------------------------------

class ReversibilityBudget:
    """
    Track how many irreversible actions an autonomous agent has taken.
    When the budget is exceeded, require human re-authorization before
    taking further irreversible actions.

    Irreversible: delete file, send email, POST to external API, overwrite without backup
    Reversible: read file, create new file, append to log, dry-run

    The concurrency angle: under parallel execution, multiple agents
    can each take an irreversible action that individually seems safe
    but collectively exceeds what was authorized. Budget enforces a ceiling.
    """

    def __init__(self, max_irreversible: int = 5):
        self._max = max_irreversible
        self._count = 0
        self._lock = threading.Lock()
        self._log: list[str] = []

    def attempt(self, action: str, is_reversible: bool) -> bool:
        """Returns True if action is allowed, False if budget exceeded."""
        with self._lock:
            if not is_reversible:
                if self._count >= self._max:
                    print(f"  [budget] BLOCKED '{action}' — irreversible budget exhausted ({self._count}/{self._max})")
                    return False
                self._count += 1
                self._log.append(action)
                print(f"  [budget] ALLOWED '{action}' (irreversible {self._count}/{self._max})")
            else:
                print(f"  [budget] ALLOWED '{action}' (reversible, free)")
            return True


def demo_reversibility_budget():
    print("\n" + "=" * 60)
    print("Reversibility Budget — Constraining Autonomous Action Scope")
    print("=" * 60)

    budget = ReversibilityBudget(max_irreversible=3)

    actions = [
        ("read_config.json",         True),   # reversible
        ("write_draft.md",           True),   # reversible (new file)
        ("delete_old_backup.tar",    False),  # irreversible
        ("send_notification_email",  False),  # irreversible
        ("overwrite_production.cfg", False),  # irreversible — hits limit
        ("drop_database_table",      False),  # irreversible — BLOCKED
        ("read_logs",                True),   # reversible — still allowed
    ]

    print()
    for action, reversible in actions:
        budget.attempt(action, reversible)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    explain_threat_model()
    demo_permission_race()
    demo_memory_consistency()
    demo_cancellation()
    demo_audit_log()
    demo_circuit_breaker()
    demo_reversibility_budget()

    print("\n" + "=" * 60)
    print("Key Interview Points: Autonomous Agent Safety")
    print("=" * 60)
    print("""
  1. PERMISSION RACES: autonomous agents need to hold a permission lock
     for the duration of an action, not just check-then-act. ABA on
     permission state is a real threat in multi-user environments.

  2. MEMORY CONSISTENCY: snapshot isolation (read a consistent state,
     act, write with version check) is the agent equivalent of a
     database transaction. Without it, decisions are made on stale data.

  3. COOPERATIVE CANCELLATION: safe kill switches fire at explicit safe
     points, not at arbitrary bytecodes. This ensures state is always
     consistent when the agent stops.

  4. CAUSAL AUDIT LOGS: Lamport timestamps give causal ordering
     independent of wall-clock arrival order. Essential for forensics
     in concurrent multi-agent systems.

  5. CIRCUIT BREAKERS: autonomous agents must self-throttle on failure.
     Continuing to act after repeated errors compounds damage.

  6. REVERSIBILITY BUDGET: authorization for autonomous execution is
     implicitly authorization for a bounded number of irreversible actions.
     Enforce this ceiling explicitly, especially under parallel execution.

  These six patterns together form the safety layer that separates
  a trustworthy autonomous agent from a dangerous one.
    """)
