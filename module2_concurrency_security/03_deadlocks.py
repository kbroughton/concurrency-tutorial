"""
Module 2, File 3: Deadlocks — Creation, Detection, and Prevention
=================================================================

A deadlock occurs when two or more agents each hold a resource
and are waiting for a resource held by the other.

The four Coffman conditions (ALL must hold for deadlock):
  1. Mutual exclusion  — resources are non-shareable
  2. Hold and wait     — agent holds one resource while requesting another
  3. No preemption     — resources are released only voluntarily
  4. Circular wait     — circular chain of waiting agents

Prevention: break ANY of the four conditions.
"""

import threading
import time
import sys
from contextlib import contextmanager
from typing import Optional


# ---------------------------------------------------------------------------
# 1. Classic Deadlock Demo
# ---------------------------------------------------------------------------

def demo_classic_deadlock():
    """
    Agent A: acquires config_lock, then wants state_lock
    Agent B: acquires state_lock, then wants config_lock
    → Both wait forever
    """
    print("=" * 60)
    print("Classic Deadlock (with timeout to avoid hanging)")
    print("=" * 60)

    config_lock = threading.Lock()
    state_lock  = threading.Lock()
    results = {"deadlock_detected": False}

    def agent_a():
        with config_lock:
            print("  Agent A: acquired config_lock, waiting for state_lock...")
            time.sleep(0.05)  # ensure B acquires state_lock first
            acquired = state_lock.acquire(timeout=0.5)  # timeout to avoid hanging
            if acquired:
                print("  Agent A: acquired state_lock — no deadlock this run")
                state_lock.release()
            else:
                print("  Agent A: DEADLOCKED — could not acquire state_lock")
                results["deadlock_detected"] = True

    def agent_b():
        with state_lock:
            print("  Agent B: acquired state_lock, waiting for config_lock...")
            time.sleep(0.05)
            acquired = config_lock.acquire(timeout=0.5)
            if acquired:
                print("  Agent B: acquired config_lock — no deadlock this run")
                config_lock.release()
            else:
                print("  Agent B: DEADLOCKED — could not acquire config_lock")
                results["deadlock_detected"] = True

    t_a = threading.Thread(target=agent_a)
    t_b = threading.Thread(target=agent_b)
    t_a.start()
    t_b.start()
    t_a.join()
    t_b.join()

    print(f"\n  Deadlock detected: {results['deadlock_detected']}")


# ---------------------------------------------------------------------------
# 2. Fix 1: Lock Ordering (Break Circular Wait)
# ---------------------------------------------------------------------------

class OrderedLockManager:
    """
    Prevention strategy: always acquire locks in a consistent global order.
    If all agents acquire config_lock before state_lock, circular wait is impossible.

    Implementation: assign each lock a numeric ID, always acquire in ascending order.
    """

    def __init__(self):
        self.config_lock = threading.Lock()
        self.state_lock  = threading.Lock()
        self.log_lock    = threading.Lock()
        # Global lock order: config(0) → state(1) → log(2)
        self._order = {
            id(self.config_lock): 0,
            id(self.state_lock):  1,
            id(self.log_lock):    2,
        }

    @contextmanager
    def acquire_ordered(self, *locks):
        """Acquire multiple locks in consistent order to prevent deadlock."""
        sorted_locks = sorted(locks, key=lambda l: self._order[id(l)])
        acquired = []
        try:
            for lock in sorted_locks:
                lock.acquire()
                acquired.append(lock)
            yield
        finally:
            for lock in reversed(acquired):
                lock.release()


def demo_lock_ordering():
    print("\n" + "=" * 60)
    print("Fix 1: Lock Ordering")
    print("=" * 60)

    mgr = OrderedLockManager()
    errors = []

    def agent_a():
        # Even though A "wants" config first then state, ordering enforces config→state
        with mgr.acquire_ordered(mgr.config_lock, mgr.state_lock):
            time.sleep(0.02)

    def agent_b():
        # B "wants" state first then config, but ordering still enforces config→state
        with mgr.acquire_ordered(mgr.state_lock, mgr.config_lock):
            time.sleep(0.02)

    threads = [
        threading.Thread(target=agent_a),
        threading.Thread(target=agent_b),
        threading.Thread(target=agent_a),
        threading.Thread(target=agent_b),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=3.0)
        if t.is_alive():
            errors.append("Thread still running — deadlock!")

    if errors:
        print(f"  Errors: {errors}")
    else:
        print("  All threads completed without deadlock")


# ---------------------------------------------------------------------------
# 3. Fix 2: Timeout with Backoff (Break Hold-and-Wait)
# ---------------------------------------------------------------------------

class TryLockManager:
    """
    Use non-blocking acquire with exponential backoff.
    If a second lock can't be acquired, release the first and retry.
    This breaks the 'hold and wait' condition.
    """

    @staticmethod
    def acquire_with_backoff(
        lock1: threading.Lock,
        lock2: threading.Lock,
        max_attempts: int = 10,
    ) -> bool:
        for attempt in range(max_attempts):
            if lock1.acquire(timeout=0.1):
                if lock2.acquire(timeout=0.1):
                    return True  # both acquired
                else:
                    lock1.release()  # release first lock — break hold-and-wait
            # Exponential backoff with jitter
            import random
            time.sleep(0.01 * (2 ** attempt) + random.uniform(0, 0.01))
        return False


def demo_try_lock():
    print("\n" + "=" * 60)
    print("Fix 2: Try-Lock with Backoff")
    print("=" * 60)

    lock_a = threading.Lock()
    lock_b = threading.Lock()
    success_count = [0]

    mgr = TryLockManager()

    def worker(name: str, l1, l2):
        if mgr.acquire_with_backoff(l1, l2):
            try:
                success_count[0] += 1
                time.sleep(0.01)
            finally:
                l2.release()
                l1.release()
        else:
            print(f"  {name}: could not acquire both locks, gave up")

    threads = [
        threading.Thread(target=worker, args=("Thread A", lock_a, lock_b)),
        threading.Thread(target=worker, args=("Thread B", lock_b, lock_a)),
        threading.Thread(target=worker, args=("Thread C", lock_a, lock_b)),
        threading.Thread(target=worker, args=("Thread D", lock_b, lock_a)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)

    print(f"  Successful operations: {success_count[0]} / {len(threads)}")


# ---------------------------------------------------------------------------
# 4. Deadlock Detection via Resource Graph
# ---------------------------------------------------------------------------

class ResourceGraph:
    """
    Maintain a wait-for graph and detect cycles (= deadlock).
    In production: use this to detect deadlocks and break them by
    choosing a 'victim' to kill (lowest priority / youngest thread).
    """

    def __init__(self):
        self._lock = threading.Lock()
        # agent_id → set of agent_ids they're waiting for
        self.waiting_for: dict[str, set[str]] = {}
        # resource_id → agent_id currently holding it
        self.held_by: dict[str, Optional[str]] = {}

    def request(self, agent: str, resource: str):
        with self._lock:
            holder = self.held_by.get(resource)
            if holder and holder != agent:
                if agent not in self.waiting_for:
                    self.waiting_for[agent] = set()
                self.waiting_for[agent].add(holder)

    def release(self, agent: str, resource: str):
        with self._lock:
            self.held_by.pop(resource, None)
            # Remove this agent from waiting_for for all others
            for waiters in self.waiting_for.values():
                waiters.discard(agent)
            self.waiting_for.pop(agent, None)

    def acquire(self, agent: str, resource: str):
        with self._lock:
            self.held_by[resource] = agent
            if agent in self.waiting_for:
                self.waiting_for[agent].discard(
                    self.held_by.get(resource, None)
                )

    def has_cycle(self) -> Optional[list[str]]:
        """DFS cycle detection on the wait-for graph. Returns cycle path if found."""
        with self._lock:
            graph = dict(self.waiting_for)

        visited = set()
        path = []

        def dfs(node: str) -> Optional[list[str]]:
            if node in path:
                cycle_start = path.index(node)
                return path[cycle_start:]
            if node in visited:
                return None
            visited.add(node)
            path.append(node)
            for neighbor in graph.get(node, set()):
                result = dfs(neighbor)
                if result:
                    return result
            path.pop()
            return None

        for node in list(graph.keys()):
            result = dfs(node)
            if result:
                return result
        return None


def demo_deadlock_detection():
    print("\n" + "=" * 60)
    print("Deadlock Detection via Resource Graph")
    print("=" * 60)

    graph = ResourceGraph()

    # Simulate: A holds R1, wants R2; B holds R2, wants R1
    graph.acquire("Agent_A", "resource_1")
    graph.acquire("Agent_B", "resource_2")

    graph.request("Agent_A", "resource_2")  # A waits for B
    graph.request("Agent_B", "resource_1")  # B waits for A

    cycle = graph.has_cycle()
    if cycle:
        print(f"\n  DEADLOCK DETECTED: {' → '.join(cycle)} → {cycle[0]}")
        print("  Resolution: choose a victim (e.g., Agent_B) and abort its operation")
    else:
        print("  No deadlock detected")

    # Resolve by releasing Agent_B's resources
    graph.release("Agent_B", "resource_2")
    cycle_after = graph.has_cycle()
    print(f"\n  After releasing Agent_B's resources: cycle={cycle_after}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    demo_classic_deadlock()
    demo_lock_ordering()
    demo_try_lock()
    demo_deadlock_detection()

    print("\n" + "=" * 60)
    print("Deadlock Prevention Checklist")
    print("=" * 60)
    print("""
  Break CIRCULAR WAIT:
    → Always acquire locks in a consistent global order
    → Use a central lock manager that enforces ordering

  Break HOLD AND WAIT:
    → Use non-blocking acquire (timeout=0) with rollback
    → Acquire all needed locks at once (all-or-nothing)

  Break NO PREEMPTION:
    → Use trylock with backoff and exponential jitter
    → Design for lock cancellation

  Detect and recover:
    → Maintain a wait-for graph, run cycle detection periodically
    → Choose a victim to abort (lowest priority wins)
    → Use timeouts as a last resort (they mask bugs, not fix them)
    """)
