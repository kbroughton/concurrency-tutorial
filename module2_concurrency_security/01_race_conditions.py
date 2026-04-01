"""
Module 2, File 1: Race Conditions in Depth
==========================================

Covers:
  1. The GIL myth — why += is still a race
  2. ABA problem
  3. Signal handler races
  4. Double-checked locking (broken in Python without memory barriers)
  5. Atomic operations that ARE safe
"""

import dis
import threading
import time
import signal
import os
import ctypes
from typing import Optional


# ---------------------------------------------------------------------------
# 1. The GIL Myth: Why += is Still a Race
# ---------------------------------------------------------------------------

def show_counter_race():
    """
    Many Python programmers believe the GIL makes threads safe.
    It doesn't. The GIL is released between bytecodes, so:

        counter += 1

    which compiles to:
        LOAD_GLOBAL  counter
        LOAD_CONST   1
        INPLACE_ADD
        STORE_GLOBAL counter   ← another thread can run HERE, before store

    is NOT atomic.
    """
    print("=" * 60)
    print("The GIL Does NOT Protect You from Race Conditions")
    print("=" * 60)

    print("\n  Bytecode for 'counter += 1':")
    def sample(counter): counter += 1
    for instr in dis.get_instructions(sample):
        print(f"    {instr.opname:25s} {instr.argval or ''}")

    print()

    # Demonstrate the race
    counter = [0]  # Use list so threads can share reference

    def increment_many(n: int):
        for _ in range(n):
            counter[0] += 1

    N = 100_000
    threads = [threading.Thread(target=increment_many, args=(N,)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    expected = 4 * N
    actual = counter[0]
    print(f"  Expected: {expected:,}")
    print(f"  Actual:   {actual:,}")
    if actual < expected:
        print(f"  Lost {expected - actual:,} increments due to race condition")
    else:
        print("  Lucky run — no lost increments (try again, it's non-deterministic)")

    # The fix
    print("\n  Fix: use threading.Lock() or collections.Counter with a lock")
    print("  Or use ctypes.c_long for true atomic integer operations")


# ---------------------------------------------------------------------------
# 2. ABA Problem
# ---------------------------------------------------------------------------

def show_aba_problem():
    """
    ABA: a shared value goes A → B → A between two reads.
    The second reader sees A and thinks nothing changed — but B had side effects.

    Classic example in lock-free programming. In Python agent systems:
    an agent reads a "pending" state, another marks it done+reset it to pending
    (for a new task), and the first agent thinks its original task is still pending.
    """
    print("\n" + "=" * 60)
    print("ABA Problem")
    print("=" * 60)

    # Shared "task queue" state: None means no task, string means pending task
    shared_state = {"task": "task_001", "completed": []}
    aba_triggered = [False]

    def agent_a():
        """Agent A: check if task_001 is pending, then process it."""
        task = shared_state["task"]  # reads "task_001"
        if task is None:
            return

        # Simulate slow processing
        time.sleep(0.02)

        # Agent A assumes task is still "task_001" — but it might have been
        # replaced with a different task that happens to have the same ID
        if shared_state["task"] == task:
            # Looks safe — same value. But was it the SAME task or a recycled one?
            shared_state["completed"].append(task)
            print(f"  Agent A completed: {task}")
        else:
            print(f"  Agent A: task changed, skipping")

    def agent_b():
        """Agent B: mark task_001 done, assign new task_001 (recycled ID)."""
        time.sleep(0.005)
        # Complete original task_001
        original = shared_state["task"]
        shared_state["task"] = None   # task done
        time.sleep(0.005)
        # New cycle: assign a NEW task with the same ID (recycled)
        shared_state["task"] = "task_001"  # ABA: back to same string
        aba_triggered[0] = True
        print(f"  Agent B: recycled task ID back to task_001")

    t_a = threading.Thread(target=agent_a)
    t_b = threading.Thread(target=agent_b)

    t_a.start()
    t_b.start()
    t_a.join()
    t_b.join()

    print(f"\n  ABA triggered: {aba_triggered[0]}")
    print(f"  Tasks agent A 'completed': {shared_state['completed']}")
    print("""
  Fix: Use a version counter (monotonic) alongside the value:
    state = {"task": "task_001", "version": 1}
  A compare-and-swap must match BOTH task AND version to succeed.
  This is the foundation of lock-free data structures (CAS operations).
    """)


# ---------------------------------------------------------------------------
# 3. Signal Handler Race
# ---------------------------------------------------------------------------

def show_signal_race():
    """
    Python signal handlers run between arbitrary bytecodes in the main thread.
    If a signal handler modifies shared mutable state, it's a race with the
    main thread — even without any user-created threads.
    """
    print("=" * 60)
    print("Signal Handler Race Condition")
    print("=" * 60)

    shared_list = []
    ITERATIONS = 10_000

    def signal_handler(signum, frame):
        """Runs asynchronously between any two bytecodes."""
        shared_list.append("SIGNAL")

    original_handler = signal.getsignal(signal.SIGUSR1)
    signal.signal(signal.SIGUSR1, signal_handler)

    def send_signals():
        """Send SIGUSR1 rapidly to the main process."""
        pid = os.getpid()
        for _ in range(20):
            os.kill(pid, signal.SIGUSR1)
            time.sleep(0.001)

    def main_thread_work():
        """Main thread appending its own items."""
        for i in range(ITERATIONS):
            shared_list.append(f"main_{i}")

    # Run signal sender in background thread
    sender = threading.Thread(target=send_signals)
    sender.start()
    main_thread_work()
    sender.join()

    signal.signal(signal.SIGUSR1, original_handler)

    signal_items = [x for x in shared_list if x == "SIGNAL"]
    main_items = [x for x in shared_list if x.startswith("main_")]

    print(f"\n  Total items: {len(shared_list)}")
    print(f"  Signal items: {len(signal_items)}")
    print(f"  Main items: {len(main_items)}")
    print(f"  Expected main items: {ITERATIONS}")
    print("""
  Signal handlers should only:
  - Set a simple flag (assignment of a small object is atomic in CPython)
  - Write a single byte to a self-pipe (the self-pipe trick)
  - Call os.write() on a non-blocking fd

  Never: acquire locks, call malloc/free indirectly, modify complex data structures
  The asyncio signal handling mechanism uses the self-pipe trick for safety.
    """)


# ---------------------------------------------------------------------------
# 4. What IS Atomic in CPython?
# ---------------------------------------------------------------------------

def show_atomic_operations():
    """
    Not all operations are racy. Some CPython operations are effectively atomic
    due to how the GIL works with single bytecodes.
    """
    print("=" * 60)
    print("What's Actually Atomic in CPython")
    print("=" * 60)

    print("""
  ATOMIC (single bytecode, GIL held for entire operation):
  ─────────────────────────────────────────────────────────
  x = value              # STORE_NAME — assignment of reference is atomic
  list.append(item)      # C-level append holds GIL throughout
  dict[key] = value      # C-level dict insert (but not check+insert!)
  x = y                  # Reference copy is atomic

  NOT ATOMIC (multiple bytecodes, GIL can be released between them):
  ───────────────────────────────────────────────────────────────────
  x += 1                 # LOAD, ADD, STORE — three bytecodes
  if key not in d: d[k] # CHECK + INSERT — two bytecodes
  x = x + [item]         # Read x, create new list, store — three bytecodes
  obj.attr = val         # __setattr__ may have multiple steps

  CPYTHON IMPLEMENTATION NOTE:
  ─────────────────────────────
  The GIL is released every sys.getswitchinterval() seconds (default: 5ms)
  OR at certain C API boundaries. C extensions can release the GIL explicitly.

  This means: even C-level operations in extensions may not be atomic if they
  release the GIL mid-operation (numpy, pandas, cryptography all do this).
    """)

    import sys
    print(f"  Current switch interval: {sys.getswitchinterval()*1000:.1f}ms")
    print()


# ---------------------------------------------------------------------------
# 5. Broken Double-Checked Locking
# ---------------------------------------------------------------------------

class BrokenSingleton:
    """
    Double-checked locking: a common pattern that's broken without
    memory barriers (which Python doesn't have explicit support for).

    The problem: the compiler/CPU can reorder writes, so another thread
    might see _instance partially initialized.
    In CPython this is less of an issue due to GIL + dictionary memory model,
    but in multi-process or when extending with C, it can manifest.
    """
    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:           # Check #1 (no lock)
            with cls._lock:
                if cls._instance is None:   # Check #2 (with lock)
                    cls._instance = cls()   # BROKEN: instance may be partially
                                            # initialized when visible to other threads
        return cls._instance


class SafeSingleton:
    """
    Safe version: use threading.local() for per-thread state,
    or just accept the lock overhead on every call.
    Or better yet: use module-level singletons (Python module import is thread-safe).
    """
    _instance: Optional['SafeSingleton'] = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> 'SafeSingleton':
        # Always acquire lock — simpler, CPython GIL makes this fast anyway
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
        return cls._instance


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    show_counter_race()
    show_aba_problem()
    show_signal_race()
    show_atomic_operations()

    print("=" * 60)
    print("Key Takeaways")
    print("=" * 60)
    print("""
  1. The GIL is NOT a synchronization primitive — it's a CPython implementation
     detail that can be removed (PEP 703). Never rely on it for correctness.

  2. ABA problems arise whenever you use values as identity markers.
     Fix: add a monotonically increasing version/generation counter.

  3. Signal handlers are asynchronous and can race with any point in your code.
     Keep them minimal: set flags, write to pipes, nothing else.

  4. list.append() and dict[k]=v are effectively atomic in CPython TODAY,
     but this is an implementation detail. Code that relies on it is fragile.

  5. For security code, use explicit locks. Performance is secondary to correctness.
    """)
