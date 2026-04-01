"""
Module 4, File 1: CPython Concurrency Internals
================================================

Before building our own library, we need to understand what CPython provides
at the C level. This file explores:

  1. The GIL — what it is, when it's released, PEP 703 (free-threaded CPython)
  2. Thread state (PyThreadState) — per-thread Python state
  3. Bytecode and the eval loop — where the GIL is checked
  4. What "atomic" means in CPython vs. hardware
  5. The C-level primitives asyncio actually uses
"""

import sys
import dis
import threading
import time
import ctypes
import gc


# ---------------------------------------------------------------------------
# 1. The GIL — Global Interpreter Lock
# ---------------------------------------------------------------------------

def explain_gil():
    """
    The GIL is a mutex (pthread_mutex or Win32 critical section) that must
    be held by any thread before executing Python bytecode.

    Purpose (historical):
      - Simplifies CPython's memory management (reference counting is not atomic)
      - Makes non-thread-safe C extensions safe by default

    When it's released:
      - At sys.getswitchinterval() intervals (default 5ms) — preemptive
      - During blocking I/O syscalls (read, write, accept, sleep)
      - During long C operations that explicitly call Py_BEGIN_ALLOW_THREADS
        (numpy, hashlib, zlib, ssl, subprocess)

    What this means for you:
      - CPU-bound threads: GIL prevents true parallelism → use multiprocessing
      - I/O-bound threads: GIL is released during I/O → threading works fine
      - asyncio: single-threaded cooperative → GIL irrelevant but never blocking
    """
    print("=" * 60)
    print("The GIL")
    print("=" * 60)
    print(f"\n  Switch interval: {sys.getswitchinterval()*1000:.1f}ms")
    print(f"  Python version: {sys.version}")
    print(f"  Free-threaded build: {getattr(sys, '_is_gil_enabled', lambda: True)()}")

    # Demonstrate: CPU-bound threads don't actually parallelize
    import time

    def cpu_bound(n: int):
        total = 0
        for i in range(n):
            total += i * i
        return total

    N = 5_000_000

    # Single thread
    t0 = time.perf_counter()
    cpu_bound(N)
    single_time = time.perf_counter() - t0

    # Two threads — should be ~2x faster if GIL didn't exist
    t0 = time.perf_counter()
    threads = [threading.Thread(target=cpu_bound, args=(N//2,)) for _ in range(2)]
    for t in threads: t.start()
    for t in threads: t.join()
    two_thread_time = time.perf_counter() - t0

    print(f"\n  CPU-bound benchmark (N={N:,}):")
    print(f"    Single thread:  {single_time*1000:.1f}ms")
    print(f"    Two threads:    {two_thread_time*1000:.1f}ms")
    speedup = single_time / two_thread_time
    print(f"    Speedup:        {speedup:.2f}x (expected ~2x without GIL, got ~1x)")

    # I/O-bound threads DO parallelize (GIL released during sleep/I/O)
    def io_bound(secs: float):
        time.sleep(secs)

    t0 = time.perf_counter()
    io_bound(0.1)
    io_single = time.perf_counter() - t0

    t0 = time.perf_counter()
    threads = [threading.Thread(target=io_bound, args=(0.1,)) for _ in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    io_parallel = time.perf_counter() - t0

    print(f"\n  I/O-bound benchmark (4 × 100ms sleep):")
    print(f"    Sequential:    {4*io_single*1000:.0f}ms")
    print(f"    Parallel:      {io_parallel*1000:.0f}ms")
    print(f"    Speedup:       {(4*io_single)/io_parallel:.1f}x (GIL released during sleep)")


# ---------------------------------------------------------------------------
# 2. PyThreadState — Per-Thread Python State
# ---------------------------------------------------------------------------

def explain_thread_state():
    """
    Each OS thread has a PyThreadState struct in CPython containing:
      - frame stack (currently executing frames)
      - exception state
      - GIL request flag
      - tracing hooks

    You can introspect this via sys._current_frames() and threading.

    This is why you can't just pass Python objects between OS threads arbitrarily —
    each thread has its own exception state, and frame objects are not thread-safe.
    """
    print("\n" + "=" * 60)
    print("PyThreadState — Per-Thread State")
    print("=" * 60)

    thread_frames = {}
    ready = threading.Event()

    def worker():
        # Each thread has its own frame stack
        def inner():
            ready.set()
            time.sleep(0.1)

        inner()

    t = threading.Thread(target=worker)
    t.start()
    ready.wait()

    # Introspect all thread frames
    all_frames = sys._current_frames()
    print(f"\n  Active threads with Python frames: {len(all_frames)}")
    for thread_id, frame in all_frames.items():
        print(f"  Thread {thread_id}: {frame.f_code.co_filename}:{frame.f_lineno} in {frame.f_code.co_name}")

    t.join()


# ---------------------------------------------------------------------------
# 3. Bytecode and the Eval Loop
# ---------------------------------------------------------------------------

def explain_eval_loop():
    """
    CPython's eval loop (ceval.c: _PyEval_EvalFrameDefault) is the heart
    of the interpreter. Key facts:

    - Each bytecode instruction is dispatched via a switch statement
    - The GIL check (EVAL_BREAKER) runs at the top of the loop
    - EVAL_BREAKER is set when:
      - A signal arrives (SIGUSR1, SIGINT)
      - Another thread is waiting for the GIL
      - A pending call is registered (GC, profiling hooks)

    Understanding this explains why:
      - Signal handlers only run between bytecodes (not mid-instruction)
      - GC can pause any thread at any time
      - The GIL is not actually a simple mutex — it's a complex state machine
        (Python 3.2+ uses a "new GIL" based on a condition variable)
    """
    print("\n" + "=" * 60)
    print("Bytecode: What Executes Between GIL Checks")
    print("=" * 60)

    def example_function(x: int, y: int) -> int:
        result = x + y
        return result

    print("\n  Bytecode for: result = x + y; return result")
    for instr in dis.get_instructions(example_function):
        is_store = "STORE" in instr.opname
        print(f"  {instr.offset:3d}  {instr.opname:25s} {str(instr.argval or ''):20s} {'← GIL could release after here' if is_store else ''}")

    # Show bytecode for a compound expression
    print("\n  Bytecode for: counter += 1")
    def increment(counter): counter += 1
    for instr in dis.get_instructions(increment):
        print(f"  {instr.offset:3d}  {instr.opname:25s} {str(instr.argval or '')}")


# ---------------------------------------------------------------------------
# 4. Reference Counting and Why Objects Die (or Don't)
# ---------------------------------------------------------------------------

def explain_refcounting():
    """
    CPython uses reference counting for memory management.
    Every object has ob_refcnt; when it reaches 0, __del__ is called immediately.

    Thread-safety of refcounting:
      - Incrementing ob_refcnt is NOT atomic at the hardware level
      - The GIL makes it effectively atomic (only one thread modifies at a time)
      - In free-threaded CPython (PEP 703), refcounting uses atomic CPU instructions

    Security relevance:
      - An object's __del__ can run at any time when the last reference drops
      - This can cause use-after-free in C extensions that don't hold references
      - In asyncio, tasks must be referenced to avoid premature cancellation
    """
    print("\n" + "=" * 60)
    print("Reference Counting")
    print("=" * 60)

    import sys

    x = [1, 2, 3]
    print(f"\n  List refcount before assignment: {sys.getrefcount(x) - 1}")  # -1 for the getrefcount arg
    y = x
    print(f"  After y = x: {sys.getrefcount(x) - 1}")
    del y
    print(f"  After del y: {sys.getrefcount(x) - 1}")

    print("""
  asyncio gotcha: creating a Task and not keeping a reference:
    asyncio.create_task(coro())  # BUG: task may be GC'd immediately
    task = asyncio.create_task(coro())  # CORRECT: hold a reference

  The asyncio docs warn about this: "Save a reference to the result."
    """)


# ---------------------------------------------------------------------------
# 5. What asyncio Actually Uses at the OS Level
# ---------------------------------------------------------------------------

def explain_asyncio_internals():
    """
    asyncio's event loop uses selectors.DefaultSelector, which wraps:
      - epoll  on Linux
      - kqueue on macOS/BSD
      - select on Windows (fallback)

    The event loop's run_forever() is essentially:

      while True:
          # Process ready callbacks
          for callback in ready_callbacks:
              callback()

          # Calculate timeout until next scheduled timer
          timeout = next_timer - monotonic()

          # Block on I/O until something is ready OR timeout
          events = selector.select(timeout)

          # Schedule I/O callbacks
          for key, mask in events:
              schedule_callback(key.data.callback)

          # Process expired timers
          while timers and timers[0].when <= monotonic():
              schedule_callback(timers.pop().callback)

    That's the entire event loop. The rest is Python wrapping.
    """
    print("\n" + "=" * 60)
    print("What asyncio Uses at the OS Level")
    print("=" * 60)

    import selectors
    sel = selectors.DefaultSelector()
    print(f"\n  Platform selector: {type(sel).__name__}")
    print(f"  Available selectors: {[s for s in dir(selectors) if s.endswith('Selector')]}")
    sel.close()

    print("""
  The three OS primitives asyncio is built on:
    1. Generators (yield/send) — coroutine suspension/resumption
    2. selectors.DefaultSelector — I/O readiness notification
    3. heapq + time.monotonic() — timer scheduling

  Everything else (Lock, Semaphore, Queue, gather) is pure Python on top of these.
    """)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    explain_gil()
    explain_thread_state()
    explain_eval_loop()
    explain_refcounting()
    explain_asyncio_internals()
