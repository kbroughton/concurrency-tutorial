"""
Module 4, File 3: Build a Cooperative Scheduler from Scratch
=============================================================

We implement a working cooperative scheduler that can run multiple coroutines
"concurrently" on a single thread.

This is functionally equivalent to asyncio's event loop, minus I/O multiplexing.
It works on MicroPython, CPython, and any Python with generators.

Architecture:
  Scheduler has a queue of (coroutine, pending_value) pairs.
  On each iteration it pops one, advances it, and handles the result:
    - If the coroutine yields a SleepRequest → re-enqueue after delay
    - If the coroutine yields another coroutine → run it inline
    - If the coroutine is exhausted (StopIteration) → it's done
    - If the coroutine raises an exception → handle or propagate
"""

import heapq
import time
import sys
from typing import Generator, Any, Optional, Callable


# ---------------------------------------------------------------------------
# 1. Scheduling Primitives (Yielded Signals)
# ---------------------------------------------------------------------------

class SleepRequest:
    """Coroutine yields this to request suspension for `seconds` seconds."""
    def __init__(self, seconds: float):
        self.until = time.monotonic() + seconds


class YieldControl:
    """Coroutine yields this to voluntarily yield control to the scheduler."""
    pass


YIELD_CONTROL = YieldControl()


# ---------------------------------------------------------------------------
# 2. The Scheduler
# ---------------------------------------------------------------------------

class Scheduler:
    """
    A minimal cooperative scheduler.

    Coroutines must explicitly yield to give up control.
    No coroutine can be preempted — they run until they yield.

    This is the same cooperative model as asyncio, Node.js, and most
    single-threaded async frameworks.
    """

    def __init__(self):
        # (ready_at, coroutine, pending_value) — min-heap by ready_at
        self._ready: list[tuple[float, int, Generator, Any]] = []
        self._counter = 0  # tiebreaker for heap (generators aren't comparable)
        self._running = True

    def spawn(self, coro: Generator, value: Any = None) -> None:
        """Add a coroutine to the ready queue."""
        self._enqueue(0.0, coro, value)

    def _enqueue(self, delay: float, coro: Generator, value: Any = None) -> None:
        ready_at = time.monotonic() + delay
        heapq.heappush(self._ready, (ready_at, self._counter, coro, value))
        self._counter += 1

    def run(self) -> None:
        """
        Main scheduler loop.
        Runs until all coroutines are exhausted.
        """
        while self._ready:
            ready_at, _, coro, send_value = heapq.heappop(self._ready)

            # Wait until this task is ready (for sleep requests)
            now = time.monotonic()
            if ready_at > now:
                time.sleep(ready_at - now)

            # Advance the coroutine
            try:
                yielded = coro.send(send_value)
            except StopIteration:
                continue  # coroutine finished
            except Exception as exc:
                print(f"  [scheduler] Unhandled exception in coroutine: {exc}")
                continue

            # Dispatch based on what was yielded
            if isinstance(yielded, SleepRequest):
                delay = max(0.0, yielded.until - time.monotonic())
                self._enqueue(delay, coro, None)
            elif isinstance(yielded, YieldControl):
                self._enqueue(0.0, coro, None)
            elif isinstance(yielded, Generator):
                # Sub-coroutine: schedule the sub-coroutine, then re-queue self
                # (simplified: doesn't handle return value from sub-coro)
                self._enqueue(0.0, yielded, None)
                self._enqueue(0.0, coro, None)
            else:
                # Unknown yield — re-enqueue with the value as send_value
                self._enqueue(0.0, coro, yielded)


# ---------------------------------------------------------------------------
# 3. Helper Coroutine Utilities
# ---------------------------------------------------------------------------

def sleep(seconds: float) -> Generator:
    """
    Coroutine-friendly sleep. Yields a SleepRequest to the scheduler.
    Usage: yield from sleep(0.1)
    """
    yield SleepRequest(seconds)


def yield_control() -> Generator:
    """Yield control to the scheduler without sleeping."""
    yield YIELD_CONTROL


# ---------------------------------------------------------------------------
# 4. Example Coroutines
# ---------------------------------------------------------------------------

def ticker(name: str, interval: float, count: int) -> Generator:
    """A coroutine that ticks N times at a given interval."""
    for i in range(count):
        print(f"  [{name}] tick {i+1}/{count} at t={time.monotonic():.3f}")
        yield from sleep(interval)
    print(f"  [{name}] done")


def counter_task(name: str, n: int) -> Generator:
    """A CPU-bound-ish task that yields control after each step."""
    total = 0
    for i in range(n):
        total += i * i
        if i % (n // 5) == 0:
            print(f"  [{name}] progress {i}/{n}")
            yield from yield_control()
    print(f"  [{name}] done, total={total}")


def producer_consumer(
    shared_buffer: list,
    produced: list,
    consumed: list,
) -> Generator:
    """Demonstrate producer/consumer with cooperative scheduling."""

    def producer() -> Generator:
        for i in range(5):
            item = f"item_{i}"
            shared_buffer.append(item)
            produced.append(item)
            print(f"  [producer] produced {item}, buffer size: {len(shared_buffer)}")
            yield from sleep(0.02)

    def consumer() -> Generator:
        while len(consumed) < 5:
            if shared_buffer:
                item = shared_buffer.pop(0)
                consumed.append(item)
                print(f"  [consumer] consumed {item}")
            else:
                print(f"  [consumer] buffer empty, waiting...")
            yield from sleep(0.03)

    # Spawn both within this coroutine (simplified — real scheduler handles this)
    yield producer()
    yield consumer()


# ---------------------------------------------------------------------------
# 5. Run the Demo
# ---------------------------------------------------------------------------

def demo_scheduler():
    print("=" * 60)
    print("Cooperative Scheduler Demo")
    print("=" * 60)

    sched = Scheduler()

    # Spawn multiple coroutines
    sched.spawn(ticker("fast", 0.05, 4))
    sched.spawn(ticker("slow", 0.12, 2))
    sched.spawn(counter_task("counter", 1000))

    print("\n  Running scheduler...")
    t0 = time.monotonic()
    sched.run()
    elapsed = time.monotonic() - t0

    print(f"\n  Total time: {elapsed:.3f}s")
    print("  All coroutines completed")


# ---------------------------------------------------------------------------
# 6. Key Properties of Cooperative Scheduling
# ---------------------------------------------------------------------------

def explain_cooperative_vs_preemptive():
    print("\n" + "=" * 60)
    print("Cooperative vs. Preemptive Scheduling")
    print("=" * 60)
    print("""
  Cooperative (asyncio, this scheduler, Node.js):
    + No GIL / lock contention between tasks
    + Predictable task switching points (only at yield/await)
    + Simple mental model — only one task runs at a time
    + Works on single-core (IoT) without OS thread support
    - A task that doesn't yield starves all others
    - CPU-bound tasks block the event loop
    - Bugs in one task can stall the whole system

  Preemptive (threading, OS scheduler):
    + Tasks can be interrupted at any point
    + CPU-bound tasks don't starve others
    + True parallelism on multi-core (if no GIL)
    - Race conditions, deadlocks require locks
    - Harder to reason about
    - Higher overhead (context switches, lock contention)

  For security tooling (like Claude Code hooks):
    - I/O-bound → cooperative is fine (asyncio)
    - CPU-bound rules evaluation → use ProcessPoolExecutor
    - Need isolation → subprocess (not threading or asyncio)

  For IoT / MicroPython:
    - Use cooperative scheduling (uasyncio)
    - No threading on most MCU ports
    - main() loops with yield/await; hardware interrupts are separate
    """)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    demo_scheduler()
    explain_cooperative_vs_preemptive()
