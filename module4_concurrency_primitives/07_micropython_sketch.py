"""
Module 4, File 7: MicroPython / Constrained Environment Concurrency
====================================================================

This file is designed to run on BOTH CPython and MicroPython.
It implements a minimal coroutine scheduler that works in environments
where asyncio is unavailable or too large:

  - MicroPython ports without uasyncio (older firmware)
  - CircuitPython (Adafruit's fork, limited asyncio)
  - Embedded Python in custom runtimes
  - mypy strict mode environments (asyncio types are complex)

The implementation fits in ~100 lines and requires only:
  - Generator protocol (yield)
  - time.monotonic() or time.ticks_ms() on MicroPython
  - Optional: select.poll() for I/O

MicroPython differences flagged with: # µPy:
"""

import sys
import time
import collections

# Detect MicroPython
IS_MICROPYTHON = sys.implementation.name == "micropython"

# µPy: use time.ticks_ms() / time.ticks_diff() on MicroPython (avoids float overflow)
if IS_MICROPYTHON:
    def monotonic_ms() -> int:
        return time.ticks_ms()  # type: ignore
    def elapsed_ms(start: int) -> int:
        return time.ticks_diff(time.ticks_ms(), start)  # type: ignore
else:
    def monotonic_ms() -> int:
        return int(time.monotonic() * 1000)
    def elapsed_ms(start: int) -> int:
        return monotonic_ms() - start


# ---------------------------------------------------------------------------
# Minimal Scheduler (100 lines, works on MicroPython)
# ---------------------------------------------------------------------------

class MicroScheduler:
    """
    A minimal cooperative scheduler for constrained environments.
    - No closures (avoids heap fragmentation on MCUs)
    - No external dependencies
    - Works with 8KB+ RAM

    Usage:
        sched = MicroScheduler()
        sched.run(my_coro())
        sched.run(another_coro())
        sched.loop()
    """

    def __init__(self):
        # Use list instead of heapq — simpler, acceptable for <10 tasks
        # For more tasks, replace with heapq
        self._tasks: list = []  # [(ready_at_ms, generator)]

    def run(self, coro) -> None:
        """Add a coroutine to run immediately."""
        self._tasks.append((monotonic_ms(), coro))

    def run_after(self, delay_ms: int, coro) -> None:
        """Schedule a coroutine to start after delay_ms milliseconds."""
        self._tasks.append((monotonic_ms() + delay_ms, coro))

    def loop(self) -> None:
        """Run until all tasks complete."""
        while self._tasks:
            now = monotonic_ms()

            # Find the earliest ready task
            ready_idx = None
            earliest = None
            for i, (ready_at, _) in enumerate(self._tasks):
                if ready_at <= now:
                    if earliest is None or ready_at < earliest:
                        earliest = ready_at
                        ready_idx = i

            if ready_idx is None:
                # No task ready — sleep until earliest timer
                min_ready = min(t[0] for t in self._tasks)
                sleep_ms = max(0, min_ready - now)
                if IS_MICROPYTHON:
                    time.sleep_ms(sleep_ms)  # type: ignore
                else:
                    time.sleep(sleep_ms / 1000)
                continue

            # Pop and advance the ready task
            ready_at, coro = self._tasks.pop(ready_idx)

            try:
                result = next(coro)
            except StopIteration:
                continue  # task done

            # Dispatch yielded value
            if isinstance(result, int):
                # µPy convention: yield N means sleep N milliseconds
                self._tasks.append((monotonic_ms() + result, coro))
            elif result is None:
                # yield None means re-schedule immediately
                self._tasks.append((monotonic_ms(), coro))
            # else: unknown, drop the task (or handle per your protocol)


# ---------------------------------------------------------------------------
# Coroutine Helpers (no asyncio dependency)
# ---------------------------------------------------------------------------

def sleep_ms(ms: int):
    """Yield from this to sleep for ms milliseconds."""
    yield ms  # scheduler interprets int as milliseconds


def yield_now():
    """Yield control to the scheduler without sleeping."""
    yield None


# ---------------------------------------------------------------------------
# Example Tasks for IoT Use Cases
# ---------------------------------------------------------------------------

def blink_led(pin_num: int, interval_ms: int, count: int):
    """
    Simulate blinking an LED without blocking.
    On real MicroPython:
        from machine import Pin
        pin = Pin(pin_num, Pin.OUT)
    """
    for i in range(count * 2):
        state = i % 2
        print(f"  [LED pin={pin_num}] {'ON ' if state else 'OFF'}")
        yield from sleep_ms(interval_ms)
    print(f"  [LED pin={pin_num}] done")


def read_sensor(sensor_id: str, samples: int, interval_ms: int):
    """
    Simulate reading a sensor periodically.
    On real hardware: read from ADC, I2C, SPI, etc.
    """
    import random  # not available on all MicroPython ports — use os.urandom or machine.ADC
    for i in range(samples):
        value = random.uniform(20.0, 25.0)  # temperature simulation
        print(f"  [sensor {sensor_id}] sample {i+1}/{samples}: {value:.2f}°C")
        yield from sleep_ms(interval_ms)
    print(f"  [sensor {sensor_id}] done")


def watchdog_task(timeout_ms: int):
    """
    A watchdog that resets the system if nothing checks in.
    On MicroPython: machine.WDT; here we simulate it.
    """
    last_checkin = [monotonic_ms()]

    def checkin():
        last_checkin[0] = monotonic_ms()

    check_interval = timeout_ms // 4
    for _ in range(20):
        elapsed = elapsed_ms(last_checkin[0])
        if elapsed > timeout_ms:
            print(f"  [watchdog] TIMEOUT — would reset system!")
            return
        yield from sleep_ms(check_interval)
        checkin()  # self-checkin for demo purposes
        print(f"  [watchdog] checked in, elapsed={elapsed}ms")

    print("  [watchdog] completed normally")


# ---------------------------------------------------------------------------
# Cooperative I/O (without select — polling approach for MCUs)
# ---------------------------------------------------------------------------

def poll_until_readable(fd, timeout_ms: int, check_interval_ms: int = 5):
    """
    Cooperative polling — check if fd is readable without blocking.
    On MicroPython: use select.poll() if available, or loop over machine.UART.any()
    """
    import select  # not available on all MicroPython ports
    start = monotonic_ms()
    while elapsed_ms(start) < timeout_ms:
        r, _, _ = select.select([fd], [], [], 0)  # non-blocking check
        if r:
            return True  # fd is readable
        yield from sleep_ms(check_interval_ms)
    return False  # timed out


# ---------------------------------------------------------------------------
# Type-Annotated Version for mypy Strict Mode
# ---------------------------------------------------------------------------

from typing import Generator, Iterator

# On mypy strict, asyncio coroutine types are messy.
# Generator-based coroutines have clearer types:

def typed_sleep_ms(ms: int) -> Generator[int, None, None]:
    """Type-annotated sleep for mypy strict mode."""
    yield ms


def typed_task(name: str, count: int) -> Generator[int | None, None, None]:
    """Fully typed coroutine compatible with mypy --strict."""
    for i in range(count):
        print(f"  [{name}] step {i}")
        yield from typed_sleep_ms(10)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def demo_micro_scheduler():
    print("=" * 60)
    print("MicroScheduler Demo (CPython emulating MicroPython constraints)")
    print("=" * 60)

    sched = MicroScheduler()

    # Simulate an IoT device doing three things simultaneously:
    sched.run(blink_led(25, 100, 3))      # LED on GPIO 25, 100ms interval
    sched.run(read_sensor("T1", 4, 80))   # temperature sensor, every 80ms
    sched.run(watchdog_task(500))         # watchdog with 500ms timeout

    print()
    sched.loop()
    print("\n  All IoT tasks completed")


def demo_typed_scheduler():
    print("\n" + "=" * 60)
    print("Typed Scheduler (mypy --strict compatible)")
    print("=" * 60)

    sched = MicroScheduler()
    sched.run(typed_task("TypedA", 3))
    sched.run(typed_task("TypedB", 3))
    sched.loop()


def explain_constraints():
    print("\n" + "=" * 60)
    print("Why You'd Build This Instead of Using asyncio")
    print("=" * 60)
    print(f"""
  Scenario: ESP32 with 320KB RAM, running MicroPython 1.19 without uasyncio

  asyncio overhead:
    - asyncio module: ~50KB (too large for some ports)
    - Each Task: ~200 bytes + coroutine frame
    - Event loop: ~30KB resident

  Our MicroScheduler:
    - Entire implementation: ~100 lines / ~3KB
    - Per-task overhead: generator frame (~128 bytes on MicroPython)
    - No hidden allocations in the scheduler loop

  mypy --strict scenario:
    asyncio coroutines have type: Coroutine[Any, Any, T]
    Generator coroutines have type: Generator[YieldType, SendType, ReturnType]
    The latter is fully monomorphic and works cleanly with strict mypy.

  For security tooling in constrained CI environments (AWS Lambda, edge functions):
    - Our lightweight scheduler runs without asyncio installed
    - Predictable memory footprint
    - Fully static type checking
    - No hidden GC pauses from asyncio's internal deque management
    """)


if __name__ == "__main__":
    demo_micro_scheduler()
    demo_typed_scheduler()
    explain_constraints()
