"""
Module 4, File 6: Build Your Own Synchronization Primitives
============================================================

All of asyncio's synchronization primitives are built from a single low-level
OS primitive: the condition variable (threading.Condition in Python).

This file shows how to build Lock, Semaphore, Event, and Queue from scratch,
first with threading primitives, then with pure cooperative code for MicroPython.

The goal: understand what asyncio.Lock() actually does under the hood.
"""

import threading
import collections
import time
import sys
from typing import Optional, Any


# ---------------------------------------------------------------------------
# 1. Lock from a Condition Variable
# ---------------------------------------------------------------------------

class MyLock:
    """
    A mutex lock implemented using only threading.Condition.
    threading.Lock itself is a thin wrapper over pthread_mutex —
    this shows you the pattern used for higher-level primitives.
    """

    def __init__(self):
        self._cond = threading.Condition(threading.Lock())
        self._locked = False
        self._owner: Optional[int] = None

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        deadline = time.monotonic() + timeout if timeout > 0 else None
        with self._cond:
            while self._locked:
                if not blocking:
                    return False
                remaining = None
                if deadline:
                    remaining = max(0, deadline - time.monotonic())
                    if remaining <= 0:
                        return False
                self._cond.wait(timeout=remaining)
            self._locked = True
            self._owner = threading.get_ident()
            return True

    def release(self) -> None:
        with self._cond:
            if not self._locked:
                raise RuntimeError("release() on an unlocked lock")
            self._locked = False
            self._owner = None
            self._cond.notify()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *args):
        self.release()


# ---------------------------------------------------------------------------
# 2. Semaphore — Counting Lock
# ---------------------------------------------------------------------------

class MySemaphore:
    """
    A counting semaphore: allows up to N concurrent acquirers.
    asyncio.Semaphore is built on this pattern.

    Use cases:
      - Rate limiting (allow at most N concurrent requests)
      - Resource pools (database connection pool of size N)
      - Producer/consumer (bound the queue depth)
    """

    def __init__(self, value: int = 1):
        if value < 0:
            raise ValueError("Semaphore initial value must be >= 0")
        self._value = value
        self._cond = threading.Condition(threading.Lock())

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        deadline = time.monotonic() + timeout if timeout > 0 else None
        with self._cond:
            while self._value == 0:
                if not blocking:
                    return False
                remaining = None
                if deadline:
                    remaining = max(0, deadline - time.monotonic())
                    if remaining <= 0:
                        return False
                self._cond.wait(timeout=remaining)
            self._value -= 1
            return True

    def release(self) -> None:
        with self._cond:
            self._value += 1
            self._cond.notify()

    @property
    def value(self) -> int:
        with self._cond:
            return self._value

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *args):
        self.release()


# ---------------------------------------------------------------------------
# 3. Event — Binary Signal
# ---------------------------------------------------------------------------

class MyEvent:
    """
    A one-shot binary signal. Any number of waiters can wait for it;
    set() unblocks all of them simultaneously.
    Unlike Lock, multiple threads can all be "granted" at once.

    asyncio.Event is built on this pattern (without the threading primitives).
    """

    def __init__(self):
        self._cond = threading.Condition(threading.Lock())
        self._flag = False

    def set(self) -> None:
        with self._cond:
            self._flag = True
            self._cond.notify_all()  # wake ALL waiting threads

    def clear(self) -> None:
        with self._cond:
            self._flag = False

    def is_set(self) -> bool:
        return self._flag

    def wait(self, timeout: Optional[float] = None) -> bool:
        with self._cond:
            if self._flag:
                return True
            self._cond.wait(timeout=timeout)
            return self._flag


# ---------------------------------------------------------------------------
# 4. Queue — Producer/Consumer Channel
# ---------------------------------------------------------------------------

class MyQueue:
    """
    A bounded FIFO queue that blocks producers when full and consumers when empty.
    asyncio.Queue is built on the same logic.

    The key insight: get() and put() are both just semaphore operations:
      - _slots:  how many empty slots remain (producer acquires to put)
      - _items:  how many items are available (consumer acquires to get)
    """

    def __init__(self, maxsize: int = 0):
        self._maxsize = maxsize
        self._deque: collections.deque = collections.deque()
        self._mutex = threading.Lock()
        self._not_empty = threading.Condition(self._mutex)
        self._not_full  = threading.Condition(self._mutex)

    def put(self, item: Any, block: bool = True, timeout: Optional[float] = None) -> None:
        with self._not_full:
            if self._maxsize > 0:
                deadline = time.monotonic() + timeout if timeout else None
                while len(self._deque) >= self._maxsize:
                    if not block:
                        raise Exception("Queue is full")
                    remaining = None
                    if deadline:
                        remaining = max(0, deadline - time.monotonic())
                    self._not_full.wait(timeout=remaining)
                    if deadline and time.monotonic() >= deadline:
                        raise Exception("Queue put timed out")
            self._deque.append(item)
            self._not_empty.notify()

    def get(self, block: bool = True, timeout: Optional[float] = None) -> Any:
        with self._not_empty:
            deadline = time.monotonic() + timeout if timeout else None
            while not self._deque:
                if not block:
                    raise Exception("Queue is empty")
                remaining = None
                if deadline:
                    remaining = max(0, deadline - time.monotonic())
                self._not_empty.wait(timeout=remaining)
                if deadline and time.monotonic() >= deadline:
                    raise Exception("Queue get timed out")
            item = self._deque.popleft()
            self._not_full.notify()
            return item

    def qsize(self) -> int:
        with self._mutex:
            return len(self._deque)

    def empty(self) -> bool:
        return self.qsize() == 0


# ---------------------------------------------------------------------------
# 5. Cooperative Versions (for asyncio / MicroPython)
# ---------------------------------------------------------------------------

class CoopLock:
    """
    A cooperative lock for use in a coroutine-based scheduler (no threads).
    Waiters yield until the lock is available.
    This is the direct equivalent of asyncio.Lock.
    """

    def __init__(self):
        self._locked = False
        self._waiters: collections.deque = collections.deque()

    def locked(self) -> bool:
        return self._locked

    def acquire(self):
        """A generator that yields until the lock is acquired."""
        while self._locked:
            # Yield a future/event that will be set when lock is released
            resolved = [False]
            self._waiters.append(resolved)
            while not resolved[0]:
                yield  # yield control to scheduler
        self._locked = True

    def release(self):
        self._locked = False
        # Wake up the next waiter
        if self._waiters:
            waiter = self._waiters.popleft()
            waiter[0] = True


class CoopSemaphore:
    """Cooperative semaphore — same pattern as CoopLock but counting."""

    def __init__(self, value: int = 1):
        self._value = value
        self._waiters: collections.deque = collections.deque()

    def acquire(self):
        while self._value <= 0:
            resolved = [False]
            self._waiters.append(resolved)
            while not resolved[0]:
                yield
        self._value -= 1

    def release(self):
        self._value += 1
        if self._waiters:
            self._waiters.popleft()[0] = True


# ---------------------------------------------------------------------------
# 6. Demo and Tests
# ---------------------------------------------------------------------------

def demo_lock():
    print("=" * 60)
    print("MyLock: Thread-Safe Counter")
    print("=" * 60)

    counter = [0]
    lock = MyLock()
    N = 10_000

    def increment():
        for _ in range(N):
            with lock:
                counter[0] += 1

    threads = [threading.Thread(target=increment) for _ in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()

    expected = 4 * N
    print(f"\n  Expected: {expected:,}")
    print(f"  Actual:   {counter[0]:,}")
    print(f"  {'PASS' if counter[0] == expected else 'FAIL'}")


def demo_semaphore():
    print("\n" + "=" * 60)
    print("MySemaphore: Rate Limiting (max 3 concurrent)")
    print("=" * 60)

    sem = MySemaphore(3)
    concurrent_peak = [0]
    concurrent_now = [0]
    lock = threading.Lock()

    def worker(id: int):
        with sem:
            with lock:
                concurrent_now[0] += 1
                if concurrent_now[0] > concurrent_peak[0]:
                    concurrent_peak[0] = concurrent_now[0]
            time.sleep(0.02)
            with lock:
                concurrent_now[0] -= 1

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()

    print(f"\n  Peak concurrent: {concurrent_peak[0]} (limit was 3)")
    print(f"  {'PASS' if concurrent_peak[0] <= 3 else 'FAIL'}")


def demo_queue():
    print("\n" + "=" * 60)
    print("MyQueue: Producer/Consumer")
    print("=" * 60)

    q = MyQueue(maxsize=5)
    produced = []
    consumed = []

    def producer():
        for i in range(10):
            item = f"item_{i}"
            q.put(item)
            produced.append(item)
            time.sleep(0.01)

    def consumer():
        for _ in range(10):
            item = q.get()
            consumed.append(item)

    p = threading.Thread(target=producer)
    c = threading.Thread(target=consumer)
    p.start()
    c.start()
    p.join()
    c.join()

    print(f"\n  Produced: {len(produced)}, Consumed: {len(consumed)}")
    print(f"  Order preserved: {produced == consumed}")
    print(f"  {'PASS' if produced == consumed and len(consumed) == 10 else 'FAIL'}")


def explain_asyncio_lock_internals():
    print("\n" + "=" * 60)
    print("asyncio.Lock Internals")
    print("=" * 60)
    print("""
  asyncio.Lock is essentially CoopLock with asyncio Futures as waiters:

  class Lock:
      def __init__(self):
          self._locked = False
          self._waiters = collections.deque()   # deque of Futures

      async def acquire(self):
          if not self._locked and not self._waiters:
              self._locked = True
              return True
          fut = loop.create_future()
          self._waiters.append(fut)
          try:
              await fut   # suspend until released
              self._locked = True
              return True
          except CancelledError:
              self._waiters.remove(fut)
              raise

      def release(self):
          self._locked = False
          if self._waiters:
              fut = self._waiters.popleft()
              fut.set_result(True)   # wake up the first waiter

  The `await fut` in acquire() yields to the event loop.
  The event loop runs other coroutines until release() sets the future result.
  Then the waiter coroutine is rescheduled and gets the lock.

  This is exactly what our CoopLock does, but with asyncio's Future
  instead of a simple flag.
    """)


if __name__ == "__main__":
    demo_lock()
    demo_semaphore()
    demo_queue()
    explain_asyncio_lock_internals()

    print("\n--- Summary ---")
    print("All synchronization primitives reduce to one OS primitive:")
    print("  threading.Condition (= pthread_mutex + pthread_cond)")
    print()
    print("asyncio's primitives are the same pattern but:")
    print("  - 'wait' = yield to the event loop (not block the thread)")
    print("  - 'notify' = set_result on a Future (not pthread_cond_signal)")
    print("  - Works cooperatively; no OS threads needed")
