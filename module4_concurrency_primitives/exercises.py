"""
Module 4 Exercises — Build Your Own Concurrency Primitives
===========================================================

These exercises test deep understanding of the primitives we built.
Work through them in order — each builds on the previous.
"""

import time
import threading
from typing import Generator, Any, Optional, Callable


# ---------------------------------------------------------------------------
# Exercise 1: Reentrant Lock (RLock)
# ---------------------------------------------------------------------------
# Build a reentrant lock: the same thread can acquire it multiple times
# without deadlocking. It must be fully released (all acquisitions) before
# another thread can acquire it.
#
# threading.RLock exists but build it yourself from threading.Lock/Condition.

class MyRLock:
    """
    TODO: Implement a reentrant lock.
    - acquire() increments the depth if called by the owning thread
    - release() decrements the depth; lock is freed when depth reaches 0
    - Different thread must wait until the lock is fully released
    """

    def __init__(self):
        raise NotImplementedError

    def acquire(self) -> None:
        raise NotImplementedError

    def release(self) -> None:
        raise NotImplementedError

    def __enter__(self): self.acquire(); return self
    def __exit__(self, *a): self.release()


# ---------------------------------------------------------------------------
# Exercise 2: Bounded Semaphore
# ---------------------------------------------------------------------------
# A semaphore where release() raises an error if the value would exceed
# its initial maximum (prevents coding bugs where release is called too often).

class MyBoundedSemaphore:
    """
    TODO: Build a semaphore that raises ValueError if release() would
    cause the count to exceed the initial value.
    """

    def __init__(self, value: int = 1):
        raise NotImplementedError

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        raise NotImplementedError

    def release(self) -> None:
        raise NotImplementedError

    def __enter__(self): return self if self.acquire() else None
    def __exit__(self, *a): self.release()


# ---------------------------------------------------------------------------
# Exercise 3: Barrier
# ---------------------------------------------------------------------------
# A barrier that N threads must all reach before any can proceed.
# threading.Barrier exists — implement it yourself.

class MyBarrier:
    """
    TODO: Implement a cyclic barrier for N parties.
    - Each thread calls wait()
    - When N threads are waiting, all are released simultaneously
    - After release, the barrier resets for reuse (cyclic)
    - One thread (chosen arbitrarily) should receive True from wait() as
      the "leader" that can do final setup/teardown work
    """

    def __init__(self, n_parties: int):
        raise NotImplementedError

    def wait(self, timeout: Optional[float] = None) -> bool:
        """Returns True for one thread (the 'leader'), False for others."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Exercise 4: Async-Compatible Future (generator-based)
# ---------------------------------------------------------------------------
# Build a Future that works with our cooperative scheduler from file 3.
# No threading — purely generator-based.

class CoopFuture:
    """
    TODO: A Future for cooperative coroutines.
    Coroutines can `yield from future.wait()` to suspend until resolved.
    When `future.set_result(value)` is called, all waiters are unblocked.
    """

    def __init__(self):
        raise NotImplementedError

    def set_result(self, value: Any) -> None:
        raise NotImplementedError

    def set_exception(self, exc: BaseException) -> None:
        raise NotImplementedError

    def wait(self) -> Generator:
        """
        A generator that yields (suspends) until this future is resolved.
        yield from future.wait() should return the future's result.
        """
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Exercise 5: Rate Limiter (Token Bucket)
# ---------------------------------------------------------------------------
# Implement a token bucket rate limiter as a coroutine-friendly object.
# It should allow bursting up to `capacity` tokens and refill at `rate`/second.

class TokenBucket:
    """
    TODO: Implement a token bucket rate limiter.
    acquire(n=1) acquires n tokens, blocking until available.
    Works with both threads (use threading.Condition) and coroutines
    (optionally provide an async version).
    """

    def __init__(self, capacity: float, refill_rate: float):
        """
        capacity: max tokens (burst size)
        refill_rate: tokens added per second
        """
        raise NotImplementedError

    def acquire(self, tokens: int = 1, timeout: Optional[float] = None) -> bool:
        """
        Acquire `tokens` tokens, blocking until available.
        Returns True on success, False on timeout.
        """
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Exercise 6 (Stretch): Mini asyncio.gather()
# ---------------------------------------------------------------------------
# Implement gather() for our cooperative scheduler (file 3).
# It should run N coroutines concurrently and return their results in order.
#
# def gather(*coros) -> Generator[..., None, list]:
#     ...

def gather(*coros) -> Generator:
    """
    TODO: Run all coroutines concurrently in our cooperative scheduler.
    yield from gather(coro1, coro2, coro3) should return [result1, result2, result3].

    Hint: use CoopFuture from Exercise 4 to collect results.
    """
    raise NotImplementedError
    yield  # make this a generator


# ---------------------------------------------------------------------------
# Self-Tests
# ---------------------------------------------------------------------------

def test_exercise1():
    """RLock: same thread can reacquire without deadlock."""
    try:
        lock = MyRLock()
    except NotImplementedError:
        print("  Exercise 1: NOT IMPLEMENTED")
        return

    results = []
    def worker():
        with lock:
            results.append("outer_start")
            with lock:  # reentrant — should not deadlock
                results.append("inner")
            results.append("outer_end")

    t = threading.Thread(target=worker)
    t.start()
    t.join(timeout=2.0)
    if t.is_alive():
        print("  Exercise 1: FAIL — deadlock detected")
    elif results == ["outer_start", "inner", "outer_end"]:
        print("  Exercise 1: PASS")
    else:
        print(f"  Exercise 1: FAIL — unexpected order: {results}")


def test_exercise2():
    """BoundedSemaphore: over-release raises ValueError."""
    try:
        sem = MyBoundedSemaphore(2)
    except NotImplementedError:
        print("  Exercise 2: NOT IMPLEMENTED")
        return

    sem.acquire()
    sem.release()
    try:
        sem.release()  # one too many
        print("  Exercise 2: FAIL — should have raised ValueError")
    except ValueError:
        print("  Exercise 2: PASS")


def test_exercise3():
    """Barrier: N threads synchronize before proceeding."""
    try:
        barrier = MyBarrier(3)
    except NotImplementedError:
        print("  Exercise 3: NOT IMPLEMENTED")
        return

    arrivals_before_release = [0]
    arrivals_lock = threading.Lock()
    all_released = threading.Event()
    leader_count = [0]

    def worker():
        time.sleep(0.01)  # stagger arrival slightly
        is_leader = barrier.wait(timeout=5.0)
        if is_leader:
            leader_count[0] += 1
        all_released.set()

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=5.0)

    if any(t.is_alive() for t in threads):
        print("  Exercise 3: FAIL — threads timed out")
    elif leader_count[0] == 1:
        print("  Exercise 3: PASS")
    else:
        print(f"  Exercise 3: FAIL — expected 1 leader, got {leader_count[0]}")


def test_exercise5():
    """TokenBucket: rate limiting."""
    try:
        bucket = TokenBucket(capacity=5, refill_rate=10)  # 10 tokens/sec
    except NotImplementedError:
        print("  Exercise 5: NOT IMPLEMENTED")
        return

    # Drain the bucket
    for _ in range(5):
        assert bucket.acquire(1, timeout=1.0), "Should succeed"

    # Next acquire should take ~100ms (1/10 second refill)
    t0 = time.perf_counter()
    result = bucket.acquire(1, timeout=2.0)
    elapsed = time.perf_counter() - t0

    if result and 0.08 <= elapsed <= 0.2:
        print(f"  Exercise 5: PASS (waited {elapsed*1000:.0f}ms for refill)")
    elif not result:
        print("  Exercise 5: FAIL — acquire timed out when it should have refilled")
    else:
        print(f"  Exercise 5: PARTIAL — returned {result} but timing was off ({elapsed*1000:.0f}ms)")


if __name__ == "__main__":
    print("Module 4 Exercise Results:")
    test_exercise1()
    test_exercise2()
    test_exercise3()
    print("  Exercise 4: manual review — use file 03_cooperative_scheduler.py to test")
    test_exercise5()
    print("  Exercise 6: manual review — run with cooperative scheduler")
