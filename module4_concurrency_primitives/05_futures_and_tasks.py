"""
Module 4, File 5: Futures and Tasks from Scratch
=================================================

A Future is a container for a value that doesn't exist yet.
A Task is a Future that wraps a coroutine and drives it to completion.

asyncio.gather() is just "create N Tasks and wait for all their Futures."

This file implements:
  1. Future — the fundamental promise/resolve primitive
  2. Task — wraps a coroutine in a Future
  3. gather() — wait for multiple Futures/Tasks concurrently
  4. timeout() — cancel a task if it takes too long
"""

import time
import threading
import traceback
from typing import TypeVar, Generic, Callable, Optional, Any


T = TypeVar("T")


# ---------------------------------------------------------------------------
# 1. Future — A Value That Will Exist Later
# ---------------------------------------------------------------------------

class InvalidStateError(Exception):
    pass


class CancelledError(Exception):
    pass


class Future(Generic[T]):
    """
    A Future holds a result that will be set by one party and
    read by another. Equivalent to asyncio.Future but using threading.

    State machine:
      PENDING → FINISHED (via set_result or set_exception)
      PENDING → CANCELLED (via cancel)
    """

    _PENDING   = "PENDING"
    _FINISHED  = "FINISHED"
    _CANCELLED = "CANCELLED"

    def __init__(self):
        self._state = self._PENDING
        self._result: Optional[T] = None
        self._exception: Optional[BaseException] = None
        self._callbacks: list[Callable] = []
        self._lock = threading.Lock()
        self._done_event = threading.Event()

    # -- Setting state -------------------------------------------------------

    def set_result(self, result: T) -> None:
        with self._lock:
            if self._state != self._PENDING:
                raise InvalidStateError(f"Future is already {self._state}")
            self._result = result
            self._state = self._FINISHED
            callbacks = list(self._callbacks)
        self._done_event.set()
        for cb in callbacks:
            cb(self)

    def set_exception(self, exc: BaseException) -> None:
        with self._lock:
            if self._state != self._PENDING:
                raise InvalidStateError(f"Future is already {self._state}")
            self._exception = exc
            self._state = self._FINISHED
            callbacks = list(self._callbacks)
        self._done_event.set()
        for cb in callbacks:
            cb(self)

    def cancel(self) -> bool:
        with self._lock:
            if self._state != self._PENDING:
                return False
            self._state = self._CANCELLED
            callbacks = list(self._callbacks)
        self._done_event.set()
        for cb in callbacks:
            cb(self)
        return True

    # -- Reading state -------------------------------------------------------

    def done(self) -> bool:
        return self._state != self._PENDING

    def cancelled(self) -> bool:
        return self._state == self._CANCELLED

    def result(self) -> T:
        with self._lock:
            state = self._state
            exc = self._exception
            result = self._result
        if state == self._CANCELLED:
            raise CancelledError("Future was cancelled")
        if state != self._FINISHED:
            raise InvalidStateError("Future is not done yet")
        if exc is not None:
            raise exc
        return result  # type: ignore

    def add_done_callback(self, cb: Callable) -> None:
        with self._lock:
            if self._state == self._PENDING:
                self._callbacks.append(cb)
                return
        cb(self)  # already done — call immediately

    # -- Blocking wait (for thread-based futures) ----------------------------

    def wait(self, timeout: Optional[float] = None) -> bool:
        """Block until done. Returns True if done, False if timeout."""
        return self._done_event.wait(timeout=timeout)

    def __repr__(self):
        if self._state == self._PENDING:
            return "Future<PENDING>"
        elif self._state == self._CANCELLED:
            return "Future<CANCELLED>"
        elif self._exception:
            return f"Future<FAILED: {self._exception!r}>"
        else:
            return f"Future<result={self._result!r}>"


# ---------------------------------------------------------------------------
# 2. Task — A Future That Runs a Thread
# ---------------------------------------------------------------------------

class Task(Future[T]):
    """
    A Task wraps a callable (or coroutine function) in a thread,
    resolving the Future when the callable returns or raises.

    This is the threading equivalent of asyncio.Task.
    For the async version, see the comment at the bottom.
    """

    def __init__(self, fn: Callable[[], T], name: Optional[str] = None):
        super().__init__()
        self._fn = fn
        self._name = name or fn.__name__
        self._thread = threading.Thread(target=self._run, name=self._name, daemon=True)
        self._thread.start()

    def _run(self):
        try:
            result = self._fn()
            self.set_result(result)
        except CancelledError:
            self.cancel()
        except Exception as exc:
            self.set_exception(exc)

    def __repr__(self):
        return f"Task[{self._name}]({super().__repr__()})"


# ---------------------------------------------------------------------------
# 3. gather() — Wait for Multiple Futures
# ---------------------------------------------------------------------------

def gather(*futures: Future, timeout: Optional[float] = None) -> list:
    """
    Wait for all futures to complete and return their results in order.
    Equivalent to asyncio.gather() but synchronous (blocking).

    Raises the first exception encountered.
    """
    results = [None] * len(futures)
    exceptions = []

    # Use a countdown latch pattern
    latch = threading.Barrier(len(futures) + 1)  # +1 for the waiter thread

    def on_done(index: int, future: Future):
        results[index] = future
        try:
            latch.wait()
        except threading.BrokenBarrierError:
            pass

    for i, fut in enumerate(futures):
        fut.add_done_callback(lambda f, idx=i: on_done(idx, f))

    # Wait for all to complete
    deadline = time.monotonic() + timeout if timeout else None

    # Alternative: poll loop (simpler than barrier for this demo)
    remaining_timeout = timeout
    start = time.monotonic()
    for fut in futures:
        remaining = None
        if timeout is not None:
            remaining = max(0, timeout - (time.monotonic() - start))
        if not fut.wait(timeout=remaining):
            # Cancel remaining futures on timeout
            for f in futures:
                f.cancel()
            raise TimeoutError(f"gather() timed out after {timeout}s")

    # Collect results, raising first exception
    final_results = []
    for fut in futures:
        final_results.append(fut.result())  # raises if exception or cancelled

    return final_results


# ---------------------------------------------------------------------------
# 4. Demo: Parallel I/O-Bound Tasks with Futures
# ---------------------------------------------------------------------------

def simulate_web_fetch(url: str, delay: float) -> dict:
    """Simulate a slow web fetch."""
    time.sleep(delay)
    return {"url": url, "status": 200, "size": len(url) * 100}


def demo_gather():
    print("=" * 60)
    print("gather() — Parallel Task Execution")
    print("=" * 60)

    urls = [
        ("https://api.example.com/search", 0.10),
        ("https://api.example.com/results", 0.15),
        ("https://api.example.com/metadata", 0.08),
        ("https://api.example.com/schema", 0.20),
    ]

    # Sequential
    t0 = time.perf_counter()
    sequential_results = [simulate_web_fetch(url, delay) for url, delay in urls]
    sequential_time = time.perf_counter() - t0
    print(f"\n  Sequential: {sequential_time*1000:.0f}ms ({len(sequential_results)} results)")

    # Parallel with gather
    t0 = time.perf_counter()
    tasks = [Task(lambda u=url, d=delay: simulate_web_fetch(u, d), name=f"fetch_{i}")
             for i, (url, delay) in enumerate(urls)]
    parallel_results = gather(*tasks)
    parallel_time = time.perf_counter() - t0
    print(f"  Parallel:   {parallel_time*1000:.0f}ms ({len(parallel_results)} results)")
    print(f"  Speedup:    {sequential_time/parallel_time:.1f}x")

    for result in parallel_results:
        print(f"    {result['url']:45s} status={result['status']}")


# ---------------------------------------------------------------------------
# 5. Callbacks and Chaining
# ---------------------------------------------------------------------------

def demo_callbacks():
    print("\n" + "=" * 60)
    print("Future Callbacks and Chaining")
    print("=" * 60)

    def computation() -> int:
        time.sleep(0.05)
        return 42

    fut: Future[int] = Future()

    # Register callback before result is set
    def on_done(f: Future):
        print(f"  [callback] Future completed: {f}")

    fut.add_done_callback(on_done)

    # Set result from another thread
    def resolver():
        time.sleep(0.1)
        fut.set_result(42)

    threading.Thread(target=resolver, daemon=True).start()

    print("\n  Waiting for future to be resolved...")
    fut.wait()
    print(f"  Result: {fut.result()}")

    # Register callback AFTER result is already set — should fire immediately
    fut.add_done_callback(lambda f: print(f"  [late callback] fired immediately: {f.result()}"))


# ---------------------------------------------------------------------------
# 6. How asyncio.Future.__await__ Works
# ---------------------------------------------------------------------------

def explain_async_future():
    print("\n" + "=" * 60)
    print("asyncio.Future Internals")
    print("=" * 60)
    print("""
  asyncio.Future is the core primitive. Its __await__ is:

    def __await__(self):
        if not self.done():
            self._asyncio_future_blocking = True
            yield self        # ← suspend, give control to event loop
        if not self.done():
            raise RuntimeError("await on non-done Future without blocking")
        return self.result()

  When a coroutine does:
    result = await some_future

  The event loop receives `some_future` from the yield.
  It registers a callback: when future is done, re-schedule this coroutine.
  When future.set_result() is called, the callback fires,
  the coroutine is re-added to the ready queue,
  and next iteration it resumes past the yield with the result.

  asyncio.Task drives the coroutine:
    def __step(self, exc=None):
        try:
            result = coro.send(None) if exc is None else coro.throw(exc)
        except StopIteration as e:
            self.set_result(e.value)
        except CancelledError:
            self.cancel()
        except Exception as e:
            self.set_exception(e)
        else:
            # result is what the coro yielded (e.g., a Future)
            result.add_done_callback(self.__step_done)
    """)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    demo_gather()
    demo_callbacks()
    explain_async_future()
