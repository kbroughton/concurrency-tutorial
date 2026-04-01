"""
Module 4, File 2: Generators as Coroutines
==========================================

Python's `async def` / `await` is syntactic sugar over generators.
Before asyncio existed (pre-3.4), Tornado and Twisted used generators directly.

Understanding the generator protocol is the key to understanding all async Python.

Topics:
  1. Generator basics — yield, __next__, send
  2. Two-way communication — yield as an expression
  3. yield from — delegating to sub-generators (PEP 380)
  4. Generator-based coroutines — the old async pattern
  5. How `await` translates to __await__ → __iter__ → yield
"""


# ---------------------------------------------------------------------------
# 1. Generator Basics
# ---------------------------------------------------------------------------

def explain_generator_protocol():
    """
    A generator function returns a generator object.
    The generator protocol has four operations:
      g.__next__()  — resume to next yield, return yielded value
      g.send(val)   — resume to next yield, the yield expression evaluates to val
      g.throw(exc)  — resume, raise exc at the current suspension point
      g.close()     — resume, raise GeneratorExit at the current suspension point
    """
    print("=" * 60)
    print("Generator Protocol")
    print("=" * 60)

    def counter(start: int, stop: int):
        """A simple generator that counts from start to stop."""
        print(f"  [generator] starting at {start}")
        for i in range(start, stop):
            print(f"  [generator] about to yield {i}")
            yield i
            print(f"  [generator] resumed after yielding {i}")
        print(f"  [generator] done")

    gen = counter(0, 3)
    print("\n  Calling next() three times:")
    for _ in range(3):
        val = next(gen)
        print(f"  [caller] received: {val}")

    try:
        next(gen)
    except StopIteration:
        print("  [caller] StopIteration — generator exhausted")


def explain_send():
    """
    `generator.send(value)` resumes the generator and makes the
    yield expression evaluate to `value` at the current suspension point.
    This turns generators into two-way communication channels.
    """
    print("\n" + "=" * 60)
    print("Generator send() — Two-Way Communication")
    print("=" * 60)

    def accumulator():
        """Receives values via send(), yields running total."""
        total = 0
        while True:
            value = yield total  # yield sends total out; send() puts value in
            if value is None:
                break
            total += value

    acc = accumulator()
    next(acc)  # Prime the generator (advance to first yield)

    print("\n  Sending values to accumulator generator:")
    for n in [10, 20, 5, 15]:
        running_total = acc.send(n)
        print(f"  Sent {n:3d} → running total: {running_total}")

    acc.close()


def explain_throw_and_close():
    """
    throw() and close() allow the caller to inject exceptions into the generator,
    enabling cleanup and cancellation — the basis for asyncio Task cancellation.
    """
    print("\n" + "=" * 60)
    print("Generator throw() and close() — Cancellation")
    print("=" * 60)

    def careful_worker():
        """A generator that cleans up when cancelled."""
        print("  [worker] starting, acquiring resource...")
        try:
            for i in range(100):
                print(f"  [worker] step {i}")
                yield i
        except GeneratorExit:
            print("  [worker] GeneratorExit received — cleaning up!")
        except ValueError as e:
            print(f"  [worker] ValueError received: {e} — handling error")
            yield -1  # send an error sentinel back
        finally:
            print("  [worker] releasing resource (finally block runs on throw/close)")

    gen = careful_worker()
    next(gen)
    next(gen)

    print("\n  Injecting ValueError via throw():")
    result = gen.throw(ValueError, "something went wrong")
    print(f"  [caller] generator returned: {result}")

    print("\n  Closing generator via close():")
    gen.close()


# ---------------------------------------------------------------------------
# 4. yield from — Delegation (PEP 380)
# ---------------------------------------------------------------------------

def explain_yield_from():
    """
    `yield from iterable` is not just `for x in iterable: yield x`.
    It properly delegates send() and throw() to the sub-generator.
    This is the foundation of `await` — `await x` is `yield from x.__await__()`.
    """
    print("\n" + "=" * 60)
    print("yield from — Generator Delegation (foundation of await)")
    print("=" * 60)

    def inner_coro():
        """A sub-coroutine that communicates with its caller."""
        print("  [inner] starting")
        received = yield "inner_waiting"
        print(f"  [inner] received: {received}")
        yield "inner_done"
        return "inner_result"

    def outer_coro():
        """Outer coroutine that delegates to inner via yield from."""
        print("  [outer] starting, delegating to inner...")
        result = yield from inner_coro()
        print(f"  [outer] inner returned: {result}")
        yield "outer_done"

    gen = outer_coro()

    print("\n  Step 1: advance to first yield (from inner):")
    val = next(gen)
    print(f"  [caller] yielded: {val}")

    print("\n  Step 2: send a value — goes all the way to inner_coro:")
    val = gen.send("hello from caller")
    print(f"  [caller] yielded: {val}")

    print("\n  Step 3: advance outer past inner_result handling:")
    try:
        val = next(gen)
        print(f"  [caller] yielded: {val}")
        next(gen)
    except StopIteration:
        print("  [caller] outer coroutine done")

    print("""
  Key insight: yield from properly propagates send() and throw() into the
  sub-generator. This is exactly what 'await' does:
    await expr  ≡  yield from expr.__await__()
    """)


# ---------------------------------------------------------------------------
# 5. Minimal Awaitable — Implementing __await__
# ---------------------------------------------------------------------------

class Awaitable:
    """
    The minimum an object needs to support `await expr` in an async def function.
    It must have an __await__ method that returns an iterator.

    This is how asyncio.Future.__await__ works: it yields itself,
    and the event loop checks if it's done on each iteration.
    """

    def __init__(self, value):
        self.value = value
        self._done = False

    def __await__(self):
        """
        This is called when someone does `await awaitable_obj`.
        We yield to signal suspension; when resumed, we return the value.
        """
        if not self._done:
            # Yield to the event loop (scheduler), signaling we're not ready yet
            yield self
        # When we get here, we've been resumed — return the result
        return self.value

    def resolve(self):
        """Mark this awaitable as ready to return its value."""
        self._done = True


def explain_await_protocol():
    """
    Show how __await__ works by running a minimal event loop manually.
    """
    print("\n" + "=" * 60)
    print("__await__ Protocol — How await Works")
    print("=" * 60)

    import asyncio

    async def fetch_data(awaitable: 'Awaitable') -> str:
        """Uses await to suspend until the awaitable is ready."""
        print("  [fetch_data] about to await...")
        result = await awaitable
        print(f"  [fetch_data] got result: {result}")
        return result

    a = Awaitable("the answer")

    async def main():
        # Schedule the coroutine
        task = asyncio.create_task(fetch_data(a))

        # While task is pending, do other work, then resolve the awaitable
        await asyncio.sleep(0)  # yield control
        print("  [main] resolving awaitable...")
        a.resolve()
        await asyncio.sleep(0)  # yield again so fetch_data can complete

        result = await task
        print(f"  [main] task result: {result}")

    asyncio.run(main())


# ---------------------------------------------------------------------------
# 6. Generator-Based Coroutine (Old Style — pre-3.5)
# ---------------------------------------------------------------------------

def explain_old_style_coroutine():
    """
    Before async/await (Python 3.5), coroutines were written with
    @asyncio.coroutine and yield from. Knowing this helps you understand
    legacy codebases and the underlying mechanics.
    """
    print("\n" + "=" * 60)
    print("Old-Style Generator-Based Coroutine (pre-3.5)")
    print("=" * 60)

    print("""
  Old style (Python 3.4):
    @asyncio.coroutine
    def fetch_url(url):
        response = yield from aiohttp.get(url)
        return (yield from response.text())

  New style (Python 3.5+):
    async def fetch_url(url):
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                return await response.text()

  They compile to essentially the same bytecode (YIELD_FROM / SEND).
  The async/await syntax just enforces that you only await awaitables,
  not arbitrary generators.

  For MicroPython (as of 1.22+), asyncio is available as 'asyncio'
  but the implementation is smaller — it lacks some edge cases of CPython asyncio.
  You can use generator-based coroutines directly for maximum compatibility.
    """)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    explain_generator_protocol()
    explain_send()
    explain_throw_and_close()
    explain_yield_from()
    explain_await_protocol()
    explain_old_style_coroutine()

    print("\n--- Summary ---")
    print("The generator protocol provides everything needed for coroutines:")
    print("  next()  → resume/advance the coroutine")
    print("  send()  → resume and pass a value in (how 'await' returns values)")
    print("  throw() → resume and inject an exception (how cancellation works)")
    print("  close() → terminate cleanly (calls finally blocks)")
    print("\nNext: 03_cooperative_scheduler.py — build a scheduler with these")
