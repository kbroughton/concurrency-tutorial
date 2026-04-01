# Module 4: Build Your Own Concurrency Library

## The Goal

Understand concurrency deeply enough that you could implement it yourself.
This matters for:
- **IoT / embedded** environments (MicroPython, CircuitPython) that lack asyncio
- **Type-checked** environments (mypy strict mode) where asyncio's dynamic typing causes friction
- **Constrained runtimes** where asyncio's overhead (event loop, task scheduler, 500KB+ overhead) is too large
- **Interviews** — understanding the primitives proves you understand what asyncio actually does

---

## What asyncio Actually Is

asyncio is built on top of exactly three CPython primitives:

```
1. Generator protocol  (yield / send / throw / close)
2. OS I/O multiplexing (select / poll / epoll / kqueue)
3. Heap-based timer queue (heapq with monotonic clock)
```

Everything else — Tasks, Futures, Locks, Semaphores, Queues — is built from these.

---

## CPython Concurrency Primitives

### Thread-level (OS threads via pthreads/WinAPI)
```
threading.Thread        → wraps os.pthread_create
threading.Lock          → wraps pthread_mutex
threading.Condition     → wraps pthread_cond
threading.Semaphore     → counting semaphore built on Lock + Condition
threading.Event         → binary semaphore built on Condition
threading.Barrier       → generalization of Event for N threads
```

### Cooperative (single-threaded, explicit yield points)
```
Generator.__next__()    → resumes coroutine to next yield
Generator.send(value)   → resumes coroutine, passing a value
Generator.throw(exc)    → resumes coroutine, raising an exception
Generator.close()       → sends GeneratorExit
```

### OS I/O Multiplexing
```
select.select()         → POSIX select (fd limit: 1024)
select.poll()           → POSIX poll (no fd limit)
select.epoll()          → Linux epoll (efficient for 10k+ fds)
select.kqueue()         → BSD/macOS kqueue
selectors.DefaultSelector → picks the best available for the platform
```

---

## MicroPython Notes

MicroPython targets microcontrollers with 256KB–2MB RAM.
It implements a subset of CPython's stdlib including:
- `asyncio` (uasyncio) — a simplified event loop
- `threading` — NOT available on most ports (single-threaded)
- `machine` module — hardware I/O (GPIO, I2C, SPI, UART)

For a constrained IoT build, you'd implement:
1. A cooperative scheduler using generators (no threading needed)
2. Timer-based wakeups using `machine.Timer`
3. I/O polling via `select.poll()` (available on ESP32, RP2040)

---

## Files in This Module

| File | Topic |
|------|-------|
| `01_cpython_internals.py` | GIL, PyObject, thread state, bytecode |
| `02_generators_as_coroutines.py` | yield-from, send(), throw() — the foundation |
| `03_cooperative_scheduler.py` | A working cooperative scheduler from scratch |
| `04_event_loop.py` | Add I/O multiplexing to the scheduler |
| `05_futures_and_tasks.py` | Futures, Tasks, gather() from scratch |
| `06_sync_primitives.py` | Lock, Semaphore, Event, Queue from scratch |
| `07_micropython_sketch.py` | Constrained IoT adaptation |
| `exercises.py` | Build your own: challenges |

---

## Learning Path

```
Generators → Coroutines → Scheduler → Event Loop → Futures → Full async lib
```

By the end of this module you will understand exactly what happens when Python
executes `await asyncio.sleep(1.0)`.
