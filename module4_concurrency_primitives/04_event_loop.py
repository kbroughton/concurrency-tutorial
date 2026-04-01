"""
Module 4, File 4: Build an Event Loop with I/O Multiplexing
============================================================

Our scheduler from file 3 only handles timers.
A real event loop also multiplexes I/O — it can wait for multiple
file descriptors to become readable/writable without blocking.

This file adds:
  1. selectors-based I/O multiplexing
  2. A real event loop that handles both timers and I/O
  3. Socket server/client demo using our event loop
  4. The exact structure of asyncio's event loop internals

This works on CPython and MicroPython (on ports with select.poll()).
"""

import heapq
import selectors
import socket
import time
import sys
import os
from typing import Generator, Any, Optional, Callable


# ---------------------------------------------------------------------------
# 1. I/O Request Types
# ---------------------------------------------------------------------------

class WaitReadable:
    """Yield this to wait until a file descriptor is readable."""
    def __init__(self, fd):
        self.fd = fd


class WaitWritable:
    """Yield this to wait until a file descriptor is writable."""
    def __init__(self, fd):
        self.fd = fd


class SleepRequest:
    def __init__(self, seconds: float):
        self.until = time.monotonic() + seconds


# ---------------------------------------------------------------------------
# 2. Event Loop with I/O Multiplexing
# ---------------------------------------------------------------------------

class EventLoop:
    """
    A working event loop that mirrors asyncio's structure:
      - A heap-based timer queue for scheduled callbacks
      - A selector for I/O readiness notifications
      - A ready queue for immediately runnable callbacks
      - A main loop that processes all three

    This is the direct equivalent of asyncio.BaseEventLoop.
    """

    def __init__(self):
        self._selector = selectors.DefaultSelector()
        self._timers: list[tuple[float, int, Generator, Any]] = []  # min-heap
        self._ready: list[tuple[Generator, Any]] = []
        self._counter = 0
        # fd → coroutine waiting for I/O on this fd
        self._waiting_read:  dict[int, Generator] = {}
        self._waiting_write: dict[int, Generator] = {}

    def spawn(self, coro: Generator) -> None:
        """Add a coroutine to the ready queue."""
        self._ready.append((coro, None))

    def run_until_complete(self) -> None:
        """Run until all coroutines are done."""
        while self._ready or self._timers or self._waiting_read or self._waiting_write:
            # 1. Process all immediately ready coroutines
            while self._ready:
                coro, value = self._ready.pop(0)
                self._step(coro, value)

            # 2. Calculate how long to wait in select()
            now = time.monotonic()
            timeout = None
            if self._timers:
                next_timer_at = self._timers[0][0]
                timeout = max(0.0, next_timer_at - now)

            # 3. Wait for I/O (or timeout)
            if self._selector.get_map() or timeout is not None:
                try:
                    events = self._selector.select(timeout=timeout or 0.001)
                except (OSError, ValueError):
                    events = []

                for key, mask in events:
                    fd = key.fd
                    if mask & selectors.EVENT_READ and fd in self._waiting_read:
                        coro = self._waiting_read.pop(fd)
                        self._selector.unregister(fd)
                        self._ready.append((coro, None))
                    if mask & selectors.EVENT_WRITE and fd in self._waiting_write:
                        coro = self._waiting_write.pop(fd)
                        self._selector.unregister(fd)
                        self._ready.append((coro, None))

            # 4. Process expired timers
            now = time.monotonic()
            while self._timers and self._timers[0][0] <= now:
                _, _, coro, value = heapq.heappop(self._timers)
                self._ready.append((coro, value))

        self._selector.close()

    def _step(self, coro: Generator, send_value: Any) -> None:
        """Advance a coroutine one step."""
        try:
            yielded = coro.send(send_value)
        except StopIteration:
            return
        except Exception as exc:
            print(f"  [event_loop] exception in coroutine: {exc!r}")
            return

        if isinstance(yielded, SleepRequest):
            delay = max(0.0, yielded.until - time.monotonic())
            heapq.heappush(self._timers, (time.monotonic() + delay, self._counter, coro, None))
            self._counter += 1

        elif isinstance(yielded, WaitReadable):
            fd = yielded.fd.fileno() if hasattr(yielded.fd, 'fileno') else yielded.fd
            self._waiting_read[fd] = coro
            try:
                self._selector.register(fd, selectors.EVENT_READ)
            except KeyError:
                pass  # already registered

        elif isinstance(yielded, WaitWritable):
            fd = yielded.fd.fileno() if hasattr(yielded.fd, 'fileno') else yielded.fd
            self._waiting_write[fd] = coro
            try:
                self._selector.register(fd, selectors.EVENT_WRITE)
            except KeyError:
                pass

        else:
            # Unknown yield — re-enqueue
            self._ready.append((coro, yielded))


# ---------------------------------------------------------------------------
# 3. Coroutine Helpers
# ---------------------------------------------------------------------------

def sleep(seconds: float) -> Generator:
    yield SleepRequest(seconds)


def wait_readable(sock) -> Generator:
    yield WaitReadable(sock)


def wait_writable(sock) -> Generator:
    yield WaitWritable(sock)


# ---------------------------------------------------------------------------
# 4. Echo Server / Client Demo
# ---------------------------------------------------------------------------

def echo_server(host: str, port: int, loop: EventLoop) -> Generator:
    """
    A coroutine-based TCP echo server.
    Accepts connections and echoes data back, all without blocking.
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(5)
    server_sock.setblocking(False)

    print(f"  [server] listening on {host}:{port}")

    # Handle 3 connections then stop
    for _ in range(3):
        yield from wait_readable(server_sock)
        conn, addr = server_sock.accept()
        conn.setblocking(False)
        print(f"  [server] connection from {addr}")

        # Spawn a coroutine to handle this connection
        loop.spawn(handle_client(conn))

    server_sock.close()
    print("  [server] stopped")


def handle_client(conn: socket.socket) -> Generator:
    """Coroutine to handle a single client connection."""
    try:
        yield from wait_readable(conn)
        data = conn.recv(1024)
        if data:
            print(f"  [server] received: {data.decode().strip()!r}")
            yield from wait_writable(conn)
            conn.sendall(b"ECHO: " + data)
    finally:
        conn.close()


def echo_client(host: str, port: int, message: str) -> Generator:
    """A non-blocking TCP client coroutine."""
    yield from sleep(0.05)  # wait for server to start

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)

    # Non-blocking connect — raises BlockingIOError, then wait for writable
    try:
        sock.connect((host, port))
    except (BlockingIOError, OSError):
        pass

    yield from wait_writable(sock)
    sock.sendall(message.encode())

    yield from wait_readable(sock)
    response = sock.recv(1024)
    print(f"  [client] received: {response.decode().strip()!r}")
    sock.close()


def demo_event_loop():
    print("=" * 60)
    print("Event Loop Demo: Non-Blocking TCP Echo Server")
    print("=" * 60)

    loop = EventLoop()

    HOST, PORT = "127.0.0.1", 19191

    loop.spawn(echo_server(HOST, PORT, loop))
    loop.spawn(echo_client(HOST, PORT, "Hello from client 1"))
    loop.spawn(echo_client(HOST, PORT, "Hello from client 2"))
    loop.spawn(echo_client(HOST, PORT, "Hello from client 3"))

    print()
    loop.run_until_complete()
    print("\n  All coroutines completed")


# ---------------------------------------------------------------------------
# 5. How asyncio.run() Maps to This
# ---------------------------------------------------------------------------

def explain_asyncio_mapping():
    print("\n" + "=" * 60)
    print("How asyncio Maps to Our Event Loop")
    print("=" * 60)
    print("""
  Our EventLoop          → asyncio.BaseEventLoop
  loop.spawn(coro)       → asyncio.ensure_future(coro) or loop.create_task(coro)
  loop.run_until_complete() → loop.run_forever() (with stop condition)
  sleep(n)               → asyncio.sleep(n)
  wait_readable(fd)      → loop.add_reader(fd, callback)
  wait_writable(fd)      → loop.add_writer(fd, callback)
  yield SleepRequest     → loop.call_later(delay, callback)

  The key difference: asyncio uses callbacks internally (not yield),
  then wraps them in Futures, which coroutines await.
  Our yield-based approach is simpler but functionally equivalent.

  asyncio.sleep(n) internals:
    async def sleep(delay):
        future = loop.create_future()
        loop.call_later(delay, future.set_result, None)
        await future   # suspends until future.set_result() is called

  This is the EXACT same mechanism as our SleepRequest, just with
  callbacks instead of direct yield.
    """)


# ---------------------------------------------------------------------------
# 6. MicroPython Adaptation
# ---------------------------------------------------------------------------

def explain_micropython_adaptation():
    print("=" * 60)
    print("MicroPython Adaptation")
    print("=" * 60)
    print("""
  MicroPython (uasyncio) is available on ESP32, RP2040, STM32.
  Key differences from CPython asyncio:

  1. select.poll() instead of selectors.DefaultSelector
     (no epoll on microcontrollers)

  2. machine.Timer for precise hardware timing
     Instead of heapq + time.monotonic(), use hardware timers

  3. No threading — pure cooperative only
     ISR (interrupt service routines) run in C, not Python
     Use asyncio.Event to signal from ISR to coroutine:
       def isr_handler(pin):
           event.set()   # called from C interrupt context

  4. Memory constraints — avoid closures, prefer itertools/generators
     Each coroutine frame uses ~128 bytes on RP2040

  Example MicroPython async blink:
    import asyncio
    from machine import Pin

    async def blink(pin, interval_ms):
        led = Pin(pin, Pin.OUT)
        while True:
            led.toggle()
            await asyncio.sleep_ms(interval_ms)

    async def main():
        asyncio.create_task(blink(25, 500))   # LED on pin 25
        asyncio.create_task(blink(26, 1000))  # LED on pin 26
        while True:
            await asyncio.sleep(1)

    asyncio.run(main())

  This is functionally identical to CPython asyncio but runs on 256KB RAM.
    """)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    demo_event_loop()
    explain_asyncio_mapping()
    explain_micropython_adaptation()
