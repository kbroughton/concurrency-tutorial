"""
Module 1, File 4: Hook Isolation Patterns
==========================================

Claude Code runs Python hooks as subprocesses.
This file explores WHY, the security properties gained, and the hidden risks.

Topics:
  - Process isolation vs. thread isolation
  - Inherited file descriptors (a common security hole)
  - Hook timeouts and the kill-signal race
  - Sandboxing hooks further with resource limits
"""

import os
import sys
import json
import signal
import subprocess
import resource
import tempfile
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# 1. Why Subprocesses, Not Threads?
# ---------------------------------------------------------------------------

def explain_isolation():
    """
    Print a comparison of thread vs. subprocess isolation properties.
    """
    print("=" * 60)
    print("Thread vs. Subprocess Isolation")
    print("=" * 60)
    properties = [
        ("Memory crash in handler", "Kills parent",     "Contained"),
        ("Shared global state",     "Yes (dangerous)",  "No"),
        ("GIL contention",          "Yes",              "No"),
        ("Kill/timeout",            "Difficult",        "os.kill(pid, SIGTERM)"),
        ("Separate UID/GID",        "No",               "Possible (setuid)"),
        ("Seccomp / pledge",        "No",               "Yes"),
        ("Startup overhead",        "~10µs",            "~20-50ms"),
        ("IPC cost",                "None (shared mem)","JSON over pipe"),
        ("File descriptor leak",    "Always shared",    "Closed if CLOEXEC set"),
    ]
    print(f"\n  {'Property':35s} {'Thread':20s} {'Subprocess':20s}")
    print(f"  {'-'*35} {'-'*20} {'-'*20}")
    for prop, thread, proc in properties:
        print(f"  {prop:35s} {thread:20s} {proc:20s}")

    print("""
Key insight: Claude Code chose the right tradeoff for a security tool.
A misbehaving hook (infinite loop, memory bomb, crash) cannot affect the
parent CLI process. The cost is JSON serialization on every hook call.
    """)


# ---------------------------------------------------------------------------
# 2. File Descriptor Leak Demo
# ---------------------------------------------------------------------------

def demo_fd_leak():
    """
    Subprocesses inherit open file descriptors unless CLOEXEC is set.
    This is a real security risk: a hook could read secrets from an
    inherited fd the parent opened (e.g., a config file with API keys).
    """
    print("=" * 60)
    print("File Descriptor Inheritance Demo")
    print("=" * 60)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as secret_file:
        secret_file.write("SECRET_API_KEY=anthropic_sk_..._hunter2\n")
        secret_path = secret_file.name

    # Open the secret file in the parent process (simulates having a config fd open)
    secret_fd = open(secret_path, 'r')
    fd_number = secret_fd.fileno()
    print(f"\n  Parent opened secret file at fd={fd_number}")

    # Subprocess WITHOUT close_fds=True inherits all parent fds
    leak_script = f"""
import os, sys
try:
    # Try to read parent's fd directly
    os.lseek({fd_number}, 0, 0)
    data = os.read({fd_number}, 200)
    print(f"LEAK: Read from inherited fd={fd_number}: {{data.decode()[:50]}}")
except OSError as e:
    print(f"Could not read fd={fd_number}: {{e}}")
"""
    print("\n  Without close_fds (vulnerable):")
    proc = subprocess.run(
        [sys.executable, "-c", leak_script],
        capture_output=True,
        close_fds=False,  # ← UNSAFE: inherits parent fds
    )
    output = proc.stdout.decode().strip()
    print(f"    {output}")

    print("\n  With close_fds=True (safe — Python default since 3.2):")
    proc_safe = subprocess.run(
        [sys.executable, "-c", leak_script],
        capture_output=True,
        close_fds=True,   # ← Default in Python 3.2+; explicit here for clarity
    )
    output_safe = proc_safe.stdout.decode().strip()
    print(f"    {output_safe}")

    secret_fd.close()
    os.unlink(secret_path)

    print("""
  Mitigation: subprocess.run(..., close_fds=True) — the default in Python 3.2+
  For extra safety, open sensitive fds with fcntl.FD_CLOEXEC:

      import fcntl
      fd = os.open(path, os.O_RDONLY)
      fcntl.fcntl(fd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)

  This ensures even if someone calls subprocess with close_fds=False,
  the fd is still closed in the child.
    """)


# ---------------------------------------------------------------------------
# 3. Hook Timeout and Signal Handling
# ---------------------------------------------------------------------------

SLOW_HOOK_SCRIPT = """
import time, sys, json
payload = json.load(sys.stdin)
# Malicious or buggy hook: sleeps forever
time.sleep(9999)
json.dump({"exit_code": 0}, sys.stdout)
"""


def run_hook_with_timeout(script: str, payload: dict, timeout_s: float = 2.0) -> dict:
    """
    Run a hook subprocess with a hard timeout.
    On timeout, send SIGTERM then SIGKILL if needed.
    """
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        stdout, stderr = proc.communicate(
            input=json.dumps(payload).encode(),
            timeout=timeout_s,
        )
        return json.loads(stdout) if stdout else {"exit_code": proc.returncode}
    except subprocess.TimeoutExpired:
        print(f"  Hook exceeded {timeout_s}s timeout — sending SIGTERM")
        proc.terminate()
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            print("  SIGTERM ignored — sending SIGKILL")
            proc.kill()
            proc.wait()
        return {"exit_code": -1, "error": "timeout"}
    except json.JSONDecodeError:
        return {"exit_code": -1, "error": "invalid JSON from hook"}


def demo_timeout():
    print("\n" + "=" * 60)
    print("Hook Timeout Handling")
    print("=" * 60)
    print("\n  Running a hook that sleeps forever (2s timeout)...")

    t0 = time.perf_counter()
    result = run_hook_with_timeout(SLOW_HOOK_SCRIPT, {"tool_name": "BashTool"}, timeout_s=2.0)
    elapsed = time.perf_counter() - t0

    print(f"  Result: {result}")
    print(f"  Time taken: {elapsed:.2f}s (capped at timeout)")
    print("\n  A production hook runner should also:")
    print("  - Log the timeout event for audit")
    print("  - Decide whether to block or allow the tool on hook timeout")
    print("  - Set resource limits (CPU, memory) before spawning")


# ---------------------------------------------------------------------------
# 4. Resource Limits (ulimit in Python)
# ---------------------------------------------------------------------------

def demo_resource_limits():
    """
    Show how to set resource limits on a subprocess to contain a rogue hook.
    Uses resource.setrlimit — only affects the calling process (inherit to child).
    """
    print("\n" + "=" * 60)
    print("Resource Limits for Hook Sandboxing")
    print("=" * 60)

    # Script that tries to allocate 200MB of memory
    memory_bomb_script = """
import sys
try:
    data = bytearray(200 * 1024 * 1024)  # 200 MB
    print(f"Allocated {len(data) // 1024 // 1024}MB — limit not enforced")
except MemoryError:
    print("MemoryError: allocation blocked by resource limit")
"""

    # macOS caveat: after fork(), the child inherits Python's dyld-inflated
    # virtual address space (often 100s of GB virtual due to shared library
    # cache + ASLR). Setting RLIMIT_AS to 64MB fails immediately because the
    # limit would be below the current VAS — the ValueError propagates out of
    # preexec_fn and kills the subprocess call entirely.
    # Fall back to RLIMIT_DATA (heap segment only) which avoids that problem,
    # but note macOS may not enforce it either — real memory containment on
    # macOS requires Seatbelt profiles or container isolation (bubblewrap),
    # which is exactly why Trail of Bits' claude-code-config uses those tools
    # rather than relying on Python's resource module.
    _rlimit_as_enforced = sys.platform != "darwin"

    def preexec_with_limits():
        """Called in child process before exec — sets resource limits."""
        limit_bytes = 64 * 1024 * 1024
        try:
            # Linux: limits total virtual address space — works reliably.
            # macOS: fails (current VAS >> limit_bytes); see comment above.
            resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))
        except (ValueError, OSError):
            # macOS fallback: limit heap/data segment only
            try:
                resource.setrlimit(resource.RLIMIT_DATA, (limit_bytes, limit_bytes))
            except (ValueError, OSError):
                pass  # neither enforceable; demo shows unsandboxed behavior
        # CPU limit works on both platforms
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))

    print("\n  Running memory bomb without limits:")
    proc = subprocess.run([sys.executable, "-c", memory_bomb_script], capture_output=True)
    print(f"    {proc.stdout.decode().strip()}")

    print("\n  Running memory bomb with 64MB RLIMIT_AS:")
    proc_limited = subprocess.run(
        [sys.executable, "-c", memory_bomb_script],
        capture_output=True,
        preexec_fn=preexec_with_limits,
    )
    output = proc_limited.stdout.decode().strip() or proc_limited.stderr.decode().strip()
    print(f"    {output or f'Process killed (exit code {proc_limited.returncode})'}")

    if not _rlimit_as_enforced:
        print("""
  *** macOS note: RLIMIT_AS is not effective here. Python's virtual address
  space after fork() already exceeds any practical limit due to dyld shared
  library cache. On macOS, memory containment requires Seatbelt sandbox
  profiles or OCI containers (bubblewrap on Linux). On Linux this demo
  shows the allocation blocked as expected.
        """)

    print("""
  Other useful resource limits for hook sandboxing:
    RLIMIT_NOFILE  — max open file descriptors
    RLIMIT_NPROC   — max child processes (prevent fork bombs)
    RLIMIT_FSIZE   — max file size the hook can write
    RLIMIT_CPU     — max CPU seconds (works on both Linux and macOS)
    """)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    explain_isolation()
    demo_fd_leak()
    demo_timeout()
    demo_resource_limits()

    print("\n--- Module 1 Complete ---")
    print("You can now:")
    print("  - Explain why Claude Code uses subprocess isolation for hooks")
    print("  - Identify fd leaks, TOCTOU, and lost-update races in hook code")
    print("  - Apply three fix strategies (flock, atomic rename, SQLite)")
    print("  - Sandbox hooks with resource limits and timeouts")
