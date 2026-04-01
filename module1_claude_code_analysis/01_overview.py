"""
Module 1, File 1: Claude Code Architecture Overview
====================================================

This file walks through the concurrency-relevant architecture of Claude Code's
public Python hooks. Run it to see timing comparisons between sequential and
parallel approaches.

Key concepts:
  - Hook lifecycle (PreToolUse → tool → PostToolUse)
  - Sequential vs. parallel hook evaluation
  - The cost of process isolation
"""

import subprocess
import sys
import time
import json
import os
import concurrent.futures


# ---------------------------------------------------------------------------
# 1. Simulated Hook Pipeline (Sequential — mirrors how Claude Code works)
# ---------------------------------------------------------------------------

HOOK_EVENTS = ["PreToolUse", "PostToolUse", "Stop", "UserPromptSubmit"]


def run_hook_sequential(hooks: list[dict], event: str, payload: dict) -> list[dict]:
    """
    Mimic Claude Code's sequential hook pipeline.
    Each hook receives the output of the previous one (JSON chain).
    """
    results = []
    current_payload = payload.copy()

    for hook in hooks:
        # In the real system each hook is a subprocess. We simulate with a callable.
        start = time.perf_counter()
        result = hook["fn"](event, current_payload)
        elapsed = time.perf_counter() - start

        results.append({"hook": hook["name"], "result": result, "elapsed_ms": elapsed * 1000})

        # A hook returning exit code 2 blocks the tool from running
        if result.get("exit_code") == 2:
            print(f"  [BLOCKED] Hook '{hook['name']}' blocked the operation")
            break

        # Pass enriched payload to next hook
        current_payload.update(result.get("output", {}))

    return results


def run_hook_parallel(hooks: list[dict], event: str, payload: dict) -> list[dict]:
    """
    Alternative: run all hooks in parallel, then merge results.
    Trade-off: hooks cannot depend on each other's output, but throughput is better.
    This is a design change Claude Code could make for independent hooks.
    """
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(hooks)) as executor:
        futures = {
            executor.submit(hook["fn"], event, payload.copy()): hook
            for hook in hooks
        }
        for future in concurrent.futures.as_completed(futures):
            hook = futures[future]
            result = future.result()
            results.append({"hook": hook["name"], "result": result})

    # With parallel hooks, blocking requires consensus: any hook can block
    blocked = [r for r in results if r["result"].get("exit_code") == 2]
    if blocked:
        print(f"  [BLOCKED] {len(blocked)} hook(s) blocked the operation")
    return results


# ---------------------------------------------------------------------------
# 2. Example Hooks (simulating real Claude Code hook behaviour)
# ---------------------------------------------------------------------------

def security_reminder_hook(event: str, payload: dict) -> dict:
    """
    Simulates the security-reminder Python hook.
    Reads/writes a state file — the concurrency-unsafe part.
    """
    time.sleep(0.01)  # simulate file I/O
    dangerous_tools = {"BashTool", "WriteTool", "EditTool"}
    tool = payload.get("tool_name", "")

    if event == "PreToolUse" and tool in dangerous_tools:
        return {"exit_code": 0, "output": {"security_checked": True}}
    return {"exit_code": 0, "output": {}}


def rule_evaluation_hook(event: str, payload: dict) -> dict:
    """
    Simulates evaluating a set of security rules against the tool invocation.
    In the real code: glob all *.mdc files, compile regexes, check transcript.
    """
    time.sleep(0.015)  # simulate rule loading + regex evaluation
    return {"exit_code": 0, "output": {"rules_checked": 42}}


def audit_log_hook(event: str, payload: dict) -> dict:
    """Appends to an audit log — demonstrates unprotected file append."""
    time.sleep(0.005)
    return {"exit_code": 0, "output": {"logged": True}}


HOOKS = [
    {"name": "security_reminder", "fn": security_reminder_hook},
    {"name": "rule_evaluation",   "fn": rule_evaluation_hook},
    {"name": "audit_log",         "fn": audit_log_hook},
]

SAMPLE_PAYLOAD = {"tool_name": "BashTool", "command": "ls -la", "session_id": "abc123"}


# ---------------------------------------------------------------------------
# 3. Benchmark: Sequential vs. Parallel Hook Execution
# ---------------------------------------------------------------------------

def benchmark_hooks():
    print("=" * 60)
    print("Hook Pipeline: Sequential vs. Parallel")
    print("=" * 60)

    # Sequential
    t0 = time.perf_counter()
    sequential_results = run_hook_sequential(HOOKS, "PreToolUse", SAMPLE_PAYLOAD)
    sequential_time = time.perf_counter() - t0

    print(f"\nSequential execution: {sequential_time*1000:.1f}ms")
    for r in sequential_results:
        print(f"  {r['hook']:25s} {r['elapsed_ms']:.1f}ms")

    # Parallel
    t0 = time.perf_counter()
    parallel_results = run_hook_parallel(HOOKS, "PreToolUse", SAMPLE_PAYLOAD)
    parallel_time = time.perf_counter() - t0

    print(f"\nParallel execution:  {parallel_time*1000:.1f}ms")
    print(f"\nSpeedup: {sequential_time/parallel_time:.1f}x")
    print(
        "\nNote: Parallel hooks lose ordering guarantees and output chaining.\n"
        "Claude Code's sequential design is safer for dependent hooks."
    )


# ---------------------------------------------------------------------------
# 4. Subprocess Isolation Demo
# ---------------------------------------------------------------------------

def demo_subprocess_isolation():
    """
    Show how Claude Code spawns hooks as subprocesses.
    Key property: a crashing or malicious hook cannot corrupt the parent process.
    """
    print("\n" + "=" * 60)
    print("Subprocess Isolation")
    print("=" * 60)

    hook_script = """
import sys, json, time
payload = json.load(sys.stdin)
# Simulate a slow hook
time.sleep(0.02)
result = {"exit_code": 0, "output": {"processed": True, "tool": payload.get("tool_name")}}
json.dump(result, sys.stdout)
"""
    payload = json.dumps(SAMPLE_PAYLOAD).encode()

    t0 = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, "-c", hook_script],
        input=payload,
        capture_output=True,
        timeout=5,
    )
    elapsed = time.perf_counter() - t0

    if proc.returncode == 0:
        result = json.loads(proc.stdout)
        print(f"  Hook subprocess completed in {elapsed*1000:.1f}ms")
        print(f"  Result: {result}")
    else:
        print(f"  Hook subprocess failed: {proc.stderr.decode()}")

    print("\n  Security properties of subprocess isolation:")
    print("  - Crash in hook does not kill parent CLI process")
    print("  - Hook cannot access parent's memory or file descriptors (unless inherited)")
    print("  - Hook can be killed/timed out without affecting parent")
    print("  - But: shared filesystem still requires locking!")


# ---------------------------------------------------------------------------
# 5. What Python Async Would Look Like in This Architecture
# ---------------------------------------------------------------------------

async def async_hook_pipeline_sketch():
    """
    Sketch of what an async hook pipeline could look like.
    Not how Claude Code works today — but worth understanding for interviews.
    """
    import asyncio

    async def async_hook(name: str, delay: float, payload: dict) -> dict:
        await asyncio.sleep(delay)  # non-blocking I/O wait
        return {"hook": name, "exit_code": 0}

    # Run hooks concurrently while preserving order of results
    hooks = [
        async_hook("security_reminder", 0.010, SAMPLE_PAYLOAD),
        async_hook("rule_evaluation",   0.015, SAMPLE_PAYLOAD),
        async_hook("audit_log",         0.005, SAMPLE_PAYLOAD),
    ]

    # asyncio.gather runs all coroutines concurrently
    results = await asyncio.gather(*hooks)
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    benchmark_hooks()
    demo_subprocess_isolation()

    import asyncio
    print("\n" + "=" * 60)
    print("Async Hook Pipeline (hypothetical)")
    print("=" * 60)
    results = asyncio.run(async_hook_pipeline_sketch())
    for r in results:
        print(f"  {r}")

    print("\n--- Key Takeaways ---")
    print("1. Claude Code hooks run sequentially for ordering guarantees")
    print("2. Subprocess isolation adds safety but increases spawn cost (~20-50ms per hook)")
    print("3. async gather() gives concurrency without threads — better for I/O-bound hooks")
    print("4. The architectural choice (sequential subprocess) is defensible for security tools")
