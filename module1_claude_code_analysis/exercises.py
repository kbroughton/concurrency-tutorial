"""
Module 1 Exercises
==================

Solve each exercise, then run this file to check your answers.
Solutions are in exercises_solutions.py.
"""

import json
import threading
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Exercise 1
# ---------------------------------------------------------------------------
# The following hook state manager has a race condition.
# Fix it so concurrent calls never lose an update.
# Constraint: use only stdlib (no external packages).


class BuggyHookStateManager:
    def __init__(self, path: Path):
        self.path = path
        path.write_text(json.dumps({"calls": 0, "tools": []}))

    def record_tool_call(self, tool_name: str) -> None:
        data = json.loads(self.path.read_text())
        data["calls"] += 1
        data["tools"].append(tool_name)
        self.path.write_text(json.dumps(data))

import fcntl
from fcntl import LOCK_EX, LOCK_UN

class FixedHookStateManager:
    """
    TODO: Implement a thread- and process-safe version of BuggyHookStateManager.
    - record_tool_call must never lose an update under concurrent use
    - Use fcntl.flock for cross-process safety
    """

    def __init__(self, path: Path):
        self._lock = threading.Lock()
        self.path = path
        path.write_text(json.dumps({"calls": 0, "tools": []}))

    def record_tool_call(self, tool_name: str) -> None:
        with self._lock:
            fd = open(self.path, "r+")
            fcntl.flock(fd, LOCK_EX)
            data = json.loads(self.path.read_text())
            data["calls"] += 1
            data["tools"].append(tool_name)
            self.path.write_text(json.dumps(data))
            fcntl.flock(fd, LOCK_UN)


# ---------------------------------------------------------------------------
# Exercise 2
# ---------------------------------------------------------------------------
# The following function has a TOCTOU vulnerability.
# Rewrite it to be safe against symlink-swap attacks.

def vulnerable_load_config(config_path: Path) -> dict:
    if not config_path.exists():
        return {}
    with open(config_path) as f:
        return json.load(f)

import os
def safe_load_config(config_path: Path) -> dict:
    """
    TODO: Rewrite vulnerable_load_config to be TOCTOU-safe.
    Hint: use os.open with O_NOFOLLOW, then os.fdopen.
    Should raise OSError if path is a symlink.
    """
    fd = os.open(config_path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        return json.load(f)

# ---------------------------------------------------------------------------
# Exercise 3
# ---------------------------------------------------------------------------
# Write a hook runner that:
#   1. Runs a Python script as a subprocess
#   2. Passes a JSON payload via stdin
#   3. Reads JSON result from stdout
#   4. Enforces a configurable timeout
#   5. Returns {"exit_code": -1, "error": "timeout"} on timeout

import subprocess
import sys

def run_hook(script: str, payload: dict, timeout_s: float = 1.0) -> dict:
    """
    TODO: Implement a timeout-enforcing hook runner.
    The subprocess should receive json.dumps(payload) on stdin
    and return a JSON result on stdout.
    """
    input_bytes = json.dumps(payload).encode()
    with subprocess.Popen(
        [sys.executable, "-c", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        try:
            stdout, stderr = proc.communicate(input=input_bytes, timeout=timeout_s)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            return {"exit_code": -1, "error": "timeout"}
        if stdout:
            return json.loads(stdout)
        return {"exit_code": proc.returncode}

# ---------------------------------------------------------------------------
# Exercise 4 (stretch)
# ---------------------------------------------------------------------------
# Design a hook pipeline that runs hooks in parallel EXCEPT when a hook
# declares a dependency on a previous hook's output.
#
# Hooks declare dependencies via a class attribute:
#   class MyHook:
#       depends_on = ["SecurityReminderHook"]   # must run after these
#
# Implement run_hooks_with_dependencies(hooks, event, payload) -> list[dict]
# that respects these dependencies while maximising parallelism.

def run_hooks_with_dependencies(hooks: list, event: str, payload: dict) -> list[dict]:
    """
    TODO: Topological sort hooks by dependencies, then run independent
    groups in parallel using ThreadPoolExecutor.
    """
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Self-test runner
# ---------------------------------------------------------------------------

def test_exercise1():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "state.json"
        try:
            manager = FixedHookStateManager(path)
        except NotImplementedError:
            print("  Exercise 1: NOT IMPLEMENTED")
            return

        N = 30
        threads = [
            threading.Thread(target=manager.record_tool_call, args=(f"Tool{i}",))
            for i in range(N)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        data = json.loads(path.read_text())
        if data["calls"] == N:
            print(f"  Exercise 1: PASS (calls={data['calls']})")
        else:
            print(f"  Exercise 1: FAIL (expected {N}, got {data['calls']})")


def test_exercise2():
    import os
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        real_config = d / "config.json"
        secret = d / "secret.json"
        real_config.write_text(json.dumps({"safe": True}))
        secret.write_text(json.dumps({"password": "hunter2"}))

        symlink = d / "symlink_config.json"
        symlink.symlink_to(secret)

        try:
            result = safe_load_config(symlink)
            if "password" in result:
                print("  Exercise 2: FAIL — symlink followed, secret leaked")
            else:
                print("  Exercise 2: PARTIAL — symlink not followed but no error raised")
        except NotImplementedError:
            print("  Exercise 2: NOT IMPLEMENTED")
        except OSError:
            print("  Exercise 2: PASS — symlink correctly rejected with OSError")


def test_exercise3():
    import sys
    slow_script = "import time,json,sys\njson.dump({'ok':True},sys.stdout)\ntime.sleep(10)"
    fast_script = "import json,sys\npayload=json.load(sys.stdin)\njson.dump({'received':payload},sys.stdout)"

    try:
        result_fast = run_hook(fast_script, {"tool": "BashTool"}, timeout_s=2.0)
        result_slow = run_hook(slow_script, {}, timeout_s=0.5)
        if result_fast.get("received") and result_slow.get("error") == "timeout":
            print("  Exercise 3: PASS")
        else:
            print(f"  Exercise 3: FAIL — fast={result_fast}, slow={result_slow}")
    except NotImplementedError:
        print("  Exercise 3: NOT IMPLEMENTED")


if __name__ == "__main__":
    print("Module 1 Exercise Results:")
    test_exercise1()
    test_exercise2()
    test_exercise3()
    print("\nExercise 4 requires manual review — see exercises_solutions.py")
