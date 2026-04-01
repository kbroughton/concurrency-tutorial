"""
Module 1, File 2: The State-File Race Condition
================================================

Claude Code's security-reminder hook persists state to:
    ~/.claude/security_warnings_state_{session_id}.json

When multiple sessions run simultaneously (common: tmux splits, parallel terminals,
CI pipelines) they all read/modify/write this file with NO locking.

This file reproduces the race using threads, then shows you how to detect it.

Run it and observe the "lost update" problem in action.
"""

import json
import os
import tempfile
import threading
import time
import random
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# 1. The Vulnerable Pattern (mirrors the real hook code)
# ---------------------------------------------------------------------------

class VulnerableStateStore:
    """
    Mirrors the read-modify-write pattern in Claude Code's security hook.
    No locking: multiple concurrent writers will lose updates.
    """

    def __init__(self, path: Path):
        self.path = path
        if not self.path.exists():
            self.path.write_text(json.dumps({"warnings_shown": [], "count": 0}))

    def record_warning(self, warning_id: str) -> None:
        """Read → modify → write. UNSAFE for concurrent use."""
        try:
            # Step 1: Read current state
            data = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return  # torn read — the race manifests as a lost update

        # Simulate the small window between read and write
        # In production this is microseconds — but with many sessions it's enough
        time.sleep(random.uniform(0.001, 0.005))

        # Step 2: Modify
        if warning_id not in data["warnings_shown"]:
            data["warnings_shown"].append(warning_id)
            data["count"] += 1

        # Step 3: Write back — LAST WRITER WINS, others are silently dropped
        self.path.write_text(json.dumps(data, indent=2))

    def get_count(self) -> int:
        data = json.loads(self.path.read_text())
        return data["count"]


def demo_race_condition():
    """
    Launch N threads all writing to the same state file.
    With proper locking, final count should equal N.
    Without locking, we observe lost updates.
    """
    print("=" * 60)
    print("Race Condition Demo: Vulnerable State Store")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        state_file = Path(tmpdir) / "security_state.json"
        store = VulnerableStateStore(state_file)

        NUM_THREADS = 20
        threads = []

        for i in range(NUM_THREADS):
            t = threading.Thread(
                target=store.record_warning,
                args=(f"warning_{i}",),
                name=f"session_{i}",
            )
            threads.append(t)

        # Launch all at once to maximize contention
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        final_count = store.get_count()
        print(f"\n  Threads launched:     {NUM_THREADS}")
        print(f"  Expected count:       {NUM_THREADS}")
        print(f"  Actual count:         {final_count}")

        if final_count < NUM_THREADS:
            lost = NUM_THREADS - final_count
            print(f"  Lost updates:         {lost}  ← RACE CONDITION DEMONSTRATED")
        else:
            print("  No lost updates this run (try again — it's non-deterministic)")

        # Show the actual state
        data = json.loads(state_file.read_text())
        print(f"\n  Warnings recorded: {len(data['warnings_shown'])} of {NUM_THREADS}")


# ---------------------------------------------------------------------------
# 2. The Debug Log Race (append without lock)
# ---------------------------------------------------------------------------

class VulnerableLogger:
    """
    Mirrors the unprotected append-to-log pattern.
    Multiple writers can interleave partial writes.
    """

    def __init__(self, path: Path):
        self.path = path

    def log(self, message: str) -> None:
        """Append to log file — UNSAFE. Two writers can interleave bytes."""
        with open(self.path, "a") as f:
            # Without flush+fsync between write calls, the OS buffer can
            # interleave writes from concurrent processes/threads sharing the fd
            f.write(f"{message}\n")


def demo_log_interleaving():
    """Show that concurrent log appends can produce garbled output."""
    print("\n" + "=" * 60)
    print("Log Interleaving Demo")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "debug.log"
        logger = VulnerableLogger(log_path)
        NUM_THREADS = 10
        LINES_PER_THREAD = 5

        def write_lines(thread_id: int):
            for i in range(LINES_PER_THREAD):
                # A "line" that should never be split
                msg = f"[session_{thread_id:02d}] event_{i}_{'x'*40}"
                logger.log(msg)

        threads = [
            threading.Thread(target=write_lines, args=(i,))
            for i in range(NUM_THREADS)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        lines = log_path.read_text().splitlines()
        expected = NUM_THREADS * LINES_PER_THREAD
        print(f"\n  Expected lines: {expected}")
        print(f"  Actual lines:   {len(lines)}")

        # Check for lines that don't start with '[session_' (truncated/interleaved)
        malformed = [l for l in lines if not l.startswith("[session_")]
        if malformed:
            print(f"  Malformed lines: {len(malformed)}  ← INTERLEAVING DETECTED")
            for m in malformed[:3]:
                print(f"    '{m[:60]}'")
        else:
            print("  All lines well-formed (Python's GIL protected us here)")
            print("  Note: this interleaving is more visible with multiprocessing")


# ---------------------------------------------------------------------------
# 3. TOCTOU (Time-of-Check / Time-of-Use) Race
# ---------------------------------------------------------------------------

class VulnerableFileProcessor:
    """
    Check-then-act pattern: check if file exists, then read it.
    Between the check and the read, the file can be replaced.
    This is a TOCTOU vulnerability.
    """

    def process_config(self, config_path: Path) -> Optional[dict]:
        """
        VULNERABLE: An attacker with filesystem access could swap config_path
        with a symlink to a sensitive file between the exists() check and open().
        """
        # TIME-OF-CHECK
        if not config_path.exists():
            return None

        # ← ATTACK WINDOW: attacker replaces config_path with symlink to /etc/passwd

        # TIME-OF-USE
        with open(config_path) as f:   # now reads symlink target, not config
            return json.load(f)


def demo_toctou():
    """Demonstrate the TOCTOU window with a thread that swaps the file."""
    print("\n" + "=" * 60)
    print("TOCTOU (Time-of-Check / Time-of-Use) Demo")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        config_path = tmpdir / "hook_config.json"
        secret_path = tmpdir / "secret.json"
        secret_path.write_text(json.dumps({"secret_key": "hunter2"}))

        processor = VulnerableFileProcessor()
        swap_count = [0]
        read_count = [0]
        toctou_hit = [False]

        def attacker_thread():
            """Rapidly alternate: real config ↔ symlink to secret."""
            for _ in range(500):
                # Place real config
                config_path.write_text(json.dumps({"safe": True}))
                time.sleep(0.0001)
                # Swap to symlink
                try:
                    config_path.unlink()
                    config_path.symlink_to(secret_path)
                    swap_count[0] += 1
                except FileNotFoundError:
                    pass
                time.sleep(0.0001)
                try:
                    config_path.unlink()
                except FileNotFoundError:
                    pass

        def victim_thread():
            """Repeatedly read config, looking for secret leak."""
            for _ in range(500):
                try:
                    result = processor.process_config(config_path)
                    if result and "secret_key" in result:
                        toctou_hit[0] = True
                        read_count[0] += 1
                except (json.JSONDecodeError, IsADirectoryError, OSError):
                    pass

        # Ensure config exists initially
        config_path.write_text(json.dumps({"safe": True}))

        attacker = threading.Thread(target=attacker_thread)
        victim = threading.Thread(target=victim_thread)

        attacker.start()
        victim.start()
        attacker.join()
        victim.join()

        print(f"\n  File swaps by attacker: {swap_count[0]}")
        if toctou_hit[0]:
            print(f"  Secret leaked {read_count[0]} times  ← TOCTOU EXPLOITED")
        else:
            print("  No leak this run (race window is narrow — try running again)")

        print("""
  The fix: use os.open() with O_NOFOLLOW to refuse symlinks, or
  open the file first and validate *after* — never check-then-open.
        """)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    demo_race_condition()
    demo_log_interleaving()
    demo_toctou()

    print("\n--- Summary ---")
    print("Three concurrency vulnerabilities demonstrated:")
    print("1. Lost updates (read-modify-write without lock)")
    print("2. Log interleaving (concurrent append without coordination)")
    print("3. TOCTOU (check-then-act on filesystem objects)")
    print("\nNext: module 03_fixing_races.py — three fix strategies")
