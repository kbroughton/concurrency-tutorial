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
#
# NOTE ON PRIVILEGE ESCALATION:
#
# A TOCTOU attack only escalates privilege when the check and the use run at
# DIFFERENT trust levels, and a symlink can bridge them. The generic example
# below illustrates the race mechanics, but the attacker already owns the
# temp directory — they could read the "secret" file directly. No privilege
# delta exists in the demo itself.
#
# The Claude-specific scenarios where a genuine trust boundary is crossed:
#
# 1. HOOK EXECUTION TRUST (most impactful)
#    Claude discovers scripts in .claude/hooks/ and executes them as trusted
#    subprocesses with full user permissions. A sandboxed agent has write
#    access to the workspace but NOT to ~/.claude/hooks/. If a hook sources
#    a file from the workspace:
#
#      #!/bin/bash
#      source "${PROJECT_DIR}/.claude/hook_config.sh"   # ← reads workspace
#
#    The sandboxed agent writes malicious content to hook_config.sh.
#    Claude executes the hook (trusted); the hook runs attacker content.
#    The agent crossed from untrusted workspace → trusted execution context.
#
# 2. SETTINGS INJECTION IN AGENT TEAMS — NOT a TOCTOU scenario
#    If teammate A is on the same machine and user as teammate B (the normal
#    agent teams setup), A can directly overwrite B's .claude/settings.json
#    without racing anything. TOCTOU adds nothing when the attacker already
#    has persistent write access — just overwrite directly.
#    This is a filesystem isolation failure, not a race condition.
#    The fix is OS-level separation (different UIDs, MAC policy) not O_NOFOLLOW.
#
# 3. SEMANTIC TRUST BOUNDARY (data → instruction crossing)
#    Claude checks a file is valid JSON before including it in a trusted
#    context (e.g., project memory, CLAUDE.md). An agent swaps the file
#    for one containing prompt injection between the validation check and
#    the read. The validated-clean file is now treated as trusted instruction.
#
# The demo below is a correct illustration of TOCTOU mechanics.
# See module2/05_malicious_teammate.py for scenario 2 in a team context.

class VulnerableFileProcessor:
    """
    Check-then-act pattern: check if file exists, then read it.
    Between the check and the read, the file can be replaced.

    Generic TOCTOU illustration — see module docstring above for
    the Claude-specific scenarios where this crosses a real trust boundary.
    """

    def process_config(self, config_path: Path) -> Optional[dict]:
        """
        VULNERABLE: Between exists() and open(), path can become a symlink
        pointing outside the intended directory.
        """
        # TIME-OF-CHECK
        if not config_path.exists():
            return None

        # ← ATTACK WINDOW: path is replaced with a symlink

        # TIME-OF-USE
        with open(config_path) as f:   # follows symlink, reads unintended target
            return json.load(f)


def demo_toctou():
    """
    Demonstrate the TOCTOU window mechanics.
    The 'attacker' and 'secret' are in the same temp dir here — no real
    privilege escalation. See the module docstring for Claude-specific
    scenarios where the trust boundary is genuine.
    """
    print("\n" + "=" * 60)
    print("TOCTOU (Time-of-Check / Time-of-Use) — Mechanics Demo")
    print("(Generic illustration; see docstring for Claude-specific trust boundaries)")
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
  Mechanics confirmed. Note on privilege delta:
    The demo attacker already owns the temp directory, so they could read
    secret.json directly — no real privilege escalation here.

    TOCTOU is only more powerful than direct write when there is a CHECK
  that the malicious content cannot pass. The race presents clean content
  to the check and swaps malicious content in before the use.
  If direct write is already available, the check doesn't matter.

  Real Claude scenarios where TOCTOU IS genuinely needed:
    - Hook content scanner: Claude validates hook script content before
      executing (passes injection check on clean content, swap happens
      after scan, malicious content runs). Direct write fails the scanner;
      TOCTOU bypasses it.
    - Data→instruction re-read: file is read as untrusted and validated
      clean, then re-read (or re-trusted) as an instruction source.
      Swap between the two reads means validation sees clean, execution
      sees malicious.

  NOT a TOCTOU scenario:
    - Agent teams settings file: same user/machine, direct overwrite
      works fine. This is a filesystem isolation gap, not a race.

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
