"""
Module 2, File 2: Multi-Agent Workspace Conflicts
==================================================

When multiple Claude Code agents operate on the same workspace directory,
they compete for the same files. This module simulates realistic conflict
scenarios and shows coordination strategies.

Scenarios:
  1. Two agents writing to the same plan file (lost update)
  2. Agent reads a file another agent is mid-write (torn read)
  3. Optimistic concurrency control (detect-and-retry)
  4. File-based mutex for agent coordination
"""

import fcntl
import hashlib
import json
import os
import tempfile
import threading
import time
import random
from pathlib import Path
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# 1. Lost Update: Two Agents Editing the Same Plan File
# ---------------------------------------------------------------------------

def demo_lost_update():
    """
    Simulate two agents reading, modifying, and writing a shared plan.md file.
    Without coordination, the second write overwrites the first agent's changes.
    """
    print("=" * 60)
    print("Multi-Agent Lost Update: plan.md")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as workspace:
        plan_path = Path(workspace) / "plan.md"
        plan_path.write_text("# Plan\n- Step 1: Research\n")

        results = {"agent_a_wrote": None, "agent_b_wrote": None, "final": None}

        def agent_a():
            # Agent A adds a step
            time.sleep(0.01)
            content = plan_path.read_text()
            time.sleep(0.03)  # slow processing — large window for conflict
            new_content = content + "- Step 2: Implement (Agent A)\n"
            plan_path.write_text(new_content)
            results["agent_a_wrote"] = new_content

        def agent_b():
            # Agent B also adds a step (concurrently with Agent A)
            time.sleep(0.01)
            content = plan_path.read_text()
            time.sleep(0.02)
            new_content = content + "- Step 3: Test (Agent B)\n"
            plan_path.write_text(new_content)
            results["agent_b_wrote"] = new_content

        threads = [threading.Thread(target=agent_a), threading.Thread(target=agent_b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        results["final"] = plan_path.read_text()

        print("\n  Agent A intended to write:")
        for line in results["agent_a_wrote"].splitlines():
            print(f"    {line}")

        print("\n  Agent B intended to write:")
        for line in results["agent_b_wrote"].splitlines():
            print(f"    {line}")

        print("\n  Actual file content (one agent's changes are GONE):")
        for line in results["final"].splitlines():
            print(f"    {line}")


# ---------------------------------------------------------------------------
# 2. Torn Read: Reading a File Mid-Write
# ---------------------------------------------------------------------------

def demo_torn_read():
    """
    If Agent A is writing a large JSON file and Agent B reads mid-write,
    B sees a partially-written file — potentially invalid JSON or inconsistent state.
    """
    print("\n" + "=" * 60)
    print("Torn Read: Reading During a Write")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as workspace:
        data_path = Path(workspace) / "agent_state.json"
        torn_reads = [0]
        total_reads = [0]

        # Initial valid state
        data_path.write_text(json.dumps({"status": "idle", "tasks": []}))

        def writer_agent():
            """Agent A: repeatedly writes large JSON state."""
            for i in range(50):
                # Simulate a large state object
                state = {
                    "status": "working",
                    "iteration": i,
                    "tasks": [f"task_{j}" for j in range(100)],
                    "metadata": {"timestamp": time.time(), "agent": "A"},
                }
                # DANGEROUS: write() is not atomic for large files
                data_path.write_text(json.dumps(state, indent=2))
                time.sleep(0.002)

        def reader_agent():
            """Agent B: repeatedly reads state, looks for inconsistencies."""
            for _ in range(200):
                total_reads[0] += 1
                try:
                    content = data_path.read_text()
                    json.loads(content)  # This will raise if torn
                except json.JSONDecodeError:
                    torn_reads[0] += 1
                time.sleep(0.001)

        threads = [
            threading.Thread(target=writer_agent),
            threading.Thread(target=reader_agent),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        print(f"\n  Total reads: {total_reads[0]}")
        print(f"  Torn reads (invalid JSON): {torn_reads[0]}")
        if torn_reads[0] > 0:
            print("  ← File was read mid-write, producing corrupt JSON")
        else:
            print("  (No torn reads this run — kernel buffering protected us)")

        print("""
  Fix: use write-to-temp + atomic rename:
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(state))
    os.rename(tmp, path)           # atomic on POSIX
        """)


# ---------------------------------------------------------------------------
# 3. Optimistic Concurrency Control
# ---------------------------------------------------------------------------

@dataclass
class VersionedDocument:
    """
    Document with a content hash as its version.
    Supports optimistic locking: read → modify → conditional write.
    """
    path: Path

    def read(self) -> tuple[str, str]:
        """Return (content, version_hash)."""
        content = self.path.read_text()
        version = hashlib.sha256(content.encode()).hexdigest()[:8]
        return content, version

    def conditional_write(self, new_content: str, expected_version: str) -> bool:
        """
        Write only if the file version matches expected_version.
        Returns True on success, False on conflict (another agent wrote first).
        Uses a lock file to make the check-and-write atomic.
        """
        lock_path = Path(str(self.path) + ".lock")
        with open(lock_path, "w") as lock_fd:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                current_content, current_version = self.read()
                if current_version != expected_version:
                    return False  # Conflict: someone else wrote
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text(new_content)
                os.rename(tmp, self.path)
                return True
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)


def demo_optimistic_concurrency():
    """
    Both agents attempt to append to the same document.
    The loser retries after reading the updated version.
    """
    print("\n" + "=" * 60)
    print("Optimistic Concurrency Control")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as workspace:
        doc_path = Path(workspace) / "shared_notes.md"
        doc_path.write_text("# Shared Notes\n")
        doc = VersionedDocument(doc_path)

        write_counts = {"success": 0, "retry": 0, "fail": 0}

        def agent_write(agent_id: str, message: str, max_retries: int = 5):
            for attempt in range(max_retries):
                content, version = doc.read()
                time.sleep(random.uniform(0.001, 0.01))  # simulate thinking
                new_content = content + f"- [{agent_id}] {message}\n"
                if doc.conditional_write(new_content, version):
                    write_counts["success"] += 1
                    return
                else:
                    write_counts["retry"] += 1
                    time.sleep(random.uniform(0.001, 0.005))  # back off

            write_counts["fail"] += 1
            print(f"  Agent {agent_id}: GAVE UP after {max_retries} retries")

        agents = [
            threading.Thread(target=agent_write, args=(f"Agent_{i}", f"Note from agent {i}"))
            for i in range(8)
        ]
        for t in agents:
            t.start()
        for t in agents:
            t.join()

        final_content = doc_path.read_text()
        notes_written = len([l for l in final_content.splitlines() if l.startswith("- [")])

        print(f"\n  Agents: 8")
        print(f"  Successful writes: {write_counts['success']}")
        print(f"  Retries: {write_counts['retry']}")
        print(f"  Failed writes: {write_counts['fail']}")
        print(f"  Notes in file: {notes_written}")
        print(f"\n  Final document:")
        for line in final_content.splitlines():
            print(f"    {line}")


# ---------------------------------------------------------------------------
# 4. File-Based Mutex for Agent Coordination
# ---------------------------------------------------------------------------

class AgentWorkspaceLock:
    """
    A file-based mutex that allows only one agent to operate on a workspace
    at a time. Uses flock for both cross-thread and cross-process safety.

    This is useful when agents operate on a project directory and you want
    to serialize writes to prevent conflicts.
    """

    def __init__(self, workspace: Path, agent_id: str):
        self.workspace = workspace
        self.agent_id = agent_id
        self.lock_path = workspace / ".agent_lock"
        self._fd = None

    def acquire(self, timeout_s: float = 5.0) -> bool:
        deadline = time.time() + timeout_s
        self._fd = open(self.lock_path, "w")
        while time.time() < deadline:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._fd.write(f"{self.agent_id}\n")
                self._fd.flush()
                return True
            except BlockingIOError:
                time.sleep(0.05)
        return False

    def release(self):
        if self._fd:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            self._fd.close()
            self._fd = None

    @contextmanager
    def locked(self, timeout_s: float = 5.0):
        if not self.acquire(timeout_s):
            raise TimeoutError(f"Agent {self.agent_id} could not acquire workspace lock")
        try:
            yield
        finally:
            self.release()


def demo_workspace_lock():
    print("\n" + "=" * 60)
    print("File-Based Agent Mutex")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        log = []

        def agent_work(agent_id: str, work_duration: float):
            lock = AgentWorkspaceLock(workspace, agent_id)
            with lock.locked(timeout_s=10.0):
                log.append(f"{agent_id} START")
                time.sleep(work_duration)
                log.append(f"{agent_id} END")

        agents = [
            threading.Thread(target=agent_work, args=(f"Agent_{c}", 0.05))
            for c in "ABCDE"
        ]
        for t in agents:
            t.start()
        for t in agents:
            t.join()

        print("\n  Execution order (should be strictly non-overlapping):")
        for i in range(0, len(log), 2):
            print(f"    {log[i]:20s} → {log[i+1]}")

        # Verify no overlap: check START/END pairs don't interleave
        active = set()
        overlap_detected = False
        for entry in log:
            agent_id, action = entry.rsplit(" ", 1)
            if action == "START":
                if active:
                    overlap_detected = True
                    print(f"  OVERLAP: {agent_id} started while {active} was active!")
                active.add(agent_id)
            else:
                active.discard(agent_id)

        if not overlap_detected:
            print("\n  No overlaps — mutex worked correctly")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    demo_lost_update()
    demo_torn_read()
    demo_optimistic_concurrency()
    demo_workspace_lock()
