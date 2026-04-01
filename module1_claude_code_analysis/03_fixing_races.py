"""
Module 1, File 3: Three Strategies for Fixing the State-File Race
=================================================================

After demonstrating the race in 02_race_condition_demo.py, here are three
progressively more robust fixes:

  Strategy 1: fcntl advisory lock  (Unix, in-process + cross-process)
  Strategy 2: Atomic rename         (portable, no lock primitive needed)
  Strategy 3: SQLite WAL mode       (proper concurrent DB, overkill but correct)

Each is runnable and includes a concurrent stress test to verify correctness.
"""

import fcntl
import json
import os
import sqlite3
import tempfile
import threading
import time
import random
from contextlib import contextmanager
from pathlib import Path


# ---------------------------------------------------------------------------
# Strategy 1: fcntl Advisory Lock
# ---------------------------------------------------------------------------

class LockedStateStore:
    """
    Fix #1: Use fcntl.flock() for cross-process advisory locking.

    Properties:
    - Works across processes AND threads sharing the same PID
    - Lock is released automatically when fd is closed (or process dies)
    - Advisory: other writers must also use flock to be protected
    - Unix-only (use filelock package for cross-platform)
    """

    def __init__(self, path: Path):
        self.path = path
        self.lock_path = Path(str(path) + ".lock")
        if not self.path.exists():
            self.path.write_text(json.dumps({"warnings_shown": [], "count": 0}))

    @contextmanager
    def _file_lock(self):
        """Acquire an exclusive advisory lock via a dedicated lock file."""
        lock_fd = open(self.lock_path, "w")
        try:
            # LOCK_EX = exclusive, LOCK_NB = non-blocking (raise instead of block)
            # Without LOCK_NB, this blocks until lock is available
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()

    def record_warning(self, warning_id: str) -> None:
        """Thread- and process-safe read-modify-write."""
        with self._file_lock():
            data = json.loads(self.path.read_text())
            time.sleep(random.uniform(0.001, 0.003))  # simulate work inside lock
            if warning_id not in data["warnings_shown"]:
                data["warnings_shown"].append(warning_id)
                data["count"] += 1
            self.path.write_text(json.dumps(data))

    def get_count(self) -> int:
        with self._file_lock():
            return json.loads(self.path.read_text())["count"]


# ---------------------------------------------------------------------------
# Strategy 2: Atomic Rename
# ---------------------------------------------------------------------------

class AtomicRenameStore:
    """
    Fix #2: Write to a temp file, then os.rename() into place atomically.

    Properties:
    - os.rename() is atomic on POSIX filesystems (single syscall)
    - Readers always see a complete file, never a partial write
    - Does NOT prevent two concurrent writers from overwriting each other
    - Combine with flock if you need mutual exclusion too

    Use case: protect *readers* from seeing truncated files during writes.
    For full safety, combine atomic rename with a lock.
    """

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()  # in-process lock (use flock for cross-process)
        if not self.path.exists():
            self._atomic_write({"warnings_shown": [], "count": 0})

    def _atomic_write(self, data: dict) -> None:
        """Write atomically: temp file in same directory → rename."""
        tmp_path = self.path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data))
        # os.rename is atomic on POSIX if src and dst are on the same filesystem
        os.rename(tmp_path, self.path)

    def record_warning(self, warning_id: str) -> None:
        with self.lock:
            data = json.loads(self.path.read_text())
            time.sleep(random.uniform(0.001, 0.003))
            if warning_id not in data["warnings_shown"]:
                data["warnings_shown"].append(warning_id)
                data["count"] += 1
            self._atomic_write(data)

    def get_count(self) -> int:
        return json.loads(self.path.read_text())["count"]


# ---------------------------------------------------------------------------
# Strategy 3: SQLite WAL Mode
# ---------------------------------------------------------------------------

class SQLiteStateStore:
    """
    Fix #3: Use SQLite with WAL (Write-Ahead Logging) mode.

    Properties:
    - SQLite handles concurrent readers + one writer natively
    - WAL mode allows concurrent reads during a write
    - ACID transactions — no partial writes, no lost updates
    - Overkill for a simple counter, but idiomatic for structured state

    When to use: when the state has multiple related fields that need
    transactional integrity, or when you want query capabilities.
    """

    def __init__(self, path: Path):
        self.db_path = str(path) + ".db"
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS warnings (
                    id TEXT PRIMARY KEY,
                    recorded_at REAL DEFAULT (unixepoch('now', 'subsec'))
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS stats (
                    key TEXT PRIMARY KEY,
                    value INTEGER DEFAULT 0
                )
            """)
            conn.execute("INSERT OR IGNORE INTO stats (key, value) VALUES ('count', 0)")
            conn.commit()

    def record_warning(self, warning_id: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            # INSERT OR IGNORE is atomic — no lost update possible
            cursor = conn.execute(
                "INSERT OR IGNORE INTO warnings (id) VALUES (?)", (warning_id,)
            )
            if cursor.rowcount:
                conn.execute("UPDATE stats SET value = value + 1 WHERE key = 'count'")
            conn.commit()

    def get_count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT value FROM stats WHERE key = 'count'").fetchone()
            return row[0] if row else 0


# ---------------------------------------------------------------------------
# Stress Test Runner
# ---------------------------------------------------------------------------

def stress_test(store_class, label: str, tmpdir: Path, num_threads: int = 30):
    """Launch num_threads concurrent writers, verify no lost updates."""
    path = tmpdir / f"state_{label}"
    store = store_class(path)

    threads = [
        threading.Thread(target=store.record_warning, args=(f"warning_{i}",))
        for i in range(num_threads)
    ]

    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t0

    final_count = store.get_count()
    ok = final_count == num_threads
    status = "PASS" if ok else f"FAIL (lost {num_threads - final_count} updates)"
    print(f"  {label:25s}  count={final_count:3d}/{num_threads}  {elapsed*1000:6.1f}ms  [{status}]")


def main():
    print("=" * 60)
    print("Race Condition Fixes: Stress Test")
    print("=" * 60)
    print(f"  {'Strategy':25s}  {'Result':20s}  {'Time':8s}  Status")
    print(f"  {'-'*25}  {'-'*20}  {'-'*8}  ------")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        stress_test(LockedStateStore,      "fcntl_lock",       tmpdir)
        stress_test(AtomicRenameStore,     "atomic_rename",    tmpdir)
        stress_test(SQLiteStateStore,      "sqlite_wal",       tmpdir)

    print("""
Strategy Comparison:
  fcntl_lock     - Best for existing JSON files; cross-process safe; Unix only
  atomic_rename  - Protects readers from partial writes; combine with lock for writers
  sqlite_wal     - Most correct; use when state is structured or grows over time

For Claude Code's specific case (session state files):
  Recommended fix: fcntl.flock() + atomic rename — simple, correct, no deps.
    """)

    # Also show the O_NOFOLLOW fix for TOCTOU
    print("Bonus: TOCTOU-safe file open")
    print("-" * 40)
    print("""
# Vulnerable (follows symlinks):
with open(path) as f: ...

# Safe (raises OSError if path is a symlink — requires O_NOFOLLOW):
fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
with os.fdopen(fd) as f: ...

# Even safer (open, then stat to verify it's the expected inode):
fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
stat = os.fstat(fd)
assert stat.st_nlink == 1, "Unexpected hard link"
    """)


if __name__ == "__main__":
    main()
