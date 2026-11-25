"""Choose a durable journal mode for the SQLite library used by Python."""

import sqlite3


def configure(db):
    version = sqlite3.sqlite_version_info
    # SQLite fixed a WAL checkpoint race in 3.51.3, with backports in 3.50.7 and 3.44.6.
    wal_safe = (
        version >= (3, 51, 3)
        or version[:2] == (3, 50)
        and version >= (3, 50, 7)
        or version[:2] == (3, 44)
        and version >= (3, 44, 6)
    )
    mode = "WAL" if wal_safe else "DELETE"
    actual = db.execute(f"PRAGMA journal_mode = {mode}").fetchone()[0]
    if actual.upper() != mode:
        raise RuntimeError(f"SQLite did not enter journal mode {mode}")
