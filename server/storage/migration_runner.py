from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterable
from datetime import datetime, timezone


def split_sql_statements(sql_text: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    in_dollar = False

    i = 0
    while i < len(sql_text):
        char = sql_text[i]
        
        # Check for $$
        if char == '$' and i + 1 < len(sql_text) and sql_text[i+1] == '$' and not in_single and not in_double:
            in_dollar = not in_dollar
            current.append('$')
            current.append('$')
            i += 2
            continue

        if char == "'" and not in_double and not in_dollar:
            in_single = not in_single
        elif char == '"' and not in_single and not in_dollar:
            in_double = not in_double
        elif char == ";" and not in_single and not in_double and not in_dollar:
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current = []
            i += 1
            continue
            
        current.append(char)
        i += 1

    tail = "".join(current).strip()
    if tail:
        statements.append(tail)
    return statements


def run_sql_script(connection, sql_text: str, commit: bool = True) -> int:
    cursor = connection.cursor()
    count = 0
    is_sqlite = connection.__class__.__module__.startswith("sqlite3")
    try:
        for statement in split_sql_statements(sql_text):
            if not is_sqlite:
                statement = statement.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
            else:
                statement = statement.replace("ADD COLUMN IF NOT EXISTS", "ADD COLUMN")
                statement = statement.replace("BIGSERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
                statement = statement.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
                statement = statement.replace("NOW()", "CURRENT_TIMESTAMP")
                statement = statement.replace("TIMESTAMPTZ", "TIMESTAMP")
                import re
                uncommented = re.sub(r"--[^\n]*", "", statement).strip().upper()
                if (uncommented.startswith("DO ") or uncommented.startswith("DO\n") or
                    uncommented.startswith("DO$$") or "PARTITION OF" in uncommented or
                    "PARTITION BY" in uncommented or uncommented.startswith("COMMENT ON")):
                    continue
            
            if not statement.strip():
                continue
                
            try:
                cursor.execute(statement)
                count += 1
            except Exception as e:
                # psycopg2 raises ProgrammingError for statements that only contain comments
                err_str = str(e).lower()
                if "empty query" in err_str:
                    continue
                if is_sqlite and "duplicate column name" in err_str:
                    continue
                raise
        if commit:
            connection.commit()
    except Exception:
        if commit:
            connection.rollback()
        raise
    finally:
        cursor.close()
    return count


def apply_migration_file(connection_factory: Callable[[], object], migration_path: str | Path) -> int:
    path = Path(migration_path)
    sql_text = path.read_text(encoding="utf-8")
    connection = connection_factory()
    try:
        return run_sql_script(connection, sql_text)
    finally:
        try:
            connection.close()
        except Exception:
            pass


def apply_migrations_dir(connection_factory: Callable[[], object], migrations_dir: str | Path) -> int:
    """Apply all SQL files in a directory in sorted order with serialization and transactional tracking.

    Files ending with `_pg.sql` are only applied when the connection is not SQLite.
    Returns the total number of statements executed across all files.
    """
    dirp = Path(migrations_dir)
    if not dirp.exists() or not dirp.is_dir():
        return 0
    total = 0
    # sort files to ensure deterministic ordering (001_..., 002_...)
    files = sorted([p for p in dirp.iterdir() if p.is_file() and p.suffix == '.sql'])

    conn = connection_factory()
    try:
        is_sqlite = conn.__class__.__module__.startswith("sqlite3")
        lock_acquired = False

        # Acquire PostgreSQL advisory lock to serialize concurrent worker migrations
        if not is_sqlite:
            try:
                cur = conn.cursor()
                cur.execute("SELECT pg_advisory_lock(8472910)")
                conn.commit()
                cur.close()
                lock_acquired = True
            except Exception:
                lock_acquired = False

        try:
            # Ensure a schema_migrations table exists so we can track applied migrations
            cur = conn.cursor()
            try:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        name TEXT PRIMARY KEY,
                        applied_at TEXT NOT NULL
                    );
                    """
                )
                conn.commit()
            finally:
                cur.close()

            # Build set of already applied migrations
            cur = conn.cursor()
            try:
                cur.execute("SELECT name FROM schema_migrations")
                applied = {row[0] for row in cur.fetchall()}
            except Exception:
                applied = set()
            finally:
                cur.close()

            for path in files:
                name = path.name
                if is_sqlite and (name.endswith("_pg.sql") or "partition" in name.lower()):
                    # skip Postgres-only partitioning migrations on sqlite demo
                    continue
                if name in applied:
                    continue

                sql_text = path.read_text(encoding="utf-8")
                # Execute migration and record in schema_migrations in the SAME transaction
                try:
                    file_count = run_sql_script(conn, sql_text, commit=False)
                    cur = conn.cursor()
                    try:
                        placeholder = "?" if is_sqlite else "%s"
                        applied_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                        cur.execute(
                            f"INSERT INTO schema_migrations (name, applied_at) VALUES ({placeholder}, {placeholder})",
                            (name, applied_at),
                        )
                        conn.commit()
                        total += file_count
                        applied.add(name)
                    finally:
                        cur.close()
                except Exception:
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                    raise

            return total
        finally:
            if lock_acquired and not is_sqlite:
                try:
                    cur = conn.cursor()
                    cur.execute("SELECT pg_advisory_unlock(8472910)")
                    conn.commit()
                    cur.close()
                except Exception:
                    pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
