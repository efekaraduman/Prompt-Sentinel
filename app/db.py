import os
import pathlib
from typing import Iterator

from sqlmodel import Session, SQLModel, create_engine

from . import models  # noqa: F401  # ensure models are imported for metadata


_DB_PATH = os.environ.get("PROMPTSENTINEL_DB_PATH", "./promptsentinel.db")
DATABASE_URL = f"sqlite:///{_DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False},
)


def _apply_sqlite_migrations() -> None:
    """Lightweight inline migrations for columns added after initial schema.

    Uses PRAGMA table_info to detect missing columns and issues ALTER TABLE
    statements. Safe to run on every startup — idempotent.
    """
    migrations = [
        # (table_name, column_name, column_ddl)
        ("guardscan", "model_name", "VARCHAR(120) NOT NULL DEFAULT 'unknown'"),
        ("organization", "retention_days", "INTEGER"),
        ("guardscanrecord", "attacker_pattern_score", "INTEGER NOT NULL DEFAULT 0"),
        ("guardscanrecord", "random_seed", "INTEGER NOT NULL DEFAULT 0"),
        ("organization", "strict_mode", "BOOLEAN NOT NULL DEFAULT 0"),
        ("auditevent", "resource_type", "TEXT"),
        ("auditevent", "resource_id", "TEXT"),
        ("auditevent", "org_id", "INTEGER"),
        ("guardscanrecord", "rag_risk_score", "INTEGER NOT NULL DEFAULT 0"),  # PHASE 2.1
        ("attacksignature", "cluster_id", "TEXT"),                           # PHASE 2.7
        ("guardscanrecord", "stage_timings_json", "TEXT NOT NULL DEFAULT '{}'"),  # PHASE 2.8
        ("threatcluster", "example_signature_hash", "TEXT"),                  # PHASE 2.15
        ("organization", "strict_mode_default", "BOOLEAN NOT NULL DEFAULT 0"),  # PHASE 2.18
        ("organization", "zero_trust_mode",    "BOOLEAN NOT NULL DEFAULT 0"),  # PHASE 2.27
        ("guardscanrecord", "sandbox_mode",    "BOOLEAN NOT NULL DEFAULT 0"),  # PHASE 2.35
    ]
    # Data migration: rename legacy OrgMember role "member" → "analyst" (RBAC expansion).
    with engine.connect() as _conn:
        _conn.execute(
            __import__("sqlalchemy").text(
                "UPDATE orgmember SET role = 'analyst' WHERE role = 'member'"
            )
        )
        _conn.commit()
    with engine.connect() as conn:
        for table, col, ddl in migrations:
            rows = conn.execute(
                __import__("sqlalchemy").text(f"PRAGMA table_info({table})")
            ).fetchall()
            existing_cols = {r[1] for r in rows}
            if col not in existing_cols:
                try:
                    conn.execute(
                        __import__("sqlalchemy").text(
                            f"ALTER TABLE {table} ADD COLUMN {col} {ddl}"
                        )
                    )
                    conn.commit()
                    import logging as _lg
                    _lg.getLogger("promptsentinel").info("migration: added %s.%s", table, col)
                except Exception as _mig_exc:
                    import logging as _lg
                    _lg.getLogger("promptsentinel").error(
                        "migration FAILED for %s.%s: %s", table, col, _mig_exc
                    )
                    conn.rollback()


def _migrate_modelriskprofile() -> None:
    """Recreate modelriskprofile if it uses the old model_name-as-PK schema (PHASE 2.0).

    The old schema had model_name as the sole primary key with no org_id.
    The new schema uses an integer id PK with (org_id, model_name) unique.
    Safe to run on every startup — idempotent.
    """
    _sa_text = __import__("sqlalchemy").text
    with engine.connect() as conn:
        cols = conn.execute(_sa_text("PRAGMA table_info(modelriskprofile)")).fetchall()
        col_names = {r[1] for r in cols}
        if not col_names or "org_id" in col_names:
            return  # table absent (create_all will build it) or already migrated
        # Old schema present — recreate with new layout, preserving existing rows.
        conn.execute(_sa_text("""
            CREATE TABLE IF NOT EXISTS modelriskprofile_new (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id              INTEGER,
                model_name          VARCHAR(120) NOT NULL,
                sample_count        INTEGER  NOT NULL DEFAULT 0,
                avg_risk_score      REAL     NOT NULL DEFAULT 0.0,
                avg_consensus_score REAL     NOT NULL DEFAULT 0.0,
                block_rate          REAL     NOT NULL DEFAULT 0.0,
                warn_rate           REAL     NOT NULL DEFAULT 0.0,
                updated_at          DATETIME NOT NULL
            )
        """))
        conn.execute(_sa_text("""
            INSERT INTO modelriskprofile_new
                (org_id, model_name, sample_count, avg_risk_score,
                 avg_consensus_score, block_rate, warn_rate, updated_at)
            SELECT NULL, model_name, COALESCE(sample_size, 0), COALESCE(avg_risk, 0.0),
                   0.0, COALESCE(block_rate, 0.0), 0.0, COALESCE(last_updated, datetime('now'))
            FROM modelriskprofile
        """))
        conn.execute(_sa_text("DROP TABLE modelriskprofile"))
        conn.execute(_sa_text("ALTER TABLE modelriskprofile_new RENAME TO modelriskprofile"))
        conn.execute(_sa_text(
            "CREATE INDEX IF NOT EXISTS ix_modelriskprofile_org_id    ON modelriskprofile (org_id)"
        ))
        conn.execute(_sa_text(
            "CREATE INDEX IF NOT EXISTS ix_modelriskprofile_model_name ON modelriskprofile (model_name)"
        ))
        conn.execute(_sa_text(
            "CREATE INDEX IF NOT EXISTS ix_modelriskprofile_updated_at ON modelriskprofile (updated_at)"
        ))
        conn.execute(_sa_text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_modelriskprofile_org_model "
            "ON modelriskprofile (org_id, model_name)"
        ))
        conn.commit()


def init_db() -> None:
    """Create database tables if they do not exist."""
    if os.environ.get("PROMPTSENTINEL_DEV_RESET_DB") == "1":
        engine.dispose()  # release any pooled connections before deleting
        db_path = pathlib.Path(_DB_PATH)
        if db_path.exists():
            try:
                db_path.unlink()
            except PermissionError:
                # On Windows the file may still be held; drop tables instead.
                SQLModel.metadata.drop_all(engine)
    _migrate_modelriskprofile()   # PHASE 2.0: must run before create_all on existing DBs
    SQLModel.metadata.create_all(engine)
    _apply_sqlite_migrations()


def get_session() -> Iterator[Session]:
    """FastAPI dependency that yields a database session."""
    with Session(engine) as session:
        yield session

