"""SQLite persistence for subscriptions. stdlib only.

Everything here is synchronous and is meant to be called from a worker thread
(`asyncio.to_thread`), never from the event loop. The relay's hot path does not
touch this module at all: it reads a snapshot that a background task loads.

The token secret is never stored. We keep sha256(token) for lookups and a
6-character non-secret prefix as the handle used in logs and on the CLI.
"""

import os
import sqlite3
import time

SCHEMA_VERSION = "1"

DDL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash     BLOB    NOT NULL UNIQUE,
    token_prefix   TEXT    NOT NULL UNIQUE,
    label          TEXT    NOT NULL DEFAULT '',
    plan           TEXT    NOT NULL DEFAULT 'basic',
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,          -- unix seconds UTC; 0 = never
    device_limit   INTEGER NOT NULL DEFAULT 2,
    conn_limit     INTEGER NOT NULL DEFAULT 64,
    byte_quota     INTEGER NOT NULL DEFAULT 0,-- 0 = unlimited
    quota_period   TEXT    NOT NULL DEFAULT 'none',  -- none | day | month
    tunnel_enabled INTEGER NOT NULL DEFAULT 1,
    status         TEXT    NOT NULL DEFAULT 'active', -- active | suspended | revoked
    revoked_at     INTEGER,
    note           TEXT    NOT NULL DEFAULT '',
    updated_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tokens_status  ON tokens(status);
CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires_at);

CREATE TABLE IF NOT EXISTS devices (
    token_id     INTEGER NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
    device_id    BLOB    NOT NULL,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    conns        INTEGER NOT NULL DEFAULT 0,
    bytes_up     INTEGER NOT NULL DEFAULT 0,
    bytes_down   INTEGER NOT NULL DEFAULT 0,
    blocked      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (token_id, device_id)
);
CREATE INDEX IF NOT EXISTS idx_devices_lastseen ON devices(token_id, last_seen DESC);

CREATE TABLE IF NOT EXISTS usage_daily (
    token_id     INTEGER NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
    day          TEXT    NOT NULL,            -- YYYY-MM-DD, UTC
    bytes_up     INTEGER NOT NULL DEFAULT 0,
    bytes_down   INTEGER NOT NULL DEFAULT 0,
    conns        INTEGER NOT NULL DEFAULT 0,
    rejects      INTEGER NOT NULL DEFAULT 0,
    tunnel_bytes INTEGER NOT NULL DEFAULT 0,
    tunnel_conns INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (token_id, day)
);

CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    actor    TEXT    NOT NULL,
    action   TEXT    NOT NULL,
    token_id INTEGER,
    detail   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_token ON audit(token_id, ts DESC);
"""


def connect(path):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db(path):
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    conn = connect(path)
    with conn:
        conn.executescript(DDL)
        conn.execute(
            "INSERT INTO schema_meta(key,value) VALUES('version',?) "
            "ON CONFLICT(key) DO NOTHING", (SCHEMA_VERSION,))
        conn.execute(
            "INSERT INTO schema_meta(key,value) VALUES('gen','1') "
            "ON CONFLICT(key) DO NOTHING")
    return conn


# ---- generation counter: lets the relay skip no-op cache rebuilds ----------

def get_gen(conn):
    row = conn.execute("SELECT value FROM schema_meta WHERE key='gen'").fetchone()
    return int(row["value"]) if row else 0


def bump_gen(conn):
    with conn:
        conn.execute(
            "INSERT INTO schema_meta(key,value) VALUES('gen','1') "
            "ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER)+1 AS TEXT)")
    return get_gen(conn)


# ---- what the relay's auth cache loads ------------------------------------

SNAPSHOT_SQL = """
SELECT id, token_hash, token_prefix, plan, expires_at, device_limit, conn_limit,
       byte_quota, quota_period, tunnel_enabled, status
  FROM tokens
"""


def snapshot(conn):
    """Every token, including revoked ones.

    Revoked rows stay in the snapshot on purpose: a token the relay does not
    know at all gets silently masked, which leaves the customer with no
    explanation. Keeping the row lets us answer 'revoked' until an admin
    prunes it, at which point it degrades to silent masking.
    """
    return [dict(r) for r in conn.execute(SNAPSHOT_SQL)]


def period_usage(conn, period):
    """{token_id: bytes} over the current quota window."""
    if period == "day":
        where = "day = strftime('%Y-%m-%d','now')"
    elif period == "month":
        where = "day >= strftime('%Y-%m-01','now')"
    else:
        return {}
    rows = conn.execute(
        "SELECT token_id, SUM(bytes_up + bytes_down) AS b FROM usage_daily "
        "WHERE " + where + " GROUP BY token_id")
    return {r["token_id"]: (r["b"] or 0) for r in rows}


# ---- metering flush -------------------------------------------------------

def flush_usage(conn, rows, day=None):
    """rows: iterable of dicts with token_id and any of the counter fields.

    One transaction for the whole batch; called every METER_FLUSH_SEC, never
    per connection.
    """
    if not rows:
        return 0
    if day is None:
        day = time.strftime("%Y-%m-%d", time.gmtime())
    now = int(time.time())
    n = 0
    with conn:
        for r in rows:
            conn.execute(
                "INSERT INTO usage_daily(token_id,day,bytes_up,bytes_down,conns,"
                "rejects,tunnel_bytes,tunnel_conns) VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(token_id,day) DO UPDATE SET "
                "  bytes_up     = bytes_up     + excluded.bytes_up,"
                "  bytes_down   = bytes_down   + excluded.bytes_down,"
                "  conns        = conns        + excluded.conns,"
                "  rejects      = rejects      + excluded.rejects,"
                "  tunnel_bytes = tunnel_bytes + excluded.tunnel_bytes,"
                "  tunnel_conns = tunnel_conns + excluded.tunnel_conns",
                (r["token_id"], day, r.get("bytes_up", 0), r.get("bytes_down", 0),
                 r.get("conns", 0), r.get("rejects", 0),
                 r.get("tunnel_bytes", 0), r.get("tunnel_conns", 0)))
            dev = r.get("device_id")
            if dev:
                conn.execute(
                    "INSERT INTO devices(token_id,device_id,first_seen,last_seen,"
                    "conns,bytes_up,bytes_down) VALUES(?,?,?,?,?,?,?) "
                    "ON CONFLICT(token_id,device_id) DO UPDATE SET "
                    "  last_seen  = excluded.last_seen,"
                    "  conns      = conns      + excluded.conns,"
                    "  bytes_up   = bytes_up   + excluded.bytes_up,"
                    "  bytes_down = bytes_down + excluded.bytes_down",
                    (r["token_id"], dev, now, now, r.get("conns", 0),
                     r.get("bytes_up", 0), r.get("bytes_down", 0)))
            n += 1
    return n


# ---- admin operations -----------------------------------------------------

def audit(conn, actor, action, token_id=None, detail=""):
    with conn:
        conn.execute(
            "INSERT INTO audit(ts,actor,action,token_id,detail) VALUES(?,?,?,?,?)",
            (int(time.time()), actor, action, token_id, detail))


def create_token(conn, token_hash, token_prefix, expires_at, label="",
                 plan="basic", device_limit=2, conn_limit=64, byte_quota=0,
                 quota_period="none", tunnel_enabled=1, note=""):
    now = int(time.time())
    with conn:
        cur = conn.execute(
            "INSERT INTO tokens(token_hash,token_prefix,label,plan,created_at,"
            "expires_at,device_limit,conn_limit,byte_quota,quota_period,"
            "tunnel_enabled,note,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (token_hash, token_prefix, label, plan, now, expires_at, device_limit,
             conn_limit, byte_quota, quota_period, tunnel_enabled, note, now))
        return cur.lastrowid


def find(conn, needle):
    """Resolve a CLI argument: '#<id>', a full prefix, or a unique prefix."""
    needle = (needle or "").strip()
    if not needle:
        raise ValueError("empty token reference")
    if needle.startswith("#"):
        row = conn.execute("SELECT * FROM tokens WHERE id=?", (int(needle[1:]),)).fetchone()
        if not row:
            raise ValueError("no token with id %s" % needle[1:])
        return dict(row)
    up = needle.upper()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM tokens WHERE token_prefix LIKE ?", (up[:6] + "%",))]
    if not rows:
        raise ValueError("no token matching %r" % needle)
    if len(rows) > 1:
        raise ValueError("%r is ambiguous (%d matches)" % (needle, len(rows)))
    return rows[0]


def update_token(conn, token_id, **fields):
    if not fields:
        return 0
    cols = ", ".join("%s=?" % k for k in fields)
    vals = list(fields.values()) + [int(time.time()), token_id]
    with conn:
        cur = conn.execute(
            "UPDATE tokens SET " + cols + ", updated_at=? WHERE id=?", vals)
        return cur.rowcount


def list_tokens(conn, include_all=False, expiring_days=None):
    sql = "SELECT * FROM tokens"
    args = []
    where = []
    if not include_all:
        where.append("status = 'active'")
        where.append("(expires_at = 0 OR expires_at > ?)")
        args.append(int(time.time()))
    if expiring_days is not None:
        where.append("expires_at != 0 AND expires_at <= ?")
        args.append(int(time.time()) + expiring_days * 86400)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY expires_at"
    return [dict(r) for r in conn.execute(sql, args)]


def list_devices(conn, token_id):
    return [dict(r) for r in conn.execute(
        "SELECT * FROM devices WHERE token_id=? ORDER BY last_seen DESC", (token_id,))]


def forget_device(conn, token_id, device_id):
    with conn:
        cur = conn.execute("DELETE FROM devices WHERE token_id=? AND device_id=?",
                           (token_id, device_id))
        return cur.rowcount


def usage(conn, token_id, days=30):
    return [dict(r) for r in conn.execute(
        "SELECT * FROM usage_daily WHERE token_id=? ORDER BY day DESC LIMIT ?",
        (token_id, days))]


def prune(conn, older_than_days=30):
    """Drop revoked rows that have been revoked long enough. After this the
    token becomes unknown and is silently masked instead of answered."""
    cutoff = int(time.time()) - older_than_days * 86400
    with conn:
        cur = conn.execute(
            "DELETE FROM tokens WHERE status='revoked' AND revoked_at IS NOT NULL "
            "AND revoked_at < ?", (cutoff,))
        return cur.rowcount
