"""Versioned, disposable SQLite indexes of parsed local WeChat message text."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import sqlite3
import uuid

import config

# Bump whenever message normalization or indexed fields change.
PARSER_VERSION = "1"


def _cache_path(snapshot_id: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", snapshot_id):
        raise ValueError("无效的快照 ID")
    return Path(config.DECRYPTED_DIR) / "indexes" / f"{snapshot_id}-v{PARSER_VERSION}.sqlite"


def _valid_index(path: Path, snapshot_id: str) -> bool:
    if not path.is_file():
        return False
    conn = None
    try:
        conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        metadata = dict(conn.execute("SELECT key, value FROM metadata"))
        valid = metadata == {"snapshot_id": snapshot_id, "parser_version": PARSER_VERSION}
        conn.execute("SELECT row_id, path, normalized FROM parts LIMIT 0")
        conn.execute("SELECT db_stem, table_name, local_id, cid, created_at FROM messages LIMIT 0")
        return valid
    except sqlite3.Error:
        return False
    finally:
        if conn is not None:
            conn.close()


def _build_index(ctx, target: sqlite3.Connection, snapshot_id: str):
    from message_content import search_parts
    import parser as pmod

    target.executescript("""
        PRAGMA synchronous=OFF;
        PRAGMA journal_mode=MEMORY;
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE messages (
            row_id INTEGER PRIMARY KEY,
            db_stem TEXT NOT NULL,
            table_name TEXT NOT NULL,
            local_id INTEGER NOT NULL,
            cid TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE parts (
            row_id INTEGER NOT NULL,
            path TEXT NOT NULL,
            normalized TEXT NOT NULL
        );
        CREATE INDEX parts_message ON parts(row_id);
        CREATE INDEX message_order ON messages(created_at DESC, cid DESC, local_id DESC);
    """)

    # Preload contacts once to avoid repeated SQL lookups
    contacts = pmod._load_contacts_map(ctx, None)

    next_row_id = 1
    msg_batch = []
    part_batch = []

    def flush():
        if msg_batch:
            target.executemany(
                "INSERT INTO messages(row_id, db_stem, table_name, local_id, cid, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                msg_batch,
            )
            msg_batch.clear()
        if part_batch:
            target.executemany("INSERT INTO parts(row_id, path, normalized) VALUES (?, ?, ?)", part_batch)
            part_batch.clear()

    for cid, msg_conn, table, db_stem in pmod._iter_conversation_tables(ctx):
        is_group = cid.endswith("@chatroom")
        name2id, self_rowid = pmod._load_name2id(msg_conn, db_stem, ctx)
        group_nicks, _, _ = pmod._get_chatroom_info(ctx, cid) if is_group else ({}, 0, "")
        select_sql = pmod._select_columns_sql(msg_conn, table)
        quoted = pmod._quote_ident(table)
        try:
            cursor = msg_conn.execute(f"SELECT {select_sql} FROM {quoted}")
        except sqlite3.Error:
            continue

        for row in cursor:
            local_type = int(row["local_type"] or 0)
            base_type = local_type & 0xFFFFFFFF
            # Fast path for plain text messages (no attachments, no images, no XML)
            if base_type == 1 and (local_type >> 32) == 0:
                raw_text = pmod._decode_message_content(row["compress_content"], row["message_content"]).strip()
                if is_group and raw_text:
                    _, raw_text = pmod._split_group_sender_prefix(raw_text)
                if not raw_text:
                    continue
                created_at = pmod._sec_to_ms(row["create_time"])
                local_id = int(row["local_id"] or 0)
                rid = next_row_id
                next_row_id += 1
                msg_batch.append((rid, db_stem, table, local_id, cid, created_at))
                part_batch.append((rid, "[]", raw_text.casefold()))
            else:
                # Skip image-only / emoji / video rows that have no searchable text
                if base_type in (3, 47):
                    continue
                msg = pmod._parse_message_row(
                    row,
                    ctx,
                    cid=cid,
                    is_group=is_group,
                    name2id=name2id,
                    self_rowid=self_rowid,
                    contacts=contacts,
                    group_nicks=group_nicks,
                    expand_forwarded=True,
                )
                parts = [pt for pt in search_parts(msg) if pt["text"]]
                if not parts:
                    continue
                rid = next_row_id
                next_row_id += 1
                msg_batch.append((rid, db_stem, table, int(row["local_id"] or 0), cid, msg["created_at"]))
                for pt in parts:
                    part_batch.append((rid, json.dumps(pt["path"]), pt["text"].casefold()))

            if len(msg_batch) >= 2000:
                flush()

    flush()
    target.executemany(
        "INSERT INTO metadata VALUES (?, ?)",
        [("snapshot_id", snapshot_id), ("parser_version", PARSER_VERSION)],
    )
    target.commit()


def _write_index(ctx, snapshot_id: str) -> Path:
    path = _cache_path(snapshot_id).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if _valid_index(path, snapshot_id):
        return path
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        target = sqlite3.connect(temporary)
        try:
            _build_index(ctx, target, snapshot_id)
        finally:
            target.close()
        try:
            os.replace(temporary, path)
        except OSError:
            if not _valid_index(path, snapshot_id):
                raise
    finally:
        temporary.unlink(missing_ok=True)
    return path


def prepare_snapshot_index(snapshot_dir: str | Path, snapshot_id: str) -> str:
    """Build search index for a snapshot directory."""
    from snapshots import SnapshotContext

    ctx = SnapshotContext({"path": str(snapshot_dir), "snapshot_id": snapshot_id}, immutable=True)
    try:
        return str(_write_index(ctx, snapshot_id))
    finally:
        ctx.close()


@contextmanager
def _open_index(ctx):
    from snapshots import connection_metadata

    snapshot_id = connection_metadata(ctx).get("snapshot_id")
    if snapshot_id:
        path = _write_index(ctx, snapshot_id)
        index = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    else:
        index = sqlite3.connect(":memory:")
        _build_index(ctx, index, "memory")
    index.row_factory = sqlite3.Row
    try:
        yield index
    finally:
        index.close()


def search_indexed_messages(ctx, keyword: str, limit=50, offset=0) -> dict:
    import parser as pmod

    normalized = keyword.casefold()
    where = "EXISTS (SELECT 1 FROM parts WHERE parts.row_id=messages.row_id AND instr(normalized, ?) > 0)"
    with _open_index(ctx) as index:
        total = index.execute(f"SELECT COUNT(*) FROM messages WHERE {where}", (normalized,)).fetchone()[0]
        rows = index.execute(
            f"""SELECT * FROM messages WHERE {where}
                ORDER BY created_at DESC, cid DESC, local_id DESC, row_id DESC
                LIMIT ? OFFSET ?""",
            (normalized, limit, offset),
        ).fetchall()

        messages = []
        for match in rows:
            cid = match["cid"]
            db_stem = match["db_stem"]
            table = match["table_name"]
            local_id = int(match["local_id"])

            msg_conn = ctx.message_conn(f"{db_stem}.db")
            select_sql = pmod._select_columns_sql(msg_conn, table)
            source = msg_conn.execute(
                f"SELECT {select_sql} FROM {pmod._quote_ident(table)} WHERE local_id = ? LIMIT 1",
                (local_id,),
            ).fetchone()
            if source is None:
                raise ValueError("检索索引与快照不一致，请重新刷新")

            is_group = cid.endswith("@chatroom")
            name2id, self_rowid = pmod._load_name2id(msg_conn, db_stem, ctx)
            group_nicks, _, _ = pmod._get_chatroom_info(ctx, cid) if is_group else ({}, 0, "")
            contacts = pmod._load_contacts_map(ctx, [cid, name2id.get(int(source["real_sender_id"] or 0), "")])
            msg = pmod._parse_message_row(
                source,
                ctx,
                cid=cid,
                is_group=is_group,
                name2id=name2id,
                self_rowid=self_rowid,
                contacts=contacts,
                group_nicks=group_nicks,
                expand_forwarded=False,
            )
            msg["matched_paths"] = [
                json.loads(r[0])
                for r in index.execute(
                    "SELECT DISTINCT path FROM parts WHERE row_id=? AND instr(normalized, ?) > 0 ORDER BY rowid",
                    (match["row_id"], normalized),
                )
            ]
            messages.append(msg)

    return {
        "query": keyword,
        "mode": "text",
        **pmod._page_result("messages", messages, total, limit, offset, ctx),
    }
