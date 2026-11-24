"""Validated, immutable multi-database WeChat query snapshots with atomic pointer."""

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import sqlite3
import threading
import time
import uuid

import config

logger = logging.getLogger(__name__)
_VERSION_ID = re.compile(r"s-[0-9a-f]{32}\Z")
_LEGACY_ID = re.compile(r"legacy-[0-9a-f]{32}\Z")
_MSG_DB_RE = re.compile(r"^(?:biz_)?message(?:_\d+)?\.db\Z", re.IGNORECASE)
_RETENTION_SECONDS = 24 * 60 * 60
_state_lock = threading.RLock()
_publish_lock = threading.Lock()
_active_readers = {}


class SnapshotError(RuntimeError):
    """A snapshot cannot be validated, opened, or published."""


class SnapshotNotFoundError(SnapshotError):
    code = "snapshot_not_found"


class SnapshotExpiredError(SnapshotError):
    code = "snapshot_expired"

    def __init__(self, snapshot_id):
        super().__init__(f"快照 {snapshot_id!r} 已过期或不存在，请从第一页重新查询。")


def _root() -> Path:
    return Path(config.DECRYPTED_DIR).resolve() / "snapshots"


def _utc_time(timestamp=None) -> str:
    return datetime.fromtimestamp(time.time() if timestamp is None else timestamp, timezone.utc).isoformat()


def _readonly_sqlite(path: Path, immutable: bool = True) -> sqlite3.Connection:
    uri = path.resolve().as_uri() + "?mode=ro"
    if immutable:
        uri += "&immutable=1"
    conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def list_message_db_paths(snapshot_dir: str | Path) -> list[Path]:
    root = Path(snapshot_dir)
    if not root.is_dir():
        return []
    result = []
    for p in root.glob("*.db"):
        if _MSG_DB_RE.fullmatch(p.name):
            result.append(p)
    result.sort(key=lambda p: p.name.lower())
    return result


def _validate_sqlite_file(path: Path, required_tables=None, quick_check: bool = False) -> set[str]:
    if not path.is_file():
        raise SnapshotError(f"候选快照缺少数据库文件 {path.name}")
    conn = None
    try:
        conn = _readonly_sqlite(path, immutable=False)
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if required_tables:
            lower_map = {t.lower(): t for t in tables}
            for req in required_tables:
                if req.lower() not in lower_map:
                    raise SnapshotError(f"候选数据库 {path.name} 缺少表 {req}，未发布新快照。")
        if quick_check:
            checks = [row[0] for row in conn.execute("PRAGMA quick_check(5)")]
            if checks != ["ok"]:
                raise SnapshotError(f"候选数据库 {path.name} 未通过 quick_check，未发布新快照。")
        return tables
    except sqlite3.Error as exc:
        raise SnapshotError(f"候选数据库 {path.name} 无法读取或已损坏: {exc}") from exc
    finally:
        if conn is not None:
            conn.close()


def _compute_latest_message_ms(snapshot_dir: Path) -> int:
    """Compute latest message timestamp in milliseconds across message DBs (fallback to session.db)."""
    latest_sec = 0
    for msg_db in list_message_db_paths(snapshot_dir):
        conn = _readonly_sqlite(msg_db, immutable=False)
        try:
            tables = [
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                if row[0] and (row[0].lower().startswith("msg_") or row[0].lower().startswith("chat_"))
            ]
            for tbl in tables:
                try:
                    quoted = '"' + tbl.replace('"', '""') + '"'
                    val = conn.execute(f"SELECT MAX(create_time) FROM {quoted}").fetchone()[0]
                    if val:
                        latest_sec = max(latest_sec, int(val))
                except sqlite3.Error:
                    continue
        finally:
            conn.close()

    if latest_sec <= 0:
        session_db = snapshot_dir / "session.db"
        if session_db.is_file():
            conn = _readonly_sqlite(session_db, immutable=False)
            try:
                cols = {row[1].lower() for row in conn.execute("PRAGMA table_info(SessionTable)")}
                for col in ("last_timestamp", "sort_timestamp"):
                    if col in cols:
                        val = conn.execute(f"SELECT MAX({col}) FROM SessionTable").fetchone()[0]
                        if val:
                            latest_sec = max(latest_sec, int(val))
            finally:
                conn.close()

    if latest_sec <= 0:
        return 0
    return latest_sec * 1000 if latest_sec < 10_000_000_000 else latest_sec


def validate_snapshot_dir(snapshot_dir: str | Path, *, quick_check_core: bool = True) -> int:
    """Validate required WeChat 4.x databases and return latest_message_at (ms)."""
    root = Path(snapshot_dir)
    if not root.is_dir():
        raise SnapshotNotFoundError("未找到微信解密快照目录，请先刷新数据库。")

    _validate_sqlite_file(root / "session.db", required_tables={"SessionTable"}, quick_check=quick_check_core)
    _validate_sqlite_file(root / "contact.db", required_tables={"contact"}, quick_check=quick_check_core)

    msg_dbs = list_message_db_paths(root)
    if not msg_dbs:
        raise SnapshotError("候选快照缺少消息数据库 (message_*.db)，未发布新快照。")

    for msg_db in msg_dbs:
        _validate_sqlite_file(msg_db, quick_check=False)

    return _compute_latest_message_ms(root)


def _read_json(path: Path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as stream:
            data = json.load(stream)
        if not isinstance(data, dict):
            raise ValueError("expected object")
        return data
    except (OSError, ValueError) as exc:
        raise SnapshotError("快照元数据无法读取，请重新刷新数据库。") from exc


def _read_current():
    path = _root() / "current.json"
    if not path.exists():
        return None
    current = _read_json(path)
    if not _VERSION_ID.fullmatch(str(current.get("snapshot_id", ""))):
        raise SnapshotError("当前快照指针无效，请重新刷新数据库。")
    return current


def _version_info(snapshot_id: str) -> dict:
    if not _VERSION_ID.fullmatch(str(snapshot_id)):
        raise SnapshotExpiredError(snapshot_id)
    path = _root() / snapshot_id
    metadata_path = _root() / f"{snapshot_id}.json"
    if not path.is_dir() or not metadata_path.is_file():
        raise SnapshotExpiredError(snapshot_id)
    metadata = _read_json(metadata_path)
    if (
        metadata.get("snapshot_id") != snapshot_id
        or not isinstance(metadata.get("snapshot_time"), str)
        or not isinstance(metadata.get("latest_message_at"), int)
    ):
        raise SnapshotError("快照元数据与版本不一致。")
    return {
        "path": str(path),
        "snapshot_id": snapshot_id,
        "snapshot_time": metadata["snapshot_time"],
        "latest_message_at": metadata["latest_message_at"],
    }


def _explicit_dir_info(path: Path) -> dict:
    path = path.resolve()
    if not path.is_dir():
        raise SnapshotNotFoundError("未找到微信解密快照目录，请先刷新数据库。")
    files_sig = []
    for f in sorted(path.glob("*.db")):
        st = f.stat()
        files_sig.append((f.name, st.st_size, st.st_mtime_ns))
    fp = hashlib.sha256(json.dumps(files_sig).encode("utf-8")).hexdigest()[:32]
    latest = validate_snapshot_dir(path, quick_check_core=False)
    return {
        "path": str(path),
        "snapshot_id": f"legacy-{fp}",
        "snapshot_time": _utc_time(path.stat().st_mtime),
        "latest_message_at": latest,
    }


def resolve_snapshot(snapshot_id=None, db_dir=None) -> dict:
    """Resolve an exact version, an explicit snapshot directory, or the current snapshot."""
    with _state_lock:
        explicit = Path(db_dir).resolve() if db_dir is not None else None
        if snapshot_id is not None and _VERSION_ID.fullmatch(str(snapshot_id)):
            info = _version_info(snapshot_id)
            if explicit is not None and explicit != Path(info["path"]):
                raise SnapshotExpiredError(snapshot_id)
            return info
        if snapshot_id is not None and not _LEGACY_ID.fullmatch(str(snapshot_id)):
            raise SnapshotExpiredError(snapshot_id)
        if snapshot_id is None and explicit is not None and explicit.parent == _root() and _VERSION_ID.fullmatch(explicit.name):
            return _version_info(explicit.name)
        if snapshot_id is None and explicit is None:
            current = _read_current()
            if current:
                return _version_info(current["snapshot_id"])
            raise SnapshotNotFoundError("尚未解密微信数据库，请先点击“手动同步”或调用 refresh_database。")
        if explicit is not None:
            info = _explicit_dir_info(explicit)
            if snapshot_id is not None and info["snapshot_id"] != snapshot_id:
                raise SnapshotExpiredError(snapshot_id)
            return info
        raise SnapshotExpiredError(snapshot_id)


class SnapshotContext:
    """Manages read-only SQLite connections across a multi-DB WeChat snapshot directory."""

    def __init__(self, info: dict, immutable: bool = True):
        self.snapshot_info = dict(info)
        self.root = Path(info["path"])
        self.immutable = immutable
        self._conns: dict[str, sqlite3.Connection] = {}
        self._table_map_cache: dict[str, tuple[Path, str]] | None = None
        self._closed = False

    def _open_db(self, name: str) -> sqlite3.Connection | None:
        key = name.lower()
        if key in self._conns:
            return self._conns[key]
        path = self.root / name
        if not path.is_file():
            # Case-insensitive fallback
            for p in self.root.glob("*.db"):
                if p.name.lower() == key:
                    path = p
                    break
            else:
                return None
        conn = _readonly_sqlite(path, immutable=self.immutable)
        self._conns[key] = conn
        return conn

    @property
    def session_conn(self) -> sqlite3.Connection:
        conn = self._open_db("session.db")
        if conn is None:
            raise SnapshotError("快照中缺少 session.db")
        return conn

    @property
    def contact_conn(self) -> sqlite3.Connection:
        conn = self._open_db("contact.db")
        if conn is None:
            raise SnapshotError("快照中缺少 contact.db")
        return conn

    @property
    def hardlink_conn(self) -> sqlite3.Connection | None:
        return self._open_db("hardlink.db")

    @property
    def resource_conn(self) -> sqlite3.Connection | None:
        return self._open_db("message_resource.db")

    @property
    def head_image_conn(self) -> sqlite3.Connection | None:
        return self._open_db("head_image.db")

    @property
    def emoticon_conn(self) -> sqlite3.Connection | None:
        return self._open_db("emoticon.db")

    def message_db_paths(self) -> list[Path]:
        return list_message_db_paths(self.root)

    def message_conn(self, db_name_or_path) -> sqlite3.Connection:
        name = Path(db_name_or_path).name
        conn = self._open_db(name)
        if conn is None:
            raise SnapshotError(f"快照中缺少消息数据库 {name}")
        return conn

    def get_msg_table_index(self) -> dict[str, list[tuple[Path, str]]]:
        """Map lowercase msg_<md5> table name -> list of (db_path, actual_table_name) across all shards."""
        if self._table_map_cache is not None:
            return self._table_map_cache
        mapping: dict[str, list[tuple[Path, str]]] = {}
        for db_path in self.message_db_paths():
            conn = self.message_conn(db_path)
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
                tname = str(row[0] or "")
                low = tname.lower()
                if low.startswith("msg_") or low.startswith("chat_"):
                    mapping.setdefault(low, []).append((db_path, tname))
        self._table_map_cache = mapping
        return mapping

    def close(self):
        if self._closed:
            return
        self._closed = True
        for conn in self._conns.values():
            try:
                conn.close()
            except Exception:
                pass
        self._conns.clear()
        with _state_lock:
            path = self.snapshot_info["path"]
            _active_readers[path] = max(0, _active_readers.get(path, 1) - 1)
            if not _active_readers[path]:
                _active_readers.pop(path, None)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


def open_snapshot(db_dir=None, snapshot_id=None) -> SnapshotContext:
    with _state_lock:
        info = resolve_snapshot(snapshot_id=snapshot_id, db_dir=db_dir)
        immutable = bool(_VERSION_ID.fullmatch(info["snapshot_id"]))
        ctx = SnapshotContext(info, immutable=immutable)
        try:
            # Verify core connections open cleanly
            ctx.session_conn.execute("SELECT 1 FROM SessionTable LIMIT 0")
            ctx.contact_conn.execute("SELECT 1 FROM contact LIMIT 0")
        except Exception as exc:
            ctx.close()
            raise SnapshotError(f"无法打开微信查询快照: {exc}") from exc
        _active_readers[info["path"]] = _active_readers.get(info["path"], 0) + 1
        return ctx


def connection_metadata(ctx) -> dict:
    info = getattr(ctx, "snapshot_info", None)
    if not info:
        return {}
    return {key: info[key] for key in ("snapshot_id", "snapshot_time", "latest_message_at")}


def _atomic_json(path: Path, payload: dict):
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with open(temporary, "x", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def _publish_guard():
    root = _root()
    root.mkdir(parents=True, exist_ok=True)
    with _publish_lock, open(root / ".publish.lock", "a+b") as lock:
        lock.seek(0, os.SEEK_END)
        if not lock.tell():
            lock.write(b"\0")
            lock.flush()
        locked = False
        deadline = time.monotonic() + 30
        try:
            while not locked:
                try:
                    lock.seek(0)
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                except OSError as exc:
                    if time.monotonic() >= deadline:
                        raise SnapshotError("另一个进程正在发布快照，请稍后重试。") from exc
                    time.sleep(0.05)
            yield
        finally:
            if locked:
                lock.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _remove_snapshot_indexes(snapshot_id: str):
    if not _VERSION_ID.fullmatch(snapshot_id):
        return
    index_root = Path(config.DECRYPTED_DIR).resolve() / "indexes"
    if not index_root.is_dir():
        return
    for path in index_root.glob(f"{snapshot_id}-v*.sqlite*"):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def _prune_snapshots(current: dict, now=None):
    keep = {current["snapshot_id"], current.get("previous_snapshot_id")}
    cutoff = (time.time() if now is None else now) - _RETENTION_SECONDS
    with _state_lock:
        for metadata_path in _root().glob("s-*.json"):
            snapshot_id = metadata_path.stem
            if not _VERSION_ID.fullmatch(snapshot_id) or snapshot_id in keep:
                continue
            snap_dir = _root() / snapshot_id
            if _active_readers.get(str(snap_dir)):
                continue
            try:
                metadata = _read_json(metadata_path)
                created = datetime.fromisoformat(metadata["snapshot_time"]).timestamp()
                if created >= cutoff:
                    continue
                shutil.rmtree(snap_dir, ignore_errors=False)
                metadata_path.unlink(missing_ok=True)
                _remove_snapshot_indexes(snapshot_id)
            except (OSError, ValueError, KeyError, SnapshotError):
                continue


def _compute_manifest_fingerprint(candidate_dir: Path, db_signatures: dict | None) -> str:
    if db_signatures:
        payload = json.dumps(db_signatures, sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()
    items = []
    for p in sorted(candidate_dir.glob("*.db")):
        h = hashlib.sha256()
        with p.open("rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                h.update(block)
        items.append([p.name, h.hexdigest()])
    return hashlib.sha256(json.dumps(items).encode("utf-8")).hexdigest()


def publish_snapshot(candidate_dir: str | Path, *, db_signatures: dict | None = None, prepare_index=None) -> dict:
    """Validate a candidate snapshot directory and atomically publish it."""
    with _publish_guard():
        candidate = Path(candidate_dir).resolve()
        latest = validate_snapshot_dir(candidate)
        source_fingerprint = _compute_manifest_fingerprint(candidate, db_signatures)

        root = _root()
        try:
            current_pointer = _read_current()
        except SnapshotError:
            current_pointer = None

        previous = None
        previous_usable = False
        if current_pointer:
            try:
                previous = _version_info(current_pointer["snapshot_id"])
                validate_snapshot_dir(previous["path"], quick_check_core=False)
                previous_usable = True
            except SnapshotError:
                previous_usable = False

        if previous and latest < previous["latest_message_at"]:
            raise SnapshotError("候选快照的最新消息时间早于当前快照，已保留当前快照。")

        if current_pointer and previous_usable:
            try:
                old_meta = _read_json(root / f'{current_pointer["snapshot_id"]}.json')
            except SnapshotError:
                old_meta = {}
            if old_meta.get("source_fingerprint") == source_fingerprint:
                if prepare_index is not None:
                    prepare_index(previous["path"], previous["snapshot_id"])
                _prune_snapshots(current_pointer)
                return {"outcome": "unchanged", **previous}

        snapshot_id = f"s-{uuid.uuid4().hex}"
        staged_dir = root / f".{snapshot_id}.pending"
        final_dir = root / snapshot_id
        metadata_path = root / f"{snapshot_id}.json"
        published = False

        try:
            staged_dir.mkdir(parents=True, exist_ok=True)
            for db_file in sorted(candidate.glob("*.db")):
                dst = staged_dir / db_file.name
                try:
                    os.link(db_file, dst)
                except OSError:
                    shutil.copy2(db_file, dst)

            if prepare_index is not None:
                prepare_index(str(staged_dir), snapshot_id)

            os.replace(staged_dir, final_dir)
            metadata = {
                "snapshot_id": snapshot_id,
                "snapshot_time": _utc_time(),
                "latest_message_at": latest,
                "source_fingerprint": source_fingerprint,
                "db_signatures": db_signatures or {},
                "databases": sorted(p.name for p in final_dir.glob("*.db")),
            }
            _atomic_json(metadata_path, metadata)
            pointer = {
                "schema_version": 1,
                "snapshot_id": snapshot_id,
                "previous_snapshot_id": previous["snapshot_id"] if previous else None,
            }
            with _state_lock:
                _atomic_json(root / "current.json", pointer)
                published = True
            _prune_snapshots(pointer)
            return {"outcome": "updated", **_version_info(snapshot_id)}
        except (sqlite3.Error, OSError) as exc:
            raise SnapshotError(f"新快照发布失败，当前快照保持不变：{exc}") from exc
        finally:
            if staged_dir.exists():
                shutil.rmtree(staged_dir, ignore_errors=True)
            if not published:
                if final_dir.exists():
                    shutil.rmtree(final_dir, ignore_errors=True)
                metadata_path.unlink(missing_ok=True)
                _remove_snapshot_indexes(snapshot_id)
