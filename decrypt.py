"""WeChat 4.x SQLCipher 4.0 database decryption, WAL merge, and atomic snapshot publishing."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import tempfile
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import config
import key_extractor
from log_utils import log_event

logger = logging.getLogger(__name__)

SQLITE_HEADER = b"SQLite format 3\x00"
PAGE_SIZE = 4096
SALT_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 64
RESERVE_SIZE = IV_SIZE + HMAC_SIZE  # 80 bytes

# Source DB categories we need for full chat browsing, search, contact resolution, and attachment export.
# Skips huge FTS index DBs (*_fts.db) and unrelated auxiliary DBs.
_REQUIRED_CORE_DB_NAMES = ("session.db", "contact.db")
_OPTIONAL_DB_NAMES = {
    "hardlink.db",
    "head_image.db",
    "emoticon.db",
    "message_resource.db",
}


def _should_decrypt_source_db(file_name: str) -> bool:
    low = file_name.lower()
    if not low.endswith(".db"):
        return False
    if low == "key_info.db" or low.endswith("_fts.db"):
        return False
    if low in _REQUIRED_CORE_DB_NAMES or low in _OPTIONAL_DB_NAMES:
        return True
    if low.startswith("message_") or low == "message.db":
        return True
    if low.startswith("biz_message_"):
        return True
    return False


# ---------------------------------------------------------------------------
# SQLite / SQLCipher WAL snapshot merge (without mutating source files)
# ---------------------------------------------------------------------------

def _wal_checksum(data: bytes, endian: str, state: tuple[int, int] = (0, 0)) -> tuple[int, int]:
    a, b = state
    for x, y in struct.iter_unpack(endian + "II", data):
        a = (a + x + b) & 0xFFFFFFFF
        b = (b + y + a) & 0xFFFFFFFF
    return a, b


def merge_wal_snapshot(database: bytes, wal: bytes, page_size: int = PAGE_SIZE, verify_page=None):
    """Apply checksum-valid committed WAL frames over a database buffer."""
    info = {
        "wal_bytes": len(wal),
        "committed_frames": 0,
        "applied_pages": 0,
        "ignored_tail_bytes": 0,
        "database_pages": len(database) // page_size,
    }
    if not wal:
        return database, info
    if len(wal) < 32:
        raise ValueError("WAL 文件头不完整")
    magic, version, wal_page_size = struct.unpack(">III", wal[:12])
    if magic not in (0x377F0682, 0x377F0683) or version != 3007000:
        raise ValueError("WAL 文件头或版本无效")
    if wal_page_size != page_size or len(database) % page_size:
        raise ValueError("WAL 与数据库页大小不匹配，或主数据库页不完整")

    endian = "<" if magic == 0x377F0682 else ">"
    state = _wal_checksum(wal[:24], endian)
    if state != struct.unpack(">II", wal[24:32]):
        raise ValueError("WAL 文件头校验失败")

    salt = wal[16:24]
    frame_size = 24 + page_size
    pending = {}
    committed = {}
    base_pages = len(database) // page_size
    size = base_pages
    commit_end = 32

    for offset in range(32, len(wal) - frame_size + 1, frame_size):
        header = wal[offset:offset + 24]
        if header[8:16] != salt:
            break
        pgno, db_size = struct.unpack(">II", header[:8])
        if pgno == 0 or pgno > 0xFFFFFFFE:
            raise ValueError("WAL 页号无效")
        page = wal[offset + 24:offset + frame_size]
        state = _wal_checksum(page, endian, _wal_checksum(header[:8], endian, state))
        if state != struct.unpack(">II", header[16:24]):
            raise ValueError("WAL 帧校验失败")
        pending[pgno] = page
        if db_size:
            committed.update(pending)
            pending.clear()
            committed = {n: p for n, p in committed.items() if n <= db_size}
            base_pages = min(base_pages, db_size)
            extension = sum(n > base_pages for n in committed)
            if db_size - base_pages != extension:
                raise ValueError("WAL 提交缺少数据库扩展页")
            size = db_size
            commit_end = offset + frame_size
            info["committed_frames"] = (commit_end - 32) // frame_size

    info.update(
        applied_pages=len(committed),
        ignored_tail_bytes=len(wal) - commit_end,
        database_pages=size,
    )
    if not info["committed_frames"]:
        return database, info

    output = bytearray(database[:base_pages * page_size])
    output.extend(b"\x00" * (size * page_size - len(output)))
    for pgno, page in committed.items():
        if verify_page is not None and not verify_page(page, pgno):
            raise ValueError(f"WAL 第 {pgno} 页 HMAC 校验失败")
        output[(pgno - 1) * page_size:pgno * page_size] = page
    return bytes(output), info


# ---------------------------------------------------------------------------
# Single SQLCipher 4.0 DB decryption (streaming/chunked for low peak RAM)
# ---------------------------------------------------------------------------

def _decrypt_page(enc_key: bytes, page: bytes, page_num: int) -> bytes:
    iv = page[PAGE_SIZE - RESERVE_SIZE:PAGE_SIZE - RESERVE_SIZE + IV_SIZE]
    offset = SALT_SIZE if page_num == 1 else 0
    encrypted_payload = page[offset:PAGE_SIZE - RESERVE_SIZE]
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plain = decryptor.update(encrypted_payload) + decryptor.finalize()
    if page_num == 1:
        return SQLITE_HEADER + plain + (b"\x00" * RESERVE_SIZE)
    return plain + (b"\x00" * RESERVE_SIZE)


def _source_file_signature(db_path: Path) -> list:
    sig = []
    for path in (db_path, Path(str(db_path) + "-wal")):
        try:
            st = path.stat()
            sig.append([int(st.st_size), int(st.st_mtime_ns)])
        except FileNotFoundError:
            sig.append(None)
    return sig


def _read_stable_pair(src_db: Path, retry_count=None, retry_delay=None) -> tuple[bytes, bytes, list]:
    """Read (db_bytes, wal_bytes, signature) ensuring neither changed mid-read."""
    retries = config.COPY_RETRY_COUNT if retry_count is None else retry_count
    delay = config.COPY_RETRY_DELAY if retry_delay is None else retry_delay
    wal_path = Path(str(src_db) + "-wal")

    for attempt in range(max(1, retries)):
        try:
            before = _source_file_signature(src_db)
            db_bytes = src_db.read_bytes()
            wal_bytes = wal_path.read_bytes() if wal_path.is_file() else b""
            after = _source_file_signature(src_db)
            if before != after:
                raise OSError(f"{src_db.name} 或其 WAL 在读取期间发生变化")
            return db_bytes, wal_bytes, before
        except OSError as exc:
            if attempt < retries - 1:
                log_event(
                    logger,
                    "warning",
                    "decrypt.copy_retry_failed",
                    db=src_db.name,
                    attempt=attempt + 1,
                    error=exc,
                )
                time.sleep(delay)
            else:
                raise RuntimeError(f"读取微信数据库 {src_db.name} 失败: {exc}") from exc
    raise RuntimeError(f"读取微信数据库 {src_db.name} 失败")


def decrypt_single_database(
    src_db: str | Path,
    output_path: str | Path,
    key_hex: str,
    *,
    verify_all_hmac: bool = False,
) -> dict:
    """Decrypt one WeChat 4.x SQLCipher 4.0 DB (with WAL merge) to output_path."""
    t0 = time.perf_counter()
    src = Path(src_db)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    key_bytes = bytes.fromhex(key_hex)
    db_bytes, wal_bytes, signature = _read_stable_pair(src)
    if len(db_bytes) < PAGE_SIZE:
        raise RuntimeError(f"数据库文件过小: {src.name} ({len(db_bytes)} bytes)")

    # Plain SQLite passthrough (useful for synthetic test fixtures)
    if db_bytes.startswith(SQLITE_HEADER):
        plain_page_size = int.from_bytes(db_bytes[16:18], "big")
        if plain_page_size == 1:
            plain_page_size = 65536
        merged, wal_info = merge_wal_snapshot(db_bytes, wal_bytes, plain_page_size)
        buf = bytearray(merged)
        if wal_info["committed_frames"]:
            buf[28:32] = wal_info["database_pages"].to_bytes(4, "big")
        if buf[18:20] == b"\x02\x02":
            buf[18:20] = b"\x01\x01"
        out.write_bytes(bytes(buf))
        return {
            "db_name": src.name,
            "source_signature": signature,
            "wal_frames": wal_info["committed_frames"],
            "pages": len(buf) // plain_page_size,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
            "reused": False,
        }

    page1 = db_bytes[:PAGE_SIZE]
    resolved = key_extractor.resolve_page1_key_material(key_bytes, page1)
    if resolved is None:
        raise RuntimeError(f"密钥校验失败，无法解密 {src.name} (Page 1 HMAC mismatch)")
    enc_key, mac_key, key_mode = resolved

    merged_encrypted, wal_info = merge_wal_snapshot(
        db_bytes,
        wal_bytes,
        PAGE_SIZE,
        verify_page=lambda page, pgno: hmac.compare_digest(
            page[-HMAC_SIZE:], key_extractor.compute_page_hmac(mac_key, page, pgno)
        ),
    )
    del db_bytes
    del wal_bytes

    total_pages = (len(merged_encrypted) + PAGE_SIZE - 1) // PAGE_SIZE
    hmac_warnings = 0

    with out.open("wb") as stream:
        for cur in range(total_pages):
            page_num = cur + 1
            start = cur * PAGE_SIZE
            page = merged_encrypted[start:start + PAGE_SIZE]
            if len(page) < PAGE_SIZE:
                page = page + (b"\x00" * (PAGE_SIZE - len(page)))

            if verify_all_hmac and page_num > 1:
                stored = page[PAGE_SIZE - HMAC_SIZE:PAGE_SIZE]
                expected = key_extractor.compute_page_hmac(mac_key, page, page_num)
                if not hmac.compare_digest(stored, expected):
                    hmac_warnings += 1

            plain = _decrypt_page(enc_key, page, page_num)
            if page_num == 1:
                p1 = bytearray(plain)
                if wal_info["committed_frames"]:
                    p1[28:32] = wal_info["database_pages"].to_bytes(4, "big")
                if p1[18:20] == b"\x02\x02":
                    p1[18:20] = b"\x01\x01"
                plain = bytes(p1)
            stream.write(plain)

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
    log_event(
        logger,
        "info",
        "decrypt.db_completed",
        db=src.name,
        pages=total_pages,
        wal_frames=wal_info["committed_frames"],
        hmac_warnings=hmac_warnings,
        elapsed_ms=elapsed_ms,
    )
    return {
        "db_name": src.name,
        "source_signature": signature,
        "key_mode": key_mode,
        "wal_frames": wal_info["committed_frames"],
        "pages": total_pages,
        "hmac_warnings": hmac_warnings,
        "elapsed_ms": elapsed_ms,
        "reused": False,
    }


def discover_source_databases(db_storage_dir=None) -> list[Path]:
    storage = Path(db_storage_dir or config.ENCRYPTED_DB_DIR)
    if not storage.is_dir():
        raise FileNotFoundError(
            f"未找到微信加密数据库目录: {storage}\n"
            "请确认微信桌面客户端已登录，并检查自动检测到的数据目录是否正确。"
        )
    found = {}
    for root, _, files in os.walk(storage):
        for fname in files:
            if _should_decrypt_source_db(fname):
                key = fname.lower()
                if key not in found:
                    found[key] = Path(root) / fname
    result = sorted(found.values(), key=lambda p: p.name.lower())
    if not result:
        raise FileNotFoundError(f"在 {storage} 中未找到可解密的微信数据库文件。")
    return result


def _try_link_or_copy(src: Path, dst: Path) -> None:
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def _load_previous_manifest() -> tuple[Path | None, dict]:
    from snapshots import resolve_snapshot

    try:
        prev = resolve_snapshot()
        prev_dir = Path(prev["path"])
        manifest_path = prev_dir.parent / f"{prev['snapshot_id']}.json"
        if prev_dir.is_dir() and manifest_path.is_file():
            meta = json.loads(manifest_path.read_text(encoding="utf-8"))
            return prev_dir, meta.get("db_signatures") or {}
    except Exception:
        pass
    return None, {}


def _prepare_snapshot_index(snapshot_dir, snapshot_id):
    from search_index import prepare_snapshot_index

    prepare_snapshot_index(snapshot_dir, snapshot_id)


def decrypt_all_to_directory(
    db_storage_dir=None,
    output_dir=None,
    key_hex=None,
    *,
    reuse_from_dir: Path | None = None,
    reuse_signatures: dict | None = None,
    max_workers: int | None = None,
) -> dict:
    """Decrypt all chat-relevant WeChat 4.x DBs into output_dir, reusing unchanged DBs."""
    storage = Path(db_storage_dir or config.ENCRYPTED_DB_DIR)
    sources = discover_source_databases(storage)
    if not key_hex:
        key_hex = key_extractor.get_or_extract_db_key(storage)
    else:
        probe = next((p for p in sources if p.name.lower() == "session.db"), sources[0])
        if not key_extractor.verify_key_against_db(key_hex, probe):
            raise RuntimeError(f"密钥校验失败，无法解密 {probe.name} (Page 1 HMAC mismatch)")

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    reuse_sigs = reuse_signatures or {}

    to_decrypt: list[Path] = []
    db_signatures: dict[str, list] = {}
    details: dict[str, dict] = {}

    for src in sources:
        sig = _source_file_signature(src)
        prev_sig = reuse_sigs.get(src.name)
        prev_file = (reuse_from_dir / src.name) if reuse_from_dir else None
        if prev_file and prev_file.is_file() and prev_sig == sig:
            _try_link_or_copy(prev_file, out_dir / src.name)
            db_signatures[src.name] = sig
            details[src.name] = {"db_name": src.name, "reused": True, "source_signature": sig}
            log_event(logger, "info", "decrypt.db_reused", db=src.name)
        else:
            to_decrypt.append(src)

    if to_decrypt:
        # Decrypt largest files first for optimal thread-pool load balancing
        to_decrypt.sort(key=lambda p: p.stat().st_size, reverse=True)
        workers = max(1, min(max_workers or (os.cpu_count() or 4), len(to_decrypt), 6))

        def _work(src_path: Path):
            return decrypt_single_database(src_path, out_dir / src_path.name, key_hex)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {pool.submit(_work, src): src for src in to_decrypt}
            for fut in as_completed(future_map):
                src_path = future_map[fut]
                try:
                    info = fut.result()
                    db_signatures[src_path.name] = info["source_signature"]
                    details[src_path.name] = info
                except Exception as exc:
                    log_event(logger, "warning", "decrypt.db_failed", db=src_path.name, error=exc)
                    # Required DBs must succeed; optional auxiliary DBs (like emoticon) warn & continue
                    if src_path.name.lower() in _REQUIRED_CORE_DB_NAMES or src_path.name.lower().startswith("message_"):
                        raise

    return {
        "output_dir": str(out_dir),
        "db_signatures": db_signatures,
        "details": details,
    }


def refresh_database(db_storage_dir=None, key_hex=None, build_index: bool = False):
    """Refresh immutable query snapshot from local WeChat DBs; keep old snapshot on failure."""
    from snapshots import SnapshotError, publish_snapshot, resolve_snapshot, validate_snapshot_dir

    os.makedirs(config.DECRYPTED_DIR, exist_ok=True)
    prev_dir, prev_sigs = _load_previous_manifest()

    try:
        # Also opportunistically resolve local image keys so image previews work right away
        try:
            key_extractor.get_or_resolve_image_keys()
        except Exception:
            pass

        with tempfile.TemporaryDirectory(prefix="wechat_candidate_", dir=config.DECRYPTED_DIR) as tmp_dir:
            dec_info = decrypt_all_to_directory(
                db_storage_dir=db_storage_dir,
                output_dir=tmp_dir,
                key_hex=key_hex,
                reuse_from_dir=prev_dir,
                reuse_signatures=prev_sigs,
            )
            prepare_cb = _prepare_snapshot_index if build_index else None
            result = publish_snapshot(
                tmp_dir,
                db_signatures=dec_info["db_signatures"],
                prepare_index=prepare_cb,
            )
            log_event(
                logger,
                "info",
                "decrypt.refresh_completed",
                outcome=result["outcome"],
                snapshot_id=result["snapshot_id"],
                latest_message_at=result.get("latest_message_at"),
            )
            return result
    except Exception as exc:
        log_event(logger, "warning", "decrypt.refresh_failed", error=exc)
        try:
            previous = resolve_snapshot()
            validate_snapshot_dir(previous["path"])
        except (SnapshotError, OSError, sqlite3.Error):
            return {
                "outcome": "failed",
                "snapshot_id": None,
                "snapshot_time": None,
                "latest_message_at": None,
                "path": None,
                "error": str(exc),
            }
        return {"outcome": "fallback", **previous, "error": str(exc)}


def sync_decrypt():
    """Compatibility entry point returning the usable query-snapshot directory path."""
    result = refresh_database()
    if result["outcome"] == "failed":
        raise RuntimeError(result["error"])
    return result["path"]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    res = refresh_database()
    print(json.dumps(res, ensure_ascii=False, indent=2))
