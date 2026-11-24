"""WeChat 4.x media/attachment resolver, .dat/wxgf decryptor, and export packager."""

import ctypes
from functools import lru_cache
import hashlib
import logging
import os
from pathlib import Path
import re
import shutil
import sqlite3
import struct
import subprocess

from Crypto.Cipher import AES
from Crypto.Util import Padding

import config
import key_extractor
from log_utils import log_event

logger = logging.getLogger(__name__)

_V4_V1_MAGIC = bytes((0x07, 0x08, 0x56, 0x31, 0x08, 0x07))
_V4_V2_MAGIC = bytes((0x07, 0x08, 0x56, 0x32, 0x08, 0x07))
_V4_V1_AES_KEY = b"cfcd208495d565ef"
_MD5_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)
_MD5_PREFIX_RE = re.compile(r"^([0-9a-f]{32})(?:[_.-]|$)", re.IGNORECASE)
_WXGF_HEVC_START = b"\x00\x00\x00\x01\x40\x01"


def _xor_bytes(data: bytes, xor_key: int) -> bytes:
    if not data or xor_key == 0:
        return data
    table = bytes(b ^ xor_key for b in range(256))
    return data.translate(table)


def detect_image_media_type(data: bytes) -> str:
    if not data:
        return "application/octet-stream"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff") and len(data) >= 4 and data[3] >= 0xC0 and data[3] != 0xFF:
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        return "image/webp"
    return "application/octet-stream"


def extension_for_media_type(media_type: str) -> str:
    return {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/gif": ".gif",
        "image/webp": ".webp",
    }.get(media_type, ".bin")


def detect_wechat_dat_version(data: bytes) -> int:
    if len(data) >= 6:
        if data[:6] == _V4_V2_MAGIC:
            return 2
        if data[:6] == _V4_V1_MAGIC:
            return 1
    return 0


# ---------------------------------------------------------------------------
# WXGF (WeChat HEVC image) decoding via local VoipEngine.dll or ffmpeg
# ---------------------------------------------------------------------------

class _WxAMConfig(ctypes.Structure):
    _fields_ = [("mode", ctypes.c_int), ("reserved", ctypes.c_int)]


@lru_cache(maxsize=1)
def _load_wxam_decoder():
    if os.name != "nt":
        return None
    candidates = [Path(config.PROJECT_DIR) / "tools" / "VoipEngine.dll"]
    if config.WECHAT_DLL_PATH:
        candidates.append(Path(config.WECHAT_DLL_PATH).parent / "VoipEngine.dll")
    if config.WECHAT_EXE_PATH:
        exe_parent = Path(config.WECHAT_EXE_PATH).parent
        candidates.append(exe_parent / "VoipEngine.dll")
        try:
            for item in exe_parent.glob("*/VoipEngine.dll"):
                candidates.append(item)
        except OSError:
            pass

    for dll_path in candidates:
        if not dll_path.is_file():
            continue
        try:
            dll = ctypes.WinDLL(str(dll_path))
            fn = dll.wxam_dec_wxam2pic_5
            fn.argtypes = [
                ctypes.c_int64,
                ctypes.c_int,
                ctypes.c_int64,
                ctypes.POINTER(ctypes.c_int),
                ctypes.c_int64,
            ]
            fn.restype = ctypes.c_int64
            return fn
        except Exception:
            continue
    return None


def _decode_wxgf_with_ffmpeg(data: bytes) -> bytes | None:
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        return None
    starts = []
    pos = data.find(_WXGF_HEVC_START, 4)
    while pos >= 0 and len(starts) < 2:
        starts.append(pos)
        pos = data.find(_WXGF_HEVC_START, pos + len(_WXGF_HEVC_START))
    if not starts:
        return None
    last_start = starts[-1]
    if last_start < 4:
        return None
    size = int.from_bytes(data[last_start - 4:last_start], "big")
    if not (0 < size <= len(data) - last_start):
        return None
    stream = data[last_start:last_start + size]
    try:
        proc = subprocess.run(
            [
                ffmpeg, "-hide_banner", "-loglevel", "error",
                "-f", "hevc", "-i", "pipe:0",
                "-frames:v", "1", "-f", "image2pipe", "-codec:v", "mjpeg", "-q:v", "3", "pipe:1",
            ],
            input=stream,
            capture_output=True,
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
        if proc.returncode == 0 and detect_image_media_type(proc.stdout[:32]) == "image/jpeg":
            return proc.stdout
    except Exception:
        pass
    return None


def decode_wxgf_bytes(data: bytes) -> tuple[bytes, str]:
    if not data or not data.startswith((b"wxgf", b"WXGF")):
        return data, "application/octet-stream"

    fn = _load_wxam_decoder()
    if fn is not None:
        max_out = 32 * 1024 * 1024
        for mode in (0, 3):
            try:
                cfg = _WxAMConfig(mode=mode, reserved=0)
                in_buf = ctypes.create_string_buffer(data, len(data))
                out_buf = ctypes.create_string_buffer(max_out)
                out_sz = ctypes.c_int(max_out)
                rc = fn(
                    ctypes.addressof(in_buf),
                    len(data),
                    ctypes.addressof(out_buf),
                    ctypes.byref(out_sz),
                    ctypes.addressof(cfg),
                )
                if rc == 0 and out_sz.value > 0:
                    out = out_buf.raw[:out_sz.value]
                    mt = detect_image_media_type(out[:32])
                    if mt != "application/octet-stream":
                        return out, mt
            except Exception:
                continue

    converted = _decode_wxgf_with_ffmpeg(data)
    if converted:
        return converted, "image/jpeg"
    return data, "application/octet-stream"


def decrypt_wechat_dat_bytes(data: bytes, xor_key=None, aes_key=None) -> tuple[bytes, str]:
    """Decrypt WeChat .dat (v3 XOR, v4 V1 fixed AES, v4 V2 AES+XOR, plus wxgf) or passthrough plain image."""
    if not data:
        return data, "application/octet-stream"

    plain_mt = detect_image_media_type(data[:32])
    if plain_mt != "application/octet-stream":
        return data, plain_mt

    if data.startswith((b"wxgf", b"WXGF")):
        return decode_wxgf_bytes(data)

    version = detect_wechat_dat_version(data)
    if version in (1, 2):
        if len(data) < 0x0F:
            return data, "application/octet-stream"
        header, rest = data[:0x0F], data[0x0F:]
        _, aes_size, xor_size = struct.unpack("<6sLLx", header)
        aes_padded = aes_size + (16 - aes_size % 16)
        aes_block = rest[:aes_padded]

        key16 = _V4_V1_AES_KEY if version == 1 else (
            aes_key.encode("ascii")[:16] if isinstance(aes_key, str) else bytes(aes_key or b"")[:16]
        )
        if len(key16) == 16 and len(aes_block) >= 16 and len(aes_block) % 16 == 0:
            try:
                cipher = AES.new(key16, AES.MODE_ECB)
                dec_head = Padding.unpad(cipher.decrypt(aes_block), 16)
                if xor_size > 0 and xor_key is not None:
                    raw_mid = rest[aes_padded:-xor_size]
                    xor_tail = _xor_bytes(rest[-xor_size:], int(xor_key) & 0xFF)
                else:
                    raw_mid = rest[aes_padded:]
                    xor_tail = b""
                out = dec_head + raw_mid + xor_tail
                mt = detect_image_media_type(out[:32])
                if mt != "application/octet-stream":
                    return out, mt
                if out.startswith((b"wxgf", b"WXGF")):
                    return decode_wxgf_bytes(out)
            except Exception:
                pass
        return data, "application/octet-stream"

    # Version 0: pure XOR
    if xor_key is not None:
        out = _xor_bytes(data, int(xor_key) & 0xFF)
        mt = detect_image_media_type(out[:32])
        if mt != "application/octet-stream":
            return out, mt
        if out.startswith((b"wxgf", b"WXGF")):
            return decode_wxgf_bytes(out)

    for magic in (b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"RIFF"):
        if len(data) >= len(magic):
            k = data[0] ^ magic[0]
            if all((data[i] ^ k) == magic[i] for i in range(len(magic))):
                out = _xor_bytes(data, k)
                mt = detect_image_media_type(out[:32])
                if mt != "application/octet-stream":
                    return out, mt

    return data, "application/octet-stream"


# ---------------------------------------------------------------------------
# Fast cached hardlink.db + attach directory index (O(1) lookups per message)
# ---------------------------------------------------------------------------

def _variant_priority(path: Path) -> tuple[int, int]:
    low = path.name.lower()
    if low.endswith(("_h.dat", ".h.dat")):
        rank = 0
    elif low.endswith(("_t.dat", ".t.dat", "_thumb.dat")):
        rank = 3
    elif low.endswith(("_c.dat", ".c.dat")):
        rank = 2
    else:
        rank = 1
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    return (rank, -size)


def _get_hardlink_index(ctx) -> dict:
    """Load hardlink.db into an in-memory dict once per SnapshotContext."""
    cached = getattr(ctx, "_hardlink_index", None)
    if cached is not None:
        return cached

    index = {"dir_map": {}, "image": {}, "file": {}, "video": {}}
    conn = getattr(ctx, "hardlink_conn", None) if ctx is not None else None
    if conn is None:
        if ctx is not None:
            setattr(ctx, "_hardlink_index", index)
        return index

    try:
        for row in conn.execute("SELECT rowid, username FROM dir2id"):
            index["dir_map"][int(row[0])] = str(row[1] or "").strip()
    except sqlite3.Error:
        pass

    try:
        tables = [str(r[0] or "") for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    except sqlite3.Error:
        tables = []

    for kind, prefix in (("image", "image_hardlink_info"), ("file", "file_hardlink_info"), ("video", "video_hardlink_info")):
        tbl = next((t for t in tables if t.lower().startswith(prefix)), None)
        if not tbl:
            continue
        quoted = '"' + tbl.replace('"', '""') + '"'
        try:
            for row in conn.execute(f"SELECT md5, dir1, dir2, file_name FROM {quoted} ORDER BY modify_time DESC"):
                md5 = str(row[0] or "").strip().lower()
                fname = str(row[3] or "").strip()
                if md5 and fname:
                    index[kind].setdefault(md5, []).append((int(row[1] or 0), int(row[2] or 0), fname))
        except sqlite3.Error:
            continue

    if ctx is not None:
        setattr(ctx, "_hardlink_index", index)
    return index


def _get_chat_attach_index(ctx, acc_root: Path, cid: str) -> dict[str, list[Path]]:
    """Index msg/attach/<md5(cid)>/*/Img/ once per cid to avoid repeated filesystem globs."""
    cache = getattr(ctx, "_attach_dir_index", None) if ctx is not None else None
    if cache is None:
        cache = {}
        if ctx is not None:
            setattr(ctx, "_attach_dir_index", cache)
    key = (str(acc_root), cid)
    if key in cache:
        return cache[key]

    by_md5: dict[str, list[Path]] = {}
    chat_hash = hashlib.md5(cid.encode("utf-8")).hexdigest()
    attach_chat = acc_root / "msg" / "attach" / chat_hash
    if attach_chat.is_dir():
        try:
            for month_entry in os.scandir(attach_chat):
                if not month_entry.is_dir():
                    continue
                img_dir = Path(month_entry.path) / "Img"
                if not img_dir.is_dir():
                    continue
                try:
                    for file_entry in os.scandir(img_dir):
                        if not file_entry.is_file():
                            continue
                        m = _MD5_PREFIX_RE.match(Path(file_entry.name).stem)
                        if m:
                            by_md5.setdefault(m.group(1).lower(), []).append(Path(file_entry.path))
                except OSError:
                    continue
        except OSError:
            pass
    for paths in by_md5.values():
        if len(paths) > 1:
            paths.sort(key=_variant_priority)
    cache[key] = by_md5
    return by_md5


def _get_file_dir_index(ctx, acc_root: Path) -> dict[str, Path]:
    """Index msg/file/YYYY-MM/ filenames once per SnapshotContext."""
    cache = getattr(ctx, "_file_dir_index", None) if ctx is not None else None
    if cache is not None:
        return cache
    by_name: dict[str, Path] = {}
    file_root = acc_root / "msg" / "file"
    if file_root.is_dir():
        try:
            entries = sorted(os.scandir(file_root), key=lambda e: e.name, reverse=True)
            for entry in entries:
                if entry.is_file():
                    by_name.setdefault(entry.name, Path(entry.path))
                elif entry.is_dir():
                    try:
                        for sub in os.scandir(entry.path):
                            if sub.is_file():
                                by_name.setdefault(sub.name, Path(sub.path))
                    except OSError:
                        continue
        except OSError:
            pass
    if ctx is not None:
        setattr(ctx, "_file_dir_index", by_name)
    return by_name


def resolve_local_media_path(
    kind: str,
    md5: str = "",
    *,
    cid: str = "",
    filename: str = "",
    ctx=None,
    account_dir=None,
) -> Path | None:
    """Locate a local WeChat image/file/video on disk via cached hardlink.db & directory indexes."""
    acc_root = Path(account_dir or config.WECHAT_DATA_DIR)
    if not acc_root.is_dir():
        return None

    md5_low = str(md5 or "").strip().lower()

    # 1. O(1) lookup in cached hardlink.db index
    if ctx is not None and md5_low:
        hl = _get_hardlink_index(ctx)
        dir_map = hl["dir_map"]
        entries = hl.get(kind, {}).get(md5_low, ())
        if entries:
            candidates = []
            for d1_id, d2_id, fname in entries:
                d1 = dir_map.get(d1_id, "")
                d2 = dir_map.get(d2_id, "")
                if kind == "image":
                    probes = (
                        acc_root / "msg" / "attach" / d1 / d2 / "Img" / fname,
                        acc_root / "msg" / "attach" / d2 / d1 / "Img" / fname,
                        acc_root / "msg" / "attach" / d1 / "Img" / fname,
                        acc_root / "msg" / "attach" / d1 / d2 / fname,
                    )
                elif kind == "file":
                    probes = (
                        acc_root / "msg" / "file" / d2 / fname,
                        acc_root / "msg" / "file" / d1 / fname,
                        acc_root / "msg" / "file" / d1 / d2 / fname,
                        acc_root / "msg" / "file" / fname,
                    )
                else:
                    probes = (
                        acc_root / "msg" / "video" / d2 / fname,
                        acc_root / "msg" / "video" / d1 / fname,
                        acc_root / "msg" / "video" / fname,
                    )
                for base in probes:
                    if base.is_file():
                        candidates.append(base)
                        break
            if candidates:
                candidates.sort(key=_variant_priority)
                return candidates[0]

    # 2. O(1) lookup in cached chat attach directory index
    if kind == "image" and md5_low and cid:
        by_md5 = _get_chat_attach_index(ctx, acc_root, cid)
        hits = by_md5.get(md5_low)
        if hits:
            return hits[0]

    # 3. O(1) lookup in cached msg/file directory index
    if kind == "file" and filename:
        by_name = _get_file_dir_index(ctx, acc_root)
        hit = by_name.get(filename)
        if hit and hit.is_file():
            return hit

    return None


def get_or_decrypt_cached_image(
    md5: str,
    *,
    cid: str = "",
    ctx=None,
    account_dir=None,
) -> Path | None:
    """Return path to a decrypted image file in MEDIA_CACHE_DIR, decrypting .dat/wxgf if needed."""
    md5_low = str(md5 or "").strip().lower()
    if not _MD5_RE.fullmatch(md5_low):
        return None

    cache_dir = Path(config.MEDIA_CACHE_DIR) / md5_low[:2]
    for ext in (".jpg", ".png", ".gif", ".webp"):
        existing = cache_dir / f"{md5_low}{ext}"
        if existing.is_file() and existing.stat().st_size > 16:
            return existing

    src = resolve_local_media_path("image", md5_low, cid=cid, ctx=ctx, account_dir=account_dir)
    if src is None or not src.is_file():
        return None

    try:
        raw = src.read_bytes()
    except OSError:
        return None

    keys = key_extractor.get_or_resolve_image_keys(account_dir)
    data, media_type = decrypt_wechat_dat_bytes(raw, xor_key=keys.get("xor"), aes_key=keys.get("aes"))
    if not media_type.startswith("image/"):
        return None

    ext = extension_for_media_type(media_type)
    cache_dir.mkdir(parents=True, exist_ok=True)
    out = cache_dir / f"{md5_low}{ext}"
    tmp = cache_dir / f".{md5_low}.{os.getpid()}.tmp"
    try:
        tmp.write_bytes(data)
        os.replace(tmp, out)
        return out
    except OSError:
        tmp.unlink(missing_ok=True)
        return None


# ---------------------------------------------------------------------------
# Export attachment packaging (images/ and files/)
# ---------------------------------------------------------------------------

def _sanitize_filename(filename: str) -> str:
    invalid_chars = '<>:"/\\|?*'
    for ch in invalid_chars:
        filename = filename.replace(ch, "_")
    if len(filename) > 200:
        name, ext = os.path.splitext(filename)
        filename = name[:200] + ext
    return filename or "unnamed"


def copy_attachment_to_export(src_path, export_path) -> bool:
    if not src_path or not os.path.exists(src_path):
        return False
    try:
        os.makedirs(os.path.dirname(export_path), exist_ok=True)
        shutil.copy2(src_path, export_path)
        return True
    except (OSError, shutil.Error) as exc:
        log_event(
            logger,
            "warning",
            "attachment.copy_failed",
            source_path=str(src_path),
            export_path=str(export_path),
            error=exc,
        )
        return False


def process_all_attachments(messages, export_dir, ctx=None) -> dict:
    """Decrypt/copy images and file attachments into export_dir/images and export_dir/files."""
    stats = {"images": 0, "files": 0, "skipped": 0, "errors": 0}
    img_dir = os.path.join(export_dir, "images")
    file_dir = os.path.join(export_dir, "files")

    for msg in messages:
        cid = str(msg.get("cid") or "")
        mid = str(msg.get("id") or "unknown")
        img_info = msg.get("image_info") or {}

        if img_info:
            images = img_info.get("images") or [img_info]
            exported_paths = []
            for idx, img in enumerate(images):
                md5 = str(img.get("md5") or img.get("thumb_md5") or "").strip().lower()
                local_path = img.get("local_path") or ""
                cached_img = None
                if local_path and os.path.isfile(local_path) and not local_path.lower().endswith(".dat"):
                    cached_img = Path(local_path)
                elif md5:
                    cached_img = get_or_decrypt_cached_image(md5, cid=cid, ctx=ctx)

                if cached_img is None or not cached_img.is_file():
                    exported_paths.append(None)
                    stats["skipped"] += 1
                    continue

                ext = cached_img.suffix or ".jpg"
                safe_cid = _sanitize_filename(cid)[:32]
                suffix = f"_{idx}" if len(images) > 1 else ""
                fname = _sanitize_filename(f"{safe_cid}_{mid}{suffix}{ext}")
                dst = os.path.join(img_dir, fname)
                if copy_attachment_to_export(str(cached_img), dst):
                    rel = os.path.relpath(dst, export_dir).replace("\\", "/")
                    exported_paths.append(rel)
                    stats["images"] += 1
                else:
                    exported_paths.append(None)
                    stats["errors"] += 1

            primary = next((p for p in exported_paths if p), None)
            if primary:
                msg["attachment_export_path"] = primary
            msg["image_export_paths"] = exported_paths

        for att in msg.get("attachments") or []:
            local_path = att.get("local_path") or ""
            if not local_path or not os.path.isfile(local_path):
                resolved = resolve_local_media_path(
                    "file",
                    att.get("md5", ""),
                    cid=cid,
                    filename=att.get("filename", ""),
                    ctx=ctx,
                )
                if resolved is not None and resolved.is_file():
                    local_path = str(resolved)
                    att["local_path"] = local_path
                    att["local_available"] = True
            if not local_path or not os.path.isfile(local_path):
                if att.get("filename"):
                    stats["skipped"] += 1
                continue

            fname = _sanitize_filename(att.get("filename") or os.path.basename(local_path))
            dst = os.path.join(file_dir, fname)
            if os.path.exists(dst):
                name, ext = os.path.splitext(dst)
                dst = f"{name}_{_sanitize_filename(mid)}{ext}"
            if copy_attachment_to_export(local_path, dst):
                att["export_path"] = os.path.relpath(dst, export_dir).replace("\\", "/")
                stats["files"] += 1
            else:
                stats["errors"] += 1

    log_event(
        logger,
        "info",
        "attachment.processed",
        image_count=stats["images"],
        file_count=stats["files"],
        skipped_count=stats["skipped"],
        error_count=stats["errors"],
    )
    return stats
