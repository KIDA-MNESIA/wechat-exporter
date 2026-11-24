"""WeChat 4.x database key extraction, caching, validation, and local image key resolution.

Adapted from WeChatDataAnalysis:
- Scans Weixin.dll PE code sections for 32-byte internal_db_key candidates.
- Scans running Weixin.exe memory with YARA + entropy filtering.
- Verifies candidates against page-1 SQLCipher 4.0 HMAC-SHA512 using ThreadPoolExecutor
  (GIL-free C crypto, safe inside FastAPI/MCP worker threads without Windows spawn issues).
- Resolves WeChat 4.x .dat V2 image XOR & AES keys locally from kvcomm + _t.dat templates.
"""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import ctypes
from ctypes import wintypes
import hashlib
import heapq
import hmac
import json
import logging
import os
from pathlib import Path
import re
import struct
import sys
import threading
import time
import uuid

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import config
from log_utils import log_event

logger = logging.getLogger(__name__)

# SQLCipher 4.0 constants
SQLITE_HEADER = b"SQLite format 3\x00"
PAGE_SIZE = 4096
KEY_SIZE = 32
SALT_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 64
RESERVE_SIZE = IV_SIZE + HMAC_SIZE  # 80 bytes
PBKDF2_ROUNDS = 256000

# Weixin.dll internal_db_key signature (4 x `mov rdx, imm64` + `test rax, rax`)
_DLL_KEY_PATTERN = re.compile(
    b"^\x48\xBA(.{8})"
    b".{3,8}?"
    b"\x48\xBA(.{8})"
    b".{3,8}?"
    b"\x48\xBA(.{8})"
    b".{3,8}?"
    b"\x48\xBA(.{8})"
    b".{3,8}?"
    b"\x48\x85\xC0",
    re.DOTALL,
)
_CODE_SECTION_CHAR = 0x20000000

# WeChat 4.x YARA memory stub for key pointer
_YARA_V4_RULE = r"""
rule GetKeyAddrStub
{
    strings:
        $a = { ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 2f 00 00 00 00 00 00 00 }
    condition:
        all of them
}
"""

# V2 .dat image header
V2_DAT_MAGIC = bytes((0x07, 0x08, 0x56, 0x32, 0x08, 0x07))
V2_CIPHERTEXT_START = 0x0F
_KVCOMM_FILE_RE = re.compile(r"^key_(\d+)_.+\.statistic$", re.IGNORECASE)
_MONTH_DIR_RE = re.compile(r"^\d{4}-\d{2}$")

_key_store_lock = threading.Lock()
_image_key_mem_cache: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# SQLCipher 4.0 page-1 verification helpers
# ---------------------------------------------------------------------------

def derive_sqlcipher_enc_key(key_material: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", key_material, salt, PBKDF2_ROUNDS, dklen=KEY_SIZE)


def derive_mac_key(enc_key: bytes, salt: bytes) -> bytes:
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SIZE)


def compute_page_hmac(mac_key: bytes, page: bytes, page_num: int) -> bytes:
    offset = SALT_SIZE if page_num == 1 else 0
    data_end = PAGE_SIZE - RESERVE_SIZE + IV_SIZE
    mac = hmac.new(mac_key, digestmod=hashlib.sha512)
    mac.update(page[offset:data_end])
    mac.update(page_num.to_bytes(4, "little"))
    return mac.digest()


def resolve_page1_key_material(key_material: bytes, page1: bytes):
    """Return (enc_key, mac_key, mode) if key_material authenticates page1, else None."""
    if len(page1) < PAGE_SIZE or len(key_material) != KEY_SIZE:
        return None
    salt = page1[:SALT_SIZE]
    stored = page1[PAGE_SIZE - HMAC_SIZE:PAGE_SIZE]

    # Try raw enc_key first (cheap, 2 PBKDF2 rounds)
    mac_key_raw = derive_mac_key(key_material, salt)
    if hmac.compare_digest(stored, compute_page_hmac(mac_key_raw, page1, 1)):
        return key_material, mac_key_raw, "raw_enc_key"

    # Try SQLCipher 4.0 passphrase (256,000 PBKDF2-SHA512 rounds)
    enc_key = derive_sqlcipher_enc_key(key_material, salt)
    mac_key = derive_mac_key(enc_key, salt)
    if hmac.compare_digest(stored, compute_page_hmac(mac_key, page1, 1)):
        return enc_key, mac_key, "sqlcipher_passphrase"

    return None


def verify_key_against_db(key_hex: str, db_path) -> bool:
    """Verify a 64-hex key against the first page of a database file."""
    cleaned = _normalize_hex_key(key_hex)
    if not cleaned:
        return False
    path = Path(db_path)
    if not path.is_file():
        return False
    try:
        with path.open("rb") as f:
            page1 = f.read(PAGE_SIZE)
    except OSError:
        return False
    if len(page1) < PAGE_SIZE:
        return False
    if page1.startswith(SQLITE_HEADER):
        return True
    return resolve_page1_key_material(bytes.fromhex(cleaned), page1) is not None


def _normalize_hex_key(value) -> str:
    raw = str(value or "").strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if re.fullmatch(r"[0-9a-f]{64}", raw):
        return raw
    return ""


def _xor_bytes_32(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# Persistent key store (data/keys.json)
# ---------------------------------------------------------------------------

def _read_key_store() -> dict:
    path = Path(config.KEYS_FILE)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_key_store(data: dict) -> None:
    path = Path(config.KEYS_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with open(tmp, "x", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def get_cached_account_keys(account_id=None) -> dict:
    account = config.clean_wxid(account_id or config.USER_WXID)
    with _key_store_lock:
        store = _read_key_store()
        entry = store.get(account) or store.get(str(account_id or "")) or {}
        return dict(entry) if isinstance(entry, dict) else {}


def save_account_keys(account_id=None, **fields) -> None:
    account = config.clean_wxid(account_id or config.USER_WXID)
    if not account:
        return
    with _key_store_lock:
        store = _read_key_store()
        entry = dict(store.get(account) or {})
        for k, v in fields.items():
            if v is not None:
                entry[k] = v
        entry["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        store[account] = entry
        _write_key_store(store)


# ---------------------------------------------------------------------------
# DLL internal key scan (PE code sections)
# ---------------------------------------------------------------------------

def extract_internal_db_keys_from_dll(dll_path=None) -> list[bytes]:
    """Scan Weixin.dll executable sections for 32-byte internal_db_key candidates."""
    try:
        import pefile
    except ImportError as exc:
        raise RuntimeError("缺少 pefile 依赖，无法扫描 Weixin.dll 辅助密钥") from exc

    target = Path(dll_path or config.WECHAT_DLL_PATH).expanduser()
    if not target.is_file():
        info = config.detect_wechat_installation()
        if info.get("wechat_dll_path"):
            target = Path(info["wechat_dll_path"])
    if not target.is_file():
        raise FileNotFoundError(f"未找到 Weixin.dll: {target}")

    pe = pefile.PE(str(target), fast_load=True)
    sections = []
    try:
        for sec in pe.sections:
            if int(sec.Characteristics) & _CODE_SECTION_CHAR:
                sections.append((int(sec.PointerToRawData), int(sec.SizeOfRawData)))
    finally:
        pe.close()

    keys: list[bytes] = []
    seen: set[bytes] = set()
    chunk_size = 4 * 1024 * 1024
    overlap = 100

    with target.open("rb") as f:
        for sec_offset, sec_size in sections:
            for pos in range(0, sec_size, chunk_size):
                read_len = min(chunk_size, sec_size - pos)
                f.seek(sec_offset + pos)
                data = f.read(read_len + overlap)
                idx = 0
                while True:
                    hit = data.find(b"\x48\xBA", idx)
                    if hit == -1 or hit >= read_len:
                        break
                    m = _DLL_KEY_PATTERN.match(data[hit:hit + 85])
                    if m:
                        candidate = m.group(1) + m.group(2) + m.group(3) + m.group(4)
                        if len(candidate) == KEY_SIZE and candidate not in seen:
                            seen.add(candidate)
                            keys.append(candidate)
                        idx = hit + len(m.group(0))
                    else:
                        idx = hit + 1

    log_event(logger, "info", "key.dll_scan_completed", dll=str(target), candidate_count=len(keys))
    return keys


# ---------------------------------------------------------------------------
# Windows Weixin.exe memory scan (V4 key recovery, zero restart)
# ---------------------------------------------------------------------------

class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


def _is_potential_key(key: bytes) -> bool:
    if len(key) != KEY_SIZE:
        return False
    if len(set(key)) < 15:
        return False
    printable = sum(32 <= b <= 126 for b in key)
    if printable > 24:
        return False
    return True


def _find_wechat_main_pid() -> tuple[int, str]:
    import psutil

    targets = {name.lower() for name in config.WECHAT_EXECUTABLE_NAMES}
    candidates = []
    for proc in psutil.process_iter(["pid", "name", "cmdline", "memory_info"]):
        try:
            name = str(proc.info.get("name") or "")
            if name.lower() not in targets:
                continue
            cmdline = " ".join(proc.info.get("cmdline") or [])
            # Skip Chromium/renderer/helper subprocesses (--type=...)
            is_helper = "--type=" in cmdline.lower()
            rss = getattr(proc.info.get("memory_info"), "rss", 0) or 0
            candidates.append((is_helper, len(cmdline), -rss, int(proc.info["pid"]), name))
        except (psutil.Error, OSError):
            continue
    if not candidates:
        raise RuntimeError("未找到运行中的微信进程 (Weixin.exe / WeChat.exe)，请先登录桌面版微信。")
    candidates.sort()
    _, _, _, pid, name = candidates[0]
    return pid, name


def _scan_process_memory_candidates(pid: int) -> list[bytes]:
    if os.name != "nt":
        raise RuntimeError("V4 内存密钥扫描仅支持 Windows。")
    try:
        import yara
    except ImportError as exc:
        raise RuntimeError("缺少 yara-python 依赖，无法执行内存扫描。") from exc

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    OpenProcess.restype = wintypes.HANDLE
    ReadProcessMemory = kernel32.ReadProcessMemory
    ReadProcessMemory.argtypes = [
        wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    ReadProcessMemory.restype = wintypes.BOOL
    VirtualQueryEx = kernel32.VirtualQueryEx
    VirtualQueryEx.argtypes = [
        wintypes.HANDLE, wintypes.LPCVOID,
        ctypes.POINTER(_MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
    ]
    VirtualQueryEx.restype = ctypes.c_size_t
    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [wintypes.HANDLE]
    CloseHandle.restype = wintypes.BOOL

    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    PAGE_NOACCESS = 0x01
    PAGE_GUARD = 0x100

    handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        raise RuntimeError(f"无法打开微信进程 (PID={pid}) 读取内存，请检查权限。")

    try:
        regions = []
        mbi = _MEMORY_BASIC_INFORMATION()
        address = 0
        max_addr = 0x7FFFFFFFFFFF
        while address < max_addr and VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            region_size = int(mbi.RegionSize or 0)
            if region_size <= 0:
                break
            if (
                mbi.State == MEM_COMMIT
                and mbi.Type == MEM_PRIVATE
                and not (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
                and region_size <= 256 * 1024 * 1024
            ):
                regions.append((int(mbi.BaseAddress or 0), region_size))
            address = int(mbi.BaseAddress or 0) + region_size

        rules = yara.compile(source=_YARA_V4_RULE)
        addresses: set[int] = set()

        for base_addr, region_size in regions:
            buf = ctypes.create_string_buffer(region_size)
            bytes_read = ctypes.c_size_t(0)
            if not ReadProcessMemory(handle, ctypes.c_void_p(base_addr), buf, region_size, ctypes.byref(bytes_read)):
                continue
            data = buf.raw[:bytes_read.value]
            if not data:
                continue
            matches = rules.match(data=data)
            for match in matches:
                for s in match.strings:
                    for inst in s.instances:
                        off = inst.offset
                        if off + 8 <= len(data):
                            ptr = struct.unpack_from("<Q", data, off)[0]
                            if 0x10000 <= ptr <= max_addr:
                                addresses.add(ptr)

        candidates: list[bytes] = []
        seen: set[bytes] = set()
        key_buf = ctypes.create_string_buffer(KEY_SIZE)
        bytes_read = ctypes.c_size_t(0)
        for ptr in addresses:
            if ReadProcessMemory(handle, ctypes.c_void_p(ptr), key_buf, KEY_SIZE, ctypes.byref(bytes_read)):
                raw = bytes(key_buf.raw[:KEY_SIZE])
                if len(raw) == KEY_SIZE and raw not in seen and _is_potential_key(raw):
                    seen.add(raw)
                    candidates.append(raw)
        return candidates
    finally:
        CloseHandle(handle)


def _pick_probe_db(db_storage_dir: Path) -> Path:
    """Pick a small encrypted database file in db_storage for fast page-1 verification."""
    preferred = [
        db_storage_dir / "session" / "session.db",
        db_storage_dir / "contact" / "contact.db",
        db_storage_dir / "favorite" / "favorite.db",
        db_storage_dir / "message" / "message_0.db",
    ]
    for path in preferred:
        if path.is_file() and path.stat().st_size >= PAGE_SIZE:
            return path
    for path in sorted(db_storage_dir.rglob("*.db")):
        name = path.name.lower()
        if name == "key_info.db" or name.endswith("_fts.db"):
            continue
        if path.is_file() and path.stat().st_size >= PAGE_SIZE:
            return path
    raise FileNotFoundError(f"未在 {db_storage_dir} 中找到可用于验证密钥的加密数据库文件。")


def extract_db_key_v4(db_storage_dir=None, dll_path=None) -> str:
    """Recover the 64-hex WeChat 4.x database key from the running Weixin.exe process."""
    storage = Path(db_storage_dir or config.ENCRYPTED_DB_DIR)
    probe_db = _pick_probe_db(storage)
    with probe_db.open("rb") as f:
        page1 = f.read(PAGE_SIZE)
    if len(page1) < PAGE_SIZE:
        raise RuntimeError(f"探测数据库过小: {probe_db}")
    if page1.startswith(SQLITE_HEADER):
        raise RuntimeError(f"探测数据库已经是明文 SQLite: {probe_db}")

    pid, proc_name = _find_wechat_main_pid()
    log_event(logger, "info", "key.v4_scan_started", process=proc_name, pid=pid, probe_db=str(probe_db))

    # Extract DLL XOR keys first; also keep None (direct key without XOR) as fallback.
    internal_keys: list[bytes | None] = []
    try:
        internal_keys.extend(extract_internal_db_keys_from_dll(dll_path))
    except Exception as exc:
        logger.warning("DLL key 扫描跳过: %s", exc)
    internal_keys.append(None)

    raw_candidates = _scan_process_memory_candidates(pid)
    if not raw_candidates:
        raise RuntimeError("未能从运行中的微信进程内存扫描到候选密钥，请确认微信已登录。")

    salt = page1[:SALT_SIZE]
    stored_hmac = page1[PAGE_SIZE - HMAC_SIZE:PAGE_SIZE]
    stop_event = threading.Event()
    worker_count = max(1, min(os.cpu_count() or 4, 8))

    def check_candidate(candidate_bytes: bytes, internal_key: bytes | None) -> str | None:
        if stop_event.is_set():
            return None
        passphrase = _xor_bytes_32(candidate_bytes, internal_key) if internal_key is not None else candidate_bytes
        enc_key = derive_sqlcipher_enc_key(passphrase, salt)
        mac_key = derive_mac_key(enc_key, salt)
        if hmac.compare_digest(stored_hmac, compute_page_hmac(mac_key, page1, 1)):
            stop_event.set()
            return passphrase.hex()
        return None

    for internal_key in internal_keys:
        stop_event.clear()
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            futures = [pool.submit(check_candidate, cand, internal_key) for cand in raw_candidates]
            for fut in as_completed(futures):
                found = fut.result()
                if found:
                    log_event(
                        logger,
                        "info",
                        "key.v4_scan_succeeded",
                        candidates_scanned=len(raw_candidates),
                        used_dll_xor=internal_key is not None,
                    )
                    return found

    log_event(logger, "warning", "key.v4_scan_failed", candidates_scanned=len(raw_candidates))
    raise RuntimeError(
        f"扫描了 {len(raw_candidates)} 个内存候选但未匹配数据库密钥。"
        "请确认微信已完全登录并进入聊天主界面，或通过环境变量 WECHAT_DB_KEY 手动指定 64 位十六进制密钥。"
    )


def get_or_extract_db_key(db_storage_dir=None, force_refresh=False) -> str:
    """Resolve a verified 64-hex DB key: env -> cache -> live V4 memory scan."""
    storage = Path(db_storage_dir or config.ENCRYPTED_DB_DIR)
    probe_db = _pick_probe_db(storage)

    # 1. Environment variable override
    env_key = _normalize_hex_key(os.environ.get("WECHAT_DB_KEY") or config.WECHAT_DB_KEY)
    if env_key:
        if verify_key_against_db(env_key, probe_db):
            return env_key
        raise RuntimeError("环境变量 WECHAT_DB_KEY 与当前微信数据库不匹配。")

    # 2. Cached key in data/keys.json
    if not force_refresh:
        cached = get_cached_account_keys()
        cached_key = _normalize_hex_key(cached.get("db_key"))
        if cached_key:
            if verify_key_against_db(cached_key, probe_db):
                log_event(logger, "info", "key.cache_hit", probe_db=probe_db.name)
                return cached_key
            log_event(logger, "warning", "key.cache_invalid", probe_db=probe_db.name)

    # 3. Live V4 memory scan (zero restart)
    key_hex = extract_db_key_v4(storage)
    save_account_keys(
        db_key=key_hex,
        source_db_storage=str(storage),
        source_wxid_dir=str(storage.parent),
    )
    return key_hex


# ---------------------------------------------------------------------------
# Local WeChat 4.x .dat image key resolution (kvcomm + V2 template verify)
# ---------------------------------------------------------------------------

def _detect_image_format(plaintext: bytes | None) -> str | None:
    if not plaintext:
        return None
    if plaintext.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if plaintext.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if plaintext.startswith(b"RIFF") and plaintext[8:12] == b"WEBP":
        return "webp"
    if plaintext.startswith((b"wxgf", b"WXGF")):
        return "wxgf"
    if plaintext.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    return None


def _verify_v2_aes_key(aes_key_str: str, ciphertext_block: bytes) -> bool:
    try:
        key_bytes = aes_key_str.encode("ascii")
    except UnicodeEncodeError:
        return False
    if len(key_bytes) < 16 or len(ciphertext_block) != 16:
        return False
    try:
        dec = Cipher(algorithms.AES(key_bytes[:16]), modes.ECB()).decryptor()
        plain = dec.update(ciphertext_block) + dec.finalize()
        return _detect_image_format(plain) is not None
    except Exception:
        return False


def _scan_v2_dat_templates(account_dir: Path, limit: int = 24):
    """Find recent WeChat 4.x V2 _t.dat files to verify image AES/XOR keys."""
    attach_root = account_dir / "msg" / "attach"
    heap = []
    visited = 0

    def offer_dir(directory: Path):
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if not entry.name.lower().endswith("_t.dat"):
                        continue
                    try:
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        mtime_ns = entry.stat(follow_symlinks=False).st_mtime_ns
                    except OSError:
                        continue
                    item = (mtime_ns, entry.path)
                    if len(heap) < limit * 3:
                        heapq.heappush(heap, item)
                    elif item > heap[0]:
                        heapq.heapreplace(heap, item)
        except OSError:
            pass

    if attach_root.is_dir():
        try:
            for chat_entry in os.scandir(attach_root):
                if visited >= 1500:
                    break
                if not chat_entry.is_dir():
                    continue
                visited += 1
                try:
                    for month_entry in os.scandir(chat_entry.path):
                        if visited >= 1500:
                            break
                        if not month_entry.is_dir() or not _MONTH_DIR_RE.fullmatch(month_entry.name):
                            continue
                        visited += 1
                        img_dir = Path(month_entry.path) / "Img"
                        if img_dir.is_dir():
                            offer_dir(img_dir)
                except OSError:
                    continue
        except OSError:
            pass

    templates = []
    tails = Counter()
    for _, path_str in sorted(heap, reverse=True):
        if len(templates) >= limit:
            break
        p = Path(path_str)
        try:
            with p.open("rb") as f:
                header = f.read(V2_CIPHERTEXT_START + 16)
                if len(header) < V2_CIPHERTEXT_START + 16 or not header.startswith(V2_DAT_MAGIC):
                    continue
                f.seek(-2, os.SEEK_END)
                tail = f.read(2)
            templates.append((p, header[V2_CIPHERTEXT_START:V2_CIPHERTEXT_START + 16], tail))
            if len(tail) == 2:
                tails[tail] += 1
        except (OSError, ValueError):
            continue

    inferred_xor = None
    if tails:
        pair, _ = tails.most_common(1)[0]
        x0 = pair[0] ^ 0xFF
        x1 = pair[1] ^ 0xD9
        if x0 == x1:
            inferred_xor = x0
    return templates, inferred_xor


def get_or_resolve_image_keys(account_dir=None) -> dict:
    """Resolve verified image XOR (int) and AES (16-char ASCII) keys for .dat decryption."""
    # 1. Explicit env overrides
    env_xor = os.environ.get("WECHAT_IMAGE_XOR_KEY") or config.WECHAT_IMAGE_XOR_KEY
    env_aes = (os.environ.get("WECHAT_IMAGE_AES_KEY") or config.WECHAT_IMAGE_AES_KEY).strip()
    if env_xor and len(env_aes) >= 16:
        try:
            xor_int = int(env_xor, 16) if str(env_xor).lower().startswith("0x") else int(env_xor)
            if 0 <= xor_int <= 0xFF:
                return {"xor": xor_int, "aes": env_aes[:16], "source": "env"}
        except ValueError:
            pass

    cache_key = os.path.normcase(os.path.normpath(str(account_dir or config.WECHAT_DATA_DIR)))
    if cache_key in _image_key_mem_cache:
        return dict(_image_key_mem_cache[cache_key])

    # 2. Cached verified keys
    cached = get_cached_account_keys()
    if cached.get("image_xor_key") is not None and cached.get("image_aes_key"):
        try:
            xor_raw = cached["image_xor_key"]
            xor_int = int(xor_raw, 16) if isinstance(xor_raw, str) and xor_raw.lower().startswith("0x") else int(xor_raw)
            aes_str = str(cached["image_aes_key"]).strip()[:16]
            if 0 <= xor_int <= 0xFF and len(aes_str) == 16:
                result = {"xor": xor_int, "aes": aes_str, "source": "cache"}
                _image_key_mem_cache[cache_key] = result
                return dict(result)
        except (ValueError, TypeError):
            pass

    # 3. Resolve locally from kvcomm + V2 templates
    acc_path = Path(account_dir or config.WECHAT_DATA_DIR)
    kvcomm_dir = Path(config.get_kvcomm_dir()) if config.get_kvcomm_dir() else None
    if not kvcomm_dir or not kvcomm_dir.is_dir() or not acc_path.is_dir():
        return {}

    codes = []
    try:
        with os.scandir(kvcomm_dir) as entries:
            for entry in entries:
                m = _KVCOMM_FILE_RE.fullmatch(entry.name)
                if m:
                    code = int(m.group(1))
                    if 0 < code <= 0xFFFFFFFF:
                        codes.append(code)
    except OSError:
        return {}
    if not codes:
        return {}
    codes = sorted(set(codes))

    templates, inferred_xor = _scan_v2_dat_templates(acc_path)
    if not templates:
        return {}

    if inferred_xor is not None:
        codes.sort(key=lambda c: (c & 0xFF != inferred_xor, c))

    wxid_candidates = []
    for raw in (config.USER_WXID, acc_path.name, "unknown"):
        cleaned = config.clean_wxid(raw)
        if cleaned and cleaned not in wxid_candidates:
            wxid_candidates.append(cleaned)

    _, sample_ct, _ = templates[0]
    for wxid in wxid_candidates:
        for code in codes:
            aes_key = hashlib.md5(f"{code}{wxid}".encode("utf-8")).hexdigest()[:16]
            if _verify_v2_aes_key(aes_key, sample_ct):
                xor_key = code & 0xFF
                save_account_keys(
                    image_xor_key=f"0x{xor_key:02X}",
                    image_aes_key=aes_key,
                    image_key_verified=True,
                )
                log_event(logger, "info", "key.image_resolved", verified=True)
                return {"xor": xor_key, "aes": aes_key, "source": "kvcomm"}

    return {}
