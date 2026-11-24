import ctypes
import hashlib
import json
import logging
import os
import re
import struct
import sys
from datetime import datetime
from pathlib import Path

from log_utils import log_event

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

logger = logging.getLogger(__name__)

# WeChat 4.x Windows config file name: MD5("KEY_LAST_XWEACHAT_FILE_DIR").ini
XWECHAT_CONFIG_KEY_NAME = "KEY_LAST_XWEACHAT_FILE_DIR"
CSIDL_PERSONAL = 0x0005
_GLOBAL_CONFIG_CRYPT_KEY = b"xwechat_crypt_ke"

COMMON_WECHAT_DIR_NAMES = (
    "xwechat_files",
    "WeChat Files",
    "Weixin Files",
    "wechat_files",
)

WECHAT_EXECUTABLE_NAMES = ("Weixin.exe", "WeChat.exe")

# Directories under WeChat root that are not account folders
_SYSTEM_ACCOUNT_DIRS = frozenset({
    "all_users",
    "all users",
    "applet",
    "backup",
    "wmpf",
})

RUNTIME_DIAGNOSTICS = {
    "config_source": None,
    "env_override_account": False,
    "env_override_data_dir": False,
    "env_override_db_key": False,
    "config_ini_dir": None,
    "global_config": None,
    "search_bases": [],
    "candidates": [],
    "selected_candidate": None,
    "wechat_exe_path": None,
    "wechat_dll_path": None,
    "wechat_version": None,
}


def _mask_id(value):
    text = str(value or "").strip()
    if not text or text.startswith("<"):
        return text
    if len(text) <= 6:
        return text
    return f"{text[:4]}***{text[-4:]}"


def _iso_mtime(timestamp):
    try:
        return datetime.fromtimestamp(timestamp).isoformat(timespec="seconds")
    except (OSError, ValueError, OverflowError):
        return ""


def clean_wxid(value):
    """Strip the trailing 4-hex folder suffix from wxid_xxx_abcd."""
    text = str(value or "").strip()
    if not text:
        return ""
    match = re.match(r"^(wxid_[^\s_]+)(?:_[0-9a-fA-F]{4})$", text, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    match_any = re.match(r"^(wxid_[^_\s]+)_.*$", text, flags=re.IGNORECASE)
    if match_any:
        return match_any.group(1)
    return text


def _decode_mmkv_varint(data, offset):
    shift = 0
    value = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
    return value, offset


def _decode_mmkv_value(payload):
    value_len, offset = _decode_mmkv_varint(payload, 0)
    if offset + value_len == len(payload):
        try:
            return payload[offset:].decode("utf-8")
        except UnicodeDecodeError:
            return payload[offset:].hex()
    if len(payload) == 1:
        return payload[0]
    value_len, offset = _decode_mmkv_varint(payload, 0)
    return value_len if offset == len(payload) else payload.hex()


def _parse_mmkv_kv(data):
    kv = {}
    pos = 4
    while pos < len(data):
        key_len, pos = _decode_mmkv_varint(data, pos)
        key = data[pos:pos + key_len].decode("utf-8", errors="replace")
        pos += key_len
        value_len, pos = _decode_mmkv_varint(data, pos)
        payload = data[pos:pos + value_len]
        pos += value_len
        if value_len == 0:
            kv.pop(key, None)
        else:
            kv[key] = _decode_mmkv_value(payload)
    return kv


def parse_global_config(base_path):
    """Parse all_users/config/global_config (AES-128-CFB + MMKV) for recent login info."""
    try:
        config_path = os.path.join(base_path, "all_users", "config", "global_config")
        meta_path = config_path + ".crc"
        if not os.path.isfile(config_path) or not os.path.isfile(meta_path):
            return None

        raw = Path(config_path).read_bytes()
        meta = Path(meta_path).read_bytes()
        if len(raw) < 8 or len(meta) < 28:
            return None

        iv = meta[12:28]
        data_len = struct.unpack("<I", raw[:4])[0]
        if data_len <= 0 or 4 + data_len > len(raw):
            if len(meta) >= 32:
                data_len = struct.unpack("<I", meta[28:32])[0]
            if data_len <= 0 or 4 + data_len > len(raw):
                return None

        encrypted = raw[4:4 + data_len]
        from Crypto.Cipher import AES

        plaintext = AES.new(
            _GLOBAL_CONFIG_CRYPT_KEY, AES.MODE_CFB, iv=iv, segment_size=128
        ).decrypt(encrypted)

        kv = _parse_mmkv_kv(plaintext)
        result = {
            "wxid": kv.get("mmkv_key_user_name") or "",
            "nickname": kv.get("mmkv_key_nick_name") or "",
            "avatar": kv.get("mmkv_key_head_img_url") or "",
        }
        if result["wxid"] or result["nickname"]:
            return result
        return None
    except Exception:
        return None


def _resolve_known_folder(csidl):
    if os.name != "nt":
        return None
    try:
        from ctypes import wintypes

        buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
        res = ctypes.windll.shell32.SHGetFolderPathW(None, csidl, None, 0, buf)
        if res == 0 and buf.value and os.path.isdir(buf.value):
            return buf.value
    except Exception:
        pass
    return None


def _resolve_wechat_base_dir(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    if re.match(r"^[A-Za-z]:[\\/]", raw):
        return raw
    match = re.match(r"^mydocument(?::(\d+))?$", raw, flags=re.IGNORECASE)
    if not match:
        return None
    csidl = int(match.group(1)) if match.group(1) else CSIDL_PERSONAL
    csidl &= 0x0000FFFF
    return _resolve_known_folder(csidl)


def _get_xwechat_data_dir_from_config():
    """Read WeChat 4.x configured xwechat_files root from %APPDATA%\\Tencent\\xwechat\\config."""
    if sys.platform != "win32":
        return None
    try:
        appdata = os.environ.get("APPDATA", "")
        if not appdata:
            return None
        ini_name = hashlib.md5(XWECHAT_CONFIG_KEY_NAME.encode("utf-8")).hexdigest() + ".ini"
        ini_path = Path(appdata) / "Tencent" / "xwechat" / "config" / ini_name
        if not ini_path.is_file():
            return None
        raw_bytes = ini_path.read_bytes()
        if raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
            raw = raw_bytes.decode("utf-16", errors="ignore")
        else:
            raw = raw_bytes.decode("utf-8", errors="ignore")
        base_dir = _resolve_wechat_base_dir(raw)
        if not base_dir:
            return None
        data_root = os.path.join(base_dir, "xwechat_files")
        if os.path.isdir(data_root):
            return os.path.normpath(data_root)
    except Exception:
        pass
    return None


def _is_account_dir(path):
    p = Path(path)
    if not p.is_dir():
        return False
    if p.name.lower() in _SYSTEM_ACCOUNT_DIRS:
        return False
    db_storage = p / "db_storage"
    if db_storage.is_dir():
        return True
    return False


def _latest_db_mtime(account_dir):
    db_storage = Path(account_dir) / "db_storage"
    latest = 0.0
    if not db_storage.is_dir():
        return latest
    for sub in ("session/session.db", "session/session.db-wal", "contact/contact.db", "message/message_0.db"):
        candidate = db_storage / sub
        try:
            if candidate.is_file():
                latest = max(latest, candidate.stat().st_mtime)
        except OSError:
            pass
    if latest == 0.0:
        try:
            for item in db_storage.rglob("*.db"):
                latest = max(latest, item.stat().st_mtime)
        except OSError:
            pass
    return latest


def detect_wechat_installation():
    """Detect running or installed WeChat 4.x executable, version, and Weixin.dll."""
    exe_path = ""
    dll_path = ""
    version = ""

    env_install = os.environ.get("WECHAT_INSTALL_DIR", "").strip()
    search_dirs = []
    if env_install:
        p = Path(env_install).expanduser()
        if p.is_file():
            exe_path = str(p)
            search_dirs.append(p.parent)
        elif p.is_dir():
            search_dirs.append(p)

    # Check running processes first
    if not exe_path:
        try:
            import psutil

            targets = {name.lower() for name in WECHAT_EXECUTABLE_NAMES}
            for proc in psutil.process_iter(["name", "exe"]):
                try:
                    pname = str(proc.info.get("name") or "").lower()
                    if pname in targets:
                        pexe = str(proc.info.get("exe") or "").strip()
                        if pexe and os.path.isfile(pexe):
                            exe_path = pexe
                            search_dirs.append(Path(pexe).parent)
                            break
                except (psutil.Error, OSError):
                    continue
        except Exception:
            pass

    # Common Windows install paths
    if sys.platform == "win32":
        for base in (
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        ):
            if base:
                for sub in (r"Tencent\Weixin", r"Tencent\WeChat"):
                    d = Path(base) / sub
                    if d.is_dir():
                        search_dirs.append(d)

    # Resolve exe if not yet found
    if not exe_path:
        for d in search_dirs:
            for name in WECHAT_EXECUTABLE_NAMES:
                cand = d / name
                if cand.is_file():
                    exe_path = str(cand)
                    break
            if exe_path:
                break

    # Resolve Weixin.dll / WeChat.dll
    dll_candidates = []
    seen_dlls = set()
    for d in search_dirs:
        for pattern in ("Weixin.dll", "WeChat.dll", "*/Weixin.dll", "*/WeChat.dll"):
            try:
                for item in d.glob(pattern):
                    if item.is_file():
                        key = str(item.resolve()).lower()
                        if key not in seen_dlls:
                            seen_dlls.add(key)
                            dll_candidates.append(item)
            except OSError:
                continue
    if dll_candidates:
        dll_candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        dll_path = str(dll_candidates[0])
        if re.fullmatch(r"\d+(?:\.\d+)+", dll_candidates[0].parent.name):
            version = dll_candidates[0].parent.name

    if not version and exe_path and sys.platform == "win32":
        try:
            import win32api

            info = win32api.GetFileVersionInfo(exe_path, "\\")
            version = (
                f"{info['FileVersionMS'] >> 16}."
                f"{info['FileVersionMS'] & 0xFFFF}."
                f"{info['FileVersionLS'] >> 16}."
                f"{info['FileVersionLS'] & 0xFFFF}"
            )
        except Exception:
            pass

    return {
        "wechat_exe_path": exe_path or None,
        "wechat_dll_path": dll_path or None,
        "wechat_version": version or None,
    }


def _detect_wechat_account():
    """Auto-detect WeChat 4.x account directory and canonical wxid.

    Env overrides:
      WECHAT_DATA_DIR — path to an account folder (containing db_storage) or xwechat_files root
      WECHAT_ACCOUNT  — optional account folder name or wxid
    """
    env_dir = os.environ.get("WECHAT_DATA_DIR", "").strip()
    env_account = os.environ.get("WECHAT_ACCOUNT", "").strip()
    env_key = os.environ.get("WECHAT_DB_KEY", "").strip()
    RUNTIME_DIAGNOSTICS["env_override_data_dir"] = bool(env_dir)
    RUNTIME_DIAGNOSTICS["env_override_account"] = bool(env_account)
    RUNTIME_DIAGNOSTICS["env_override_db_key"] = bool(env_key)

    if env_dir:
        candidate = Path(env_dir).expanduser()
        if candidate.name.lower() == "db_storage":
            candidate = candidate.parent
        if _is_account_dir(candidate):
            account_name = candidate.name
            wxid = env_account or clean_wxid(account_name)
            RUNTIME_DIAGNOSTICS["config_source"] = "environment"
            RUNTIME_DIAGNOSTICS["selected_candidate"] = {
                "account_dir": str(candidate),
                "account_name": account_name,
                "wxid_masked": _mask_id(wxid),
                "db_modified_at": _iso_mtime(_latest_db_mtime(candidate)),
            }
            log_event(logger, "info", "config.source_environment", wxid_masked=_mask_id(wxid), path=str(candidate))
            return str(candidate), wxid, ""

    # Build search roots
    roots = []
    if env_dir and os.path.isdir(env_dir):
        roots.append(os.path.normpath(env_dir))

    ini_dir = _get_xwechat_data_dir_from_config()
    RUNTIME_DIAGNOSTICS["config_ini_dir"] = ini_dir
    if ini_dir:
        roots.append(ini_dir)

    home = Path.home()
    for base in (home / "Documents", home):
        for name in COMMON_WECHAT_DIR_NAMES:
            cand = base / name
            if cand.is_dir():
                roots.append(os.path.normpath(str(cand)))

    if sys.platform == "darwin":
        mac_root = home / "Library" / "Containers" / "com.tencent.xinWeChat" / "Data" / "Documents" / "xwechat_files"
        if mac_root.is_dir():
            roots.append(os.path.normpath(str(mac_root)))

    # Deduplicate roots
    unique_roots = []
    seen = set()
    for r in roots:
        key = os.path.normcase(os.path.normpath(r))
        if key not in seen:
            seen.add(key)
            unique_roots.append(r)
    RUNTIME_DIAGNOSTICS["search_bases"] = unique_roots

    global_info = None
    for root in unique_roots:
        info = parse_global_config(root)
        if info:
            global_info = info
            RUNTIME_DIAGNOSTICS["global_config"] = {
                "wxid_masked": _mask_id(info.get("wxid")),
                "nickname": info.get("nickname") or "",
            }
            log_event(
                logger,
                "info",
                "config.global_config_loaded",
                wxid_masked=_mask_id(info.get("wxid")),
                nickname=info.get("nickname") or "",
            )
            break

    candidates = []
    seen_accounts = set()
    for root in unique_roots:
        root_path = Path(root)
        if _is_account_dir(root_path):
            account_paths = [root_path]
        else:
            try:
                account_paths = [p for p in root_path.iterdir() if _is_account_dir(p)]
            except OSError:
                account_paths = []
        for acc_path in account_paths:
            key = os.path.normcase(str(acc_path.resolve()))
            if key in seen_accounts:
                continue
            seen_accounts.add(key)
            mtime = _latest_db_mtime(acc_path)
            wxid = clean_wxid(acc_path.name)
            entry = {
                "account_dir": os.path.normpath(str(acc_path)),
                "account_name": acc_path.name,
                "wxid": wxid,
                "wxid_masked": _mask_id(wxid),
                "mtime": mtime,
                "db_modified_at": _iso_mtime(mtime),
            }
            candidates.append(entry)

    RUNTIME_DIAGNOSTICS["candidates"] = [
        {k: v for k, v in item.items() if k not in ("wxid", "mtime")}
        for item in candidates
    ]

    if not candidates:
        return None, None, ""

    selected = None
    if env_account:
        target = env_account.lower()
        for item in candidates:
            if item["account_name"].lower() == target or item["wxid"].lower() == clean_wxid(target).lower():
                selected = item
                break

    if selected is None and global_info and global_info.get("wxid"):
        g_wxid = clean_wxid(global_info["wxid"]).lower()
        for item in candidates:
            if item["wxid"].lower() == g_wxid:
                selected = item
                break

    if selected is None:
        candidates.sort(key=lambda item: item["mtime"], reverse=True)
        selected = candidates[0]
        if len(candidates) > 1:
            log_event(
                logger,
                "warning",
                "config.multiple_accounts_detected",
                selected_wxid_masked=selected["wxid_masked"],
                selected_path=selected["account_dir"],
                candidate_count=len(candidates),
            )

    RUNTIME_DIAGNOSTICS["config_source"] = "auto_detected"
    RUNTIME_DIAGNOSTICS["selected_candidate"] = {
        k: v for k, v in selected.items() if k not in ("wxid", "mtime")
    }
    log_event(
        logger,
        "info",
        "config.auto_detected",
        wxid_masked=selected["wxid_masked"],
        path=selected["account_dir"],
        candidates=len(candidates),
    )
    nickname = ""
    if global_info and clean_wxid(global_info.get("wxid", "")).lower() == selected["wxid"].lower():
        nickname = global_info.get("nickname") or ""
    return selected["account_dir"], selected["wxid"], nickname


# --- Auto-detection on import ---
_install_info = detect_wechat_installation()
RUNTIME_DIAGNOSTICS.update(_install_info)
WECHAT_EXE_PATH = _install_info.get("wechat_exe_path") or ""
WECHAT_DLL_PATH = _install_info.get("wechat_dll_path") or ""
WECHAT_VERSION = _install_info.get("wechat_version") or ""

_detected_dir, _detected_wxid, _detected_nickname = _detect_wechat_account()

WECHAT_DATA_DIR = _detected_dir or r"C:\Users\<YOUR_USERNAME>\Documents\xwechat_files\<YOUR_WXID>"
USER_WXID = _detected_wxid or "<YOUR_WXID>"
USER_UID = USER_WXID  # compatibility alias
USER_NICKNAME = _detected_nickname or ""

if not _detected_dir:
    RUNTIME_DIAGNOSTICS["config_source"] = "manual_fallback"
    RUNTIME_DIAGNOSTICS["selected_candidate"] = {
        "account_dir": os.path.normpath(WECHAT_DATA_DIR),
        "account_name": os.path.basename(WECHAT_DATA_DIR),
        "wxid_masked": _mask_id(USER_WXID),
    }

ENCRYPTED_DB_DIR = os.path.join(WECHAT_DATA_DIR, "db_storage")

# Optional direct key overrides via environment variables
WECHAT_DB_KEY = os.environ.get("WECHAT_DB_KEY", "").strip()
WECHAT_IMAGE_XOR_KEY = os.environ.get("WECHAT_IMAGE_XOR_KEY", "").strip()
WECHAT_IMAGE_AES_KEY = os.environ.get("WECHAT_IMAGE_AES_KEY", "").strip()

# Sync settings
SYNC_INTERVAL_HOURS = 4
SYNC_OVERLAP_SECONDS = 24 * 60
COPY_RETRY_COUNT = 3
COPY_RETRY_DELAY = 3  # seconds

# Data directories
DATA_DIR = os.path.join(PROJECT_DIR, "data")
DECRYPTED_DIR = os.path.join(DATA_DIR, "decrypted")
EXPORT_DIR = os.path.join(DATA_DIR, "exports")
MEDIA_CACHE_DIR = os.path.join(DATA_DIR, "media_cache")
LOGS_DIR = os.path.join(PROJECT_DIR, "logs")

# File paths
KEYS_FILE = os.path.join(DATA_DIR, "keys.json")
SYNC_STATE_FILE = os.path.join(DATA_DIR, "sync_state.json")

# WeChat message content types (local_type)
CONTENT_TYPE_TEXT = 1
CONTENT_TYPE_IMAGE = 3
CONTENT_TYPE_VOICE = 34
CONTENT_TYPE_CONTACT = 42
CONTENT_TYPE_VIDEO = 43
CONTENT_TYPE_EMOJI = 47
CONTENT_TYPE_LOCATION = 48
CONTENT_TYPE_APP = 49
CONTENT_TYPE_VOIP = 50
CONTENT_TYPE_MICRO_VIDEO = 62
CONTENT_TYPE_SYSTEM = 10000
CONTENT_TYPE_REVOKE = 10002

# WeChat 4.x composite local_type values (type + (subtype << 32))
LOCAL_TYPE_LINK = 17179869233           # 49 + (4 << 32)
LOCAL_TYPE_ARTICLE = 21474836529        # 49 + (5 << 32)
LOCAL_TYPE_FILE = 25769803825           # 49 + (6 << 32)
LOCAL_TYPE_MUSIC = 12884901937          # 49 + (3 << 32)
LOCAL_TYPE_FORWARDED = 81604378673      # 49 + (19 << 32)
LOCAL_TYPE_MINIPROGRAM = 154618822705   # 49 + (36 << 32)
LOCAL_TYPE_MINIPROGRAM_2 = 141733920817 # 49 + (33 << 32)
LOCAL_TYPE_FINDER = 219043332145        # 49 + (51 << 32)
LOCAL_TYPE_QUOTE = 244813135921         # 49 + (57 << 32)
LOCAL_TYPE_PAT = 266287972401           # 49 + (62 << 32)
LOCAL_TYPE_LIVE = 270582939697          # 49 + (63 << 32)
LOCAL_TYPE_ANNOUNCEMENT = 373662154801  # 49 + (87 << 32)
LOCAL_TYPE_TRANSFER = 8589934592049     # 49 + (2000 << 32)
LOCAL_TYPE_RED_PACKET = 8594229559345   # 49 + (2001 << 32)

CONTENT_TYPE_NAMES = {
    1: "文本",
    3: "图片",
    34: "语音",
    42: "名片",
    43: "视频",
    47: "动画表情",
    48: "位置",
    49: "应用消息",
    50: "音视频通话",
    62: "小视频",
    10000: "系统消息",
    10002: "系统通知",
    LOCAL_TYPE_LINK: "链接",
    LOCAL_TYPE_ARTICLE: "文章",
    LOCAL_TYPE_FILE: "文件",
    LOCAL_TYPE_MUSIC: "音乐",
    LOCAL_TYPE_FORWARDED: "合并转发",
    LOCAL_TYPE_MINIPROGRAM: "小程序",
    LOCAL_TYPE_MINIPROGRAM_2: "小程序",
    LOCAL_TYPE_FINDER: "视频号",
    LOCAL_TYPE_QUOTE: "引用消息",
    LOCAL_TYPE_PAT: "拍一拍",
    LOCAL_TYPE_LIVE: "直播",
    LOCAL_TYPE_ANNOUNCEMENT: "群公告",
    LOCAL_TYPE_TRANSFER: "转账",
    LOCAL_TYPE_RED_PACKET: "红包",
}

# Web server settings
WEB_HOST = os.environ.get("WEB_HOST", "localhost")
WEB_PORT = int(os.environ.get("WEB_PORT", "8090"))


def get_kvcomm_dir():
    override = os.environ.get("WECHAT_IMAGE_KVCOMM_DIR", "").strip()
    if override:
        return override
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return os.path.join(appdata, "Tencent", "xwechat", "net", "kvcomm")
    return ""


def get_runtime_diagnostics():
    return {
        "config_source": RUNTIME_DIAGNOSTICS["config_source"],
        "env_override_account": RUNTIME_DIAGNOSTICS["env_override_account"],
        "env_override_data_dir": RUNTIME_DIAGNOSTICS["env_override_data_dir"],
        "env_override_db_key": RUNTIME_DIAGNOSTICS["env_override_db_key"],
        "config_ini_dir": RUNTIME_DIAGNOSTICS["config_ini_dir"],
        "global_config": RUNTIME_DIAGNOSTICS["global_config"],
        "search_bases": list(RUNTIME_DIAGNOSTICS["search_bases"]),
        "candidate_count": len(RUNTIME_DIAGNOSTICS["candidates"]),
        "candidates": list(RUNTIME_DIAGNOSTICS["candidates"]),
        "selected_candidate": dict(RUNTIME_DIAGNOSTICS["selected_candidate"] or {}),
        "wechat_data_dir": os.path.normpath(WECHAT_DATA_DIR),
        "encrypted_db_dir": os.path.normpath(ENCRYPTED_DB_DIR),
        "user_wxid_masked": _mask_id(USER_WXID),
        "user_nickname": USER_NICKNAME,
        "wechat_exe_path": WECHAT_EXE_PATH or None,
        "wechat_dll_path": WECHAT_DLL_PATH or None,
        "wechat_version": WECHAT_VERSION or None,
    }


# Ensure directories exist
for _d in (DATA_DIR, DECRYPTED_DIR, EXPORT_DIR, MEDIA_CACHE_DIR, LOGS_DIR):
    os.makedirs(_d, exist_ok=True)
