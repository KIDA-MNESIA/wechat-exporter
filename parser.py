"""WeChat 4.x snapshot query and message parser (matching dingtalk-exporter API contract)."""

import base64
from datetime import datetime
import hashlib
import html
import logging
import os
from pathlib import Path
import re
import sqlite3
from urllib.parse import quote

try:
    import zstandard as zstd
except ImportError:
    zstd = None

import config
from log_utils import log_event

logger = logging.getLogger(__name__)

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_MD5_HEX_RE = re.compile(rb"(?i)[0-9a-f]{32}")
_DAT_MD5_RE = re.compile(rb"(?i)([0-9a-f]{32})(?:[._][thbc])?\.dat")
_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")

_IGNORED_USERNAMES = frozenset({
    "brandsessionholder",
    "brandservicesessionholder",
    "notifymessage",
    "opencustomerservicemsg",
    "notification_messages",
    "userexperience_alarm",
    "qmessage",
    "tmessage",
    "qqsync",
    "floatbottle",
    "shakeapp",
    "lbsapp",
    "medianote",
    "newsapp",
    "fmessage",
    "qqmail",
})


class DatabaseNotReadyError(RuntimeError):
    """Raised when the decrypted WeChat snapshot is missing or unusable."""


def _clean_surrogates(text):
    if not isinstance(text, str):
        return ""
    return _SURROGATE_RE.sub("", text)


def _format_timestamp(ts_ms):
    if not ts_ms:
        return ""
    try:
        return datetime.fromtimestamp(int(ts_ms) / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError, OverflowError):
        return ""


def _sec_to_ms(value):
    val = int(value or 0)
    if val <= 0:
        return 0
    return val * 1000 if val < 10_000_000_000 else val


def _ms_to_sec_floor(value):
    val = int(value)
    return val // 1000 if val >= 10_000_000_000 else val


def _quote_ident(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _decode_sqlite_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="ignore")
    return str(value)


def _decode_message_content(compress_value, message_value) -> str:
    """Decode WeChat 4.x text/XML payload, transparently decompressing zstd blobs."""
    for candidate in (compress_value, message_value):
        if candidate is None:
            continue
        if isinstance(candidate, memoryview):
            raw = candidate.tobytes()
        elif isinstance(candidate, (bytes, bytearray)):
            raw = bytes(candidate)
        else:
            raw = None

        if raw is not None:
            if raw.startswith(_ZSTD_MAGIC) and zstd is not None:
                try:
                    out = zstd.decompress(raw).decode("utf-8", errors="ignore").strip()
                    if out:
                        return html.unescape(out)
                except Exception:
                    pass
            decoded = raw.decode("utf-8", errors="ignore").strip()
            if decoded:
                return decoded
        elif isinstance(candidate, str):
            text = candidate.strip()
            if text:
                # Hex-encoded zstd payload check
                if len(text) >= 16 and len(text) % 2 == 0 and text.lower().startswith("28b52ffd") and zstd is not None:
                    try:
                        out = zstd.decompress(bytes.fromhex(text)).decode("utf-8", errors="ignore").strip()
                        if out:
                            return html.unescape(out)
                    except Exception:
                        pass
                return text
    return ""


def _strip_cdata(s: str) -> str:
    if not s:
        return ""
    return s.replace("<![CDATA[", "").replace("]]>", "").strip()


def _extract_xml_tag(xml_text: str, tag: str) -> str:
    if not xml_text or not tag:
        return ""
    m = re.search(rf"<{re.escape(tag)}\b[^>]*>(.*?)</{re.escape(tag)}>", xml_text, flags=re.IGNORECASE | re.DOTALL)
    return _strip_cdata(m.group(1) or "") if m else ""


def _extract_xml_attr(xml_text: str, attr: str) -> str:
    if not xml_text or not attr:
        return ""
    m = re.search(rf"\b{re.escape(attr)}\s*=\s*['\"]([^'\"]+)['\"]", xml_text, flags=re.IGNORECASE)
    return html.unescape((m.group(1) or "").strip()) if m else ""


def _extract_xml_tag_or_attr(xml_text: str, name: str) -> str:
    return _extract_xml_tag(xml_text, name) or _extract_xml_attr(xml_text, name)


def _extract_md5_from_blob(blob) -> str:
    if blob is None:
        return ""
    if isinstance(blob, memoryview):
        data = blob.tobytes()
    elif isinstance(blob, (bytes, bytearray)):
        data = bytes(blob)
    elif isinstance(blob, str):
        data = blob.encode("utf-8", errors="ignore")
    else:
        return ""
    if len(data) == 16:
        return data.hex()
    m_dat = _DAT_MD5_RE.findall(data)
    if m_dat:
        return m_dat[0].decode("ascii", errors="ignore").lower()
    m = _MD5_HEX_RE.findall(data)
    if m:
        return m[0].decode("ascii", errors="ignore").lower()
    return ""


def _extract_voice_transcript(packed_info) -> str:
    """Extract WeChat-native voice transcript from packed_info_data (field 5 -> {1: 2, 2: utf8})."""
    if packed_info is None:
        return ""
    if isinstance(packed_info, memoryview):
        data = packed_info.tobytes()
    elif isinstance(packed_info, (bytes, bytearray)):
        data = bytes(packed_info)
    else:
        return ""
    if not data or len(data) > 1024 * 1024:
        return ""

    def read_varint(raw, offset):
        val = 0
        shift = 0
        pos = offset
        for _ in range(10):
            if pos >= len(raw):
                return None, offset
            b = raw[pos]
            pos += 1
            val |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return val, pos
            shift += 7
        return None, offset

    def parse_fields(raw):
        out = []
        pos = 0
        while pos < len(raw):
            tag, nxt = read_varint(raw, pos)
            if tag is None or nxt <= pos:
                return None
            pos = nxt
            fno, wtype = tag >> 3, tag & 0x07
            if fno <= 0:
                return None
            if wtype == 0:
                val, nxt = read_varint(raw, pos)
                if val is None:
                    return None
                out.append((fno, wtype, val))
                pos = nxt
            elif wtype == 1:
                if pos + 8 > len(raw):
                    return None
                out.append((fno, wtype, raw[pos:pos + 8]))
                pos += 8
            elif wtype == 2:
                sz, nxt = read_varint(raw, pos)
                if sz is None or nxt + sz > len(raw):
                    return None
                out.append((fno, wtype, raw[nxt:nxt + sz]))
                pos = nxt + sz
            elif wtype == 5:
                if pos + 4 > len(raw):
                    return None
                out.append((fno, wtype, raw[pos:pos + 4]))
                pos += 4
            else:
                return None
        return out

    top = parse_fields(data)
    if not top:
        return ""
    for fno, wtype, blob in top:
        if fno == 5 and wtype == 2 and isinstance(blob, bytes):
            nested = parse_fields(blob)
            if not nested:
                continue
            status = None
            text_bytes = None
            for nfno, nwtype, nval in nested:
                if nfno == 1 and nwtype == 0:
                    status = int(nval)
                elif nfno == 2 and nwtype == 2 and isinstance(nval, bytes):
                    text_bytes = nval
            if status == 2 and text_bytes:
                try:
                    t = text_bytes.decode("utf-8", errors="strict").strip()
                    if t:
                        return t
                except UnicodeDecodeError:
                    pass
    return ""


# ---------------------------------------------------------------------------
# Connection & database status
# ---------------------------------------------------------------------------

def get_connection(db_dir=None, snapshot_id=None):
    """Open a read-only validated SnapshotContext."""
    from snapshots import SnapshotError, open_snapshot

    try:
        return open_snapshot(db_dir=db_dir, snapshot_id=snapshot_id)
    except SnapshotError as exc:
        raise DatabaseNotReadyError(f"{getattr(exc, 'code', 'snapshot_error')}: {exc}") from exc
    except sqlite3.Error as exc:
        log_event(logger, "warning", "parser.db_not_usable", path=db_dir, error=exc)
        raise DatabaseNotReadyError("解密后的微信数据库无法读取，请点击“手动同步”重新刷新。") from exc


def get_database_status(db_dir=None, snapshot_id=None) -> dict:
    from snapshots import connection_metadata

    info = {
        "path": str(db_dir or config.DECRYPTED_DIR),
        "exists": False,
        "ready": False,
        "error": None,
    }
    try:
        ctx = get_connection(db_dir=db_dir, snapshot_id=snapshot_id)
    except DatabaseNotReadyError as exc:
        info["error"] = str(exc)
        return info
    try:
        db_files = sorted(p.name for p in ctx.root.glob("*.db"))
        total_size = sum(p.stat().st_size for p in ctx.root.glob("*.db"))
        info.update({
            "path": str(ctx.root),
            "exists": True,
            "ready": True,
            "error": None,
            "database_count": len(db_files),
            "databases": db_files,
            "size": total_size,
        })
        info.update(connection_metadata(ctx))
        return info
    finally:
        ctx.close()


def _validate_pagination(limit, offset):
    if limit < 1:
        raise ValueError("limit must be at least 1")
    if offset < 0:
        raise ValueError("offset must be at least 0")


def _page_result(key, items, total, limit, offset, ctx=None):
    returned = len(items)
    has_more = offset + returned < total
    result = {
        "total": total,
        key: items,
        "limit": limit,
        "offset": offset,
        "returned": returned,
        "has_more": has_more,
        "next_offset": offset + returned if has_more else None,
    }
    if ctx is not None:
        from snapshots import connection_metadata
        result.update(connection_metadata(ctx))
    return result


# ---------------------------------------------------------------------------
# Contacts & chatroom metadata
# ---------------------------------------------------------------------------

def _load_contacts_map(ctx, usernames=None) -> dict[str, dict]:
    """Load contact records keyed by username from contact.db (contact + stranger tables)."""
    cache = getattr(ctx, "_contact_cache", None)
    if cache is None:
        cache = {}
        setattr(ctx, "_contact_cache", cache)

    if usernames is not None:
        missing = [u for u in dict.fromkeys(usernames) if u and u not in cache]
        if not missing:
            return cache
    else:
        missing = None

    conn = ctx.contact_conn
    tables = {r[0].lower(): r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    def query_table(tbl_key, targets):
        tbl = tables.get(tbl_key)
        if not tbl:
            return
        cols = {r[1].lower() for r in conn.execute(f"PRAGMA table_info({_quote_ident(tbl)})")}
        select_cols = [c for c in ("username", "remark", "nick_name", "alias", "flag", "big_head_url", "small_head_url") if c in cols]
        if "username" not in select_cols:
            return
        col_sql = ", ".join(select_cols)
        if targets is None:
            rows = conn.execute(f"SELECT {col_sql} FROM {_quote_ident(tbl)}").fetchall()
            _store(rows)
        else:
            for i in range(0, len(targets), 500):
                chunk = targets[i:i + 500]
                ph = ",".join("?" * len(chunk))
                rows = conn.execute(
                    f"SELECT {col_sql} FROM {_quote_ident(tbl)} WHERE username IN ({ph})",
                    chunk,
                ).fetchall()
                _store(rows)

    def _store(rows):
        for r in rows:
            u = _decode_sqlite_text(r["username"]).strip()
            if not u:
                continue
            keys = r.keys()
            cache[u] = {
                "username": u,
                "remark": _decode_sqlite_text(r["remark"]).strip() if "remark" in keys else "",
                "nick_name": _decode_sqlite_text(r["nick_name"]).strip() if "nick_name" in keys else "",
                "alias": _decode_sqlite_text(r["alias"]).strip() if "alias" in keys else "",
                "flag": int(r["flag"] or 0) if "flag" in keys else 0,
            }

    query_table("contact", missing)
    if missing is None:
        query_table("stranger", None)
    else:
        still_missing = [u for u in missing if u not in cache]
        if still_missing:
            query_table("stranger", still_missing)
    return cache


def _pick_display_name(contact_dict, fallback: str) -> str:
    if not contact_dict:
        return fallback
    for key in ("remark", "nick_name", "alias"):
        val = str(contact_dict.get(key) or "").strip()
        if val:
            return val
    return fallback


def _parse_chatroom_ext_buffer(ext_buf: bytes) -> tuple[dict[str, str], int]:
    """Parse chat_room.ext_buffer protobuf-like blob -> ({username: group_nickname}, member_count)."""
    if not ext_buf:
        return {}, 0

    def decode_varint(raw, offset):
        val = 0
        shift = 0
        pos = offset
        n = len(raw)
        while pos < n:
            b = raw[pos]
            pos += 1
            val |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return val, pos
            shift += 7
            if shift > 63:
                return None, n
        return None, n

    def iter_fields(raw):
        idx = 0
        n = len(raw)
        while idx < n:
            tag, nxt = decode_varint(raw, idx)
            if tag is None or nxt <= idx:
                break
            idx = nxt
            fno, wtype = tag >> 3, tag & 0x07
            if wtype == 0:
                _, nxt = decode_varint(raw, idx)
                if nxt <= idx:
                    break
                idx = nxt
            elif wtype == 2:
                sz, nxt = decode_varint(raw, idx)
                if sz is None or nxt + sz > n:
                    break
                yield fno, raw[nxt:nxt + sz]
                idx = nxt + sz
            elif wtype == 1:
                idx += 8
            elif wtype == 5:
                idx += 4
            else:
                break

    nicknames = {}
    member_count = 0
    for _, chunk in iter_fields(ext_buf):
        if not chunk:
            continue
        fields = {}
        for sfno, sval in iter_fields(chunk):
            if len(sval) <= 256:
                try:
                    txt = sval.decode("utf-8", errors="strict").strip()
                    if txt and sfno not in fields:
                        fields[sfno] = txt
                except UnicodeDecodeError:
                    pass
        uname = fields.get(1, "")
        if uname and (uname.startswith("wxid_") or "@" in uname or re.fullmatch(r"[A-Za-z0-9_-]{4,40}", uname)):
            member_count += 1
            g_nick = fields.get(2, "")
            if g_nick and g_nick != uname:
                nicknames[uname] = g_nick
    return nicknames, member_count


def _get_chatroom_info(ctx, chatroom_id: str) -> tuple[dict[str, str], int, str]:
    """Return (group_nickname_map, member_count, owner) cached on ctx."""
    cache = getattr(ctx, "_chatroom_cache", None)
    if cache is None:
        cache = {}
        setattr(ctx, "_chatroom_cache", cache)
    if chatroom_id in cache:
        return cache[chatroom_id]

    nicknames, member_count, owner = {}, 0, ""
    if chatroom_id.endswith("@chatroom"):
        try:
            row = ctx.contact_conn.execute(
                "SELECT owner, ext_buffer FROM chat_room WHERE username = ? LIMIT 1",
                (chatroom_id,),
            ).fetchone()
            if row is not None:
                owner = _decode_sqlite_text(row["owner"]).strip()
                ext = row["ext_buffer"]
                if isinstance(ext, memoryview):
                    ext = ext.tobytes()
                if isinstance(ext, (bytes, bytearray)) and ext:
                    nicknames, member_count = _parse_chatroom_ext_buffer(bytes(ext))
        except sqlite3.Error:
            pass
    cache[chatroom_id] = (nicknames, member_count, owner)
    return nicknames, member_count, owner


# ---------------------------------------------------------------------------
# Conversations
# ---------------------------------------------------------------------------

def _should_keep_session(username: str, include_official: bool = False) -> bool:
    if not username:
        return False
    low = username.lower()
    if low in _IGNORED_USERNAMES:
        return False
    if not include_official and low.startswith("gh_"):
        return False
    if "@kefu.openim" in low or "service_" in low:
        return False
    if low.startswith(("weixin", "qqmail", "fmessage", "medianote", "floatbottle", "newsapp")):
        return False
    return low.endswith(("@chatroom", "@openim")) or low.startswith("wxid_") or ("@" not in low)


def _is_top_contact(contact_dict) -> bool:
    if not contact_dict:
        return False
    flag = int(contact_dict.get("flag") or 0)
    return bool(flag & 2048)


def get_conversation_info(ctx, cid: str) -> dict:
    contacts = _load_contacts_map(ctx, [cid])
    c = contacts.get(cid)
    is_group = cid.endswith("@chatroom")
    title = _pick_display_name(c, cid)
    member_count = 0
    owner_id = ""
    if is_group:
        _, member_count, owner_id = _get_chatroom_info(ctx, cid)
    return {
        "cid": cid,
        "type": "group" if is_group else "single",
        "title": _clean_surrogates(title),
        "member_count": member_count,
        "owner_id": owner_id,
    }


def get_conversations(ctx, limit=100, offset=0, keyword=None, include_official=False):
    """Get conversation list from session.db enriched with contact.db names."""
    _validate_pagination(limit, offset)
    conn = ctx.session_conn
    cols = {r[1].lower() for r in conn.execute("PRAGMA table_info(SessionTable)")}
    has_hidden = "is_hidden" in cols
    has_sort_ts = "sort_timestamp" in cols
    has_last_ts = "last_timestamp" in cols
    has_unread = "unread_count" in cols
    has_summary = "summary" in cols

    select_parts = ["username"]
    select_parts.append("type" if "type" in cols else "0 AS type")
    select_parts.append("unread_count" if has_unread else "0 AS unread_count")
    select_parts.append("is_hidden" if has_hidden else "0 AS is_hidden")
    select_parts.append("summary" if has_summary else "'' AS summary")
    select_parts.append("sort_timestamp" if has_sort_ts else "0 AS sort_timestamp")
    select_parts.append("last_timestamp" if has_last_ts else "0 AS last_timestamp")

    rows = conn.execute(f"SELECT {', '.join(select_parts)} FROM SessionTable").fetchall()
    usernames = [_decode_sqlite_text(r["username"]).strip() for r in rows]
    usernames = [u for u in usernames if _should_keep_session(u, include_official=include_official)]
    contacts = _load_contacts_map(ctx, usernames)

    kw_lower = keyword.casefold() if keyword else ""
    items = []
    for r in rows:
        username = _decode_sqlite_text(r["username"]).strip()
        if not _should_keep_session(username, include_official=include_official):
            continue
        if int(r["is_hidden"] or 0) == 1:
            continue
        c = contacts.get(username)
        is_group = username.endswith("@chatroom")
        title = _pick_display_name(c, username)
        if kw_lower:
            haystacks = [
                title.casefold(),
                username.casefold(),
                str((c or {}).get("remark") or "").casefold(),
                str((c or {}).get("nick_name") or "").casefold(),
                str((c or {}).get("alias") or "").casefold(),
            ]
            if not any(kw_lower in h for h in haystacks):
                continue

        ts_sec = max(int(r["sort_timestamp"] or 0), int(r["last_timestamp"] or 0))
        is_top = _is_top_contact(c)
        items.append({
            "cid": username,
            "type": "group" if is_group else "single",
            "title": _clean_surrogates(title),
            "member_count": 0,
            "create_at": 0,
            "last_modify": _sec_to_ms(ts_sec),
            "unread_count": int(r["unread_count"] or 0),
            "is_top": is_top,
            "owner_id": "",
            "summary": _clean_surrogates(_decode_sqlite_text(r["summary"]).strip()),
        })

    items.sort(key=lambda item: (1 if item["is_top"] else 0, item["last_modify"], item["cid"]), reverse=True)
    total = len(items)
    page = items[offset:offset + limit]

    # Enrich member_count & owner_id only for returned page groups
    for conv in page:
        if conv["type"] == "group":
            _, member_count, owner_id = _get_chatroom_info(ctx, conv["cid"])
            conv["member_count"] = member_count
            conv["owner_id"] = owner_id

    return _page_result("conversations", page, total, limit, offset, ctx)


# ---------------------------------------------------------------------------
# Message table lookup & parsing
# ---------------------------------------------------------------------------

def _find_msg_tables(ctx, cid: str) -> list[tuple[sqlite3.Connection, str, str]]:
    """Return all (msg_conn, table_name, db_stem) shards for cid across message_*.db."""
    if not cid:
        return []
    md5_hex = hashlib.md5(cid.encode("utf-8")).hexdigest().lower()
    table_index = ctx.get_msg_table_index()
    entries = []
    seen = set()
    for key in (f"msg_{md5_hex}", f"chat_{md5_hex}"):
        for db_path, actual in table_index.get(key, ()):
            sig = (db_path.stem.lower(), actual.lower())
            if sig not in seen:
                seen.add(sig)
                entries.append((ctx.message_conn(db_path), actual, db_path.stem))
    if not entries:
        for key, pair_list in table_index.items():
            if md5_hex in key:
                for db_path, actual in pair_list:
                    sig = (db_path.stem.lower(), actual.lower())
                    if sig not in seen:
                        seen.add(sig)
                        entries.append((ctx.message_conn(db_path), actual, db_path.stem))
    return entries


def _load_name2id(msg_conn: sqlite3.Connection, db_stem: str, ctx) -> tuple[dict[int, str], int | None]:
    cache = getattr(ctx, "_name2id_cache", None)
    if cache is None:
        cache = {}
        setattr(ctx, "_name2id_cache", cache)
    if db_stem in cache:
        return cache[db_stem]

    mapping = {}
    self_rowid = None
    self_wxid = config.clean_wxid(config.USER_WXID).lower()
    try:
        for row in msg_conn.execute("SELECT rowid, user_name FROM Name2Id"):
            rid = int(row[0])
            uname = _decode_sqlite_text(row[1]).strip()
            if uname:
                mapping[rid] = uname
                if self_wxid and config.clean_wxid(uname).lower() == self_wxid:
                    self_rowid = rid
    except sqlite3.Error:
        pass
    cache[db_stem] = (mapping, self_rowid)
    return mapping, self_rowid


def _split_group_sender_prefix(text: str, known_sender: str = "") -> tuple[str, str]:
    if not text:
        return "", text
    sep = text.find(":\n")
    if sep <= 0 or sep > 128:
        return "", text
    prefix = text[:sep].strip()
    body = text[sep + 2:].lstrip("\n")
    if not prefix or re.search(r"\s", prefix):
        return "", text
    if (
        prefix == known_sender
        or prefix.startswith("wxid_")
        or "@" in prefix
        or body.lstrip().startswith("<")
    ):
        return prefix, body
    return "", text


def _parse_system_message(raw_text: str) -> str:
    text = str(raw_text or "").strip()
    if not text:
        return "[系统消息]"
    if "revokemsg" in text.lower():
        replaced = _extract_xml_tag(text, "replacemsg")
        if replaced:
            return re.sub(r"<[^>]+>", "", replaced).strip() or "撤回了一条消息"
        return "撤回了一条消息"
    nested = _extract_xml_tag(text, "content")
    if nested:
        text = nested
    cleaned = re.sub(r"<!--.*?-->", " ", text, flags=re.DOTALL)
    cleaned = re.sub(r"<!\[CDATA\[|\]\]>", "", cleaned)
    cleaned = re.sub(r"</?[_a-zA-Z0-9]+[^>]*>", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned or "[系统消息]"


def _parse_pat_message(raw_text: str, contacts: dict) -> str:
    template = _extract_xml_tag(raw_text, "template")
    if not template:
        return "[拍一拍]"
    rendered = template
    for m in re.finditer(r"\$\{([^}]+)\}", template):
        wxid = m.group(1)
        name = _pick_display_name(contacts.get(wxid), wxid)
        rendered = rendered.replace(f"${{{wxid}}}", name)
    return rendered.strip() or "[拍一拍]"


def _extract_appmsg_type(xml_text: str) -> int:
    m = re.search(r"<appmsg\b[^>]*>(.*?)</appmsg>", xml_text, flags=re.IGNORECASE | re.DOTALL)
    inner = m.group(1) if m else xml_text
    for nested_tag in ("refermsg", "patmsg", "recorditem", "weappinfo", "wxaappinfo"):
        inner = re.sub(rf"<{nested_tag}\b[^>]*>.*?</{nested_tag}>", "", inner, flags=re.IGNORECASE | re.DOTALL)
    val = _extract_xml_tag(inner, "type")
    try:
        return int(str(val or "0").strip())
    except ValueError:
        return 0


def _lookup_resource_md5(ctx, cid: str, local_type: int, server_id: int, local_id: int, create_time_sec: int) -> str:
    res_conn = ctx.resource_conn
    if res_conn is None:
        return ""
    chat_id_cache = getattr(ctx, "_resource_chat_id_cache", None)
    if chat_id_cache is None:
        chat_id_cache = {}
        setattr(ctx, "_resource_chat_id_cache", chat_id_cache)
    if cid in chat_id_cache:
        chat_id = chat_id_cache[cid]
    else:
        chat_id = None
        try:
            row = res_conn.execute("SELECT rowid FROM ChatName2Id WHERE user_name = ? LIMIT 1", (cid,)).fetchone()
            if row is not None:
                chat_id = int(row[0])
        except sqlite3.Error:
            chat_id = None
        chat_id_cache[cid] = chat_id

    try:
        if server_id > 0:
            sql = "SELECT packed_info FROM MessageResourceInfo WHERE message_svr_id = ?"
            params = [int(server_id)]
            if chat_id is not None:
                sql += " AND chat_id = ?"
                params.append(chat_id)
            sql += " ORDER BY message_id DESC LIMIT 1"
            row = res_conn.execute(sql, params).fetchone()
            if row and row[0]:
                md5 = _extract_md5_from_blob(row[0])
                if md5:
                    return md5
        if local_id > 0 and create_time_sec > 0:
            sql = "SELECT packed_info FROM MessageResourceInfo WHERE message_local_id = ? AND message_create_time = ?"
            params = [int(local_id), int(create_time_sec)]
            if chat_id is not None:
                sql += " AND chat_id = ?"
                params.append(chat_id)
            sql += " ORDER BY message_id DESC LIMIT 1"
            row = res_conn.execute(sql, params).fetchone()
            if row and row[0]:
                return _extract_md5_from_blob(row[0])
    except sqlite3.Error:
        pass
    return ""


def _parse_message_row(
    row,
    ctx,
    *,
    cid: str,
    is_group: bool,
    name2id: dict[int, str],
    self_rowid: int | None,
    contacts: dict[str, dict],
    group_nicks: dict[str, str],
    expand_forwarded: bool = True,
) -> dict:
    local_id = int(row["local_id"] or 0)
    server_id = int(row["server_id"] or 0)
    local_type = int(row["local_type"] or 0)
    create_time_sec = int(row["create_time"] or 0)
    created_at = _sec_to_ms(create_time_sec)
    real_sender_id = int(row["real_sender_id"] or 0)

    raw_text = _decode_message_content(row["compress_content"], row["message_content"]).strip()
    source_xml = _decode_message_content(None, row["source"]) if "source" in row.keys() else ""
    packed_info = row["packed_info_data"] if "packed_info_data" in row.keys() else None

    sender_username = name2id.get(real_sender_id, "")
    is_self = bool(
        (self_rowid is not None and real_sender_id == self_rowid)
        or (sender_username and config.clean_wxid(sender_username).lower() == config.clean_wxid(config.USER_WXID).lower())
    )

    if is_group and raw_text:
        prefix, body = _split_group_sender_prefix(raw_text, sender_username)
        if prefix:
            if not sender_username:
                sender_username = prefix
            raw_text = body

    if is_self:
        sender_username = config.clean_wxid(config.USER_WXID) or sender_username
    elif not is_group and not sender_username:
        sender_username = cid

    # Ensure sender contact is loaded
    if sender_username and sender_username not in contacts:
        _load_contacts_map(ctx, [sender_username])

    if is_self and config.USER_NICKNAME:
        sender_name = group_nicks.get(sender_username) or _pick_display_name(contacts.get(sender_username), config.USER_NICKNAME)
    else:
        sender_name = group_nicks.get(sender_username) or _pick_display_name(contacts.get(sender_username), sender_username or "未知用户")

    # Parse @ mentions from <msgsource><atuserlist>
    at_ids = {}
    if source_xml:
        at_raw = _extract_xml_tag(source_xml, "atuserlist")
        if at_raw:
            at_users = [u.strip() for u in re.split(r"[,;\s]+", at_raw) if u.strip()]
            if at_users:
                _load_contacts_map(ctx, at_users)
                for u in at_users:
                    at_ids[u] = group_nicks.get(u) or _pick_display_name(contacts.get(u), u)

    # Normalize WeChat 4.x composite local_type (low 32 bits = base type, high 32 bits = sub type)
    base_type = local_type & 0xFFFFFFFF
    sub_type = local_type >> 32

    text = ""
    message_subtype = ""
    parse_status = "complete"
    attachments = []
    image_info = None
    audio_info = None
    video_info = None
    quote_info = None
    link_info = None
    location_info = None
    contact_info = None
    transfer_info = None
    forwarded_info = None
    forwarded_messages = None

    if base_type == 1 and sub_type == 0:
        text = raw_text
    elif base_type == 3:
        text = "[图片]"
        message_subtype = "image"
        from attachment import resolve_local_media_path

        packed_md5 = _extract_md5_from_blob(packed_info)
        xml_md5 = _extract_xml_attr(raw_text, "md5").lower()
        candidates = []
        for cand in (packed_md5, xml_md5):
            if cand and cand not in candidates:
                candidates.append(cand)

        md5 = ""
        local_p = None
        for cand in candidates:
            probe = resolve_local_media_path("image", cand, cid=cid, ctx=ctx)
            if probe is not None and probe.is_file():
                md5 = cand
                local_p = probe
                break

        if local_p is None:
            res_md5 = _lookup_resource_md5(ctx, cid, local_type, server_id, local_id, create_time_sec)
            if res_md5 and res_md5 not in candidates:
                candidates.append(res_md5)
                probe = resolve_local_media_path("image", res_md5, cid=cid, ctx=ctx)
                if probe is not None and probe.is_file():
                    md5 = res_md5
                    local_p = probe

        if not md5 and candidates:
            md5 = candidates[0]

        if md5:
            cached = local_p is not None and local_p.is_file()
            src_url = f"/api/media/image/{md5}?cid={quote(cid)}" if cached else ""
            item = {
                "md5": md5,
                "local_path": str(local_p) if cached else "",
                "src": src_url,
                "cached": cached,
            }
            if xml_md5 and xml_md5 != md5:
                item["xml_md5"] = xml_md5
            image_info = {**item, "images": [item]}
        else:
            image_info = {"md5": "", "local_path": "", "src": "", "cached": False, "images": []}
    elif base_type == 34:
        message_subtype = "voice"
        dur_ms = 0
        vl = _extract_xml_attr(raw_text, "voicelength")
        if vl and vl.isdigit():
            dur_ms = int(vl)
        transcript = _extract_voice_transcript(packed_info)
        if transcript:
            text = transcript
        else:
            sec = max(1, round(dur_ms / 1000)) if dur_ms else 0
            text = f"[语音 {sec}秒]" if sec else "[语音]"
        audio_info = {"duration_ms": dur_ms, "transcript": transcript}
    elif base_type == 42:
        message_subtype = "contact"
        nick = _extract_xml_attr(raw_text, "nickname")
        uname = _extract_xml_attr(raw_text, "username")
        alias = _extract_xml_attr(raw_text, "alias")
        contact_info = {"name": nick, "username": uname, "alias": alias}
        text = f"[名片] {nick}".strip() if nick else "[名片]"
    elif base_type in (43, 62):
        message_subtype = "video"
        dur = _extract_xml_attr(raw_text, "playlength")
        md5 = _extract_xml_attr(raw_text, "md5").lower() or _extract_md5_from_blob(packed_info)
        video_info = {"duration": int(dur) if dur.isdigit() else 0, "md5": md5}
        text = f"[视频 {dur}秒]" if dur.isdigit() else "[视频]"
    elif base_type == 47:
        message_subtype = "emoji"
        text = "[动画表情]"
    elif base_type == 48:
        message_subtype = "location"
        poiname = _extract_xml_tag_or_attr(raw_text, "poiname")
        label = _extract_xml_tag_or_attr(raw_text, "label")
        lat = _extract_xml_tag_or_attr(raw_text, "x")
        lng = _extract_xml_tag_or_attr(raw_text, "y")
        location_info = {"poiname": poiname, "label": label, "lat": lat, "lng": lng}
        text = f"[位置] {poiname or label}".strip() if (poiname or label) else "[位置]"
    elif base_type == 50:
        message_subtype = "voip"
        voip_msg = _extract_xml_tag(raw_text, "msg")
        text = voip_msg or "[音视频通话]"
    elif base_type in (10000, 10002):
        message_subtype = "system"
        text = _parse_system_message(raw_text)
    elif local_type == config.LOCAL_TYPE_PAT:
        message_subtype = "pat"
        text = _parse_pat_message(raw_text, contacts)
    elif base_type == 49:
        app_type = sub_type or _extract_appmsg_type(raw_text)
        title = _extract_xml_tag(raw_text, "title")
        des = _extract_xml_tag(raw_text, "des")
        url = html.unescape(_extract_xml_tag(raw_text, "url"))
        source_display = _extract_xml_tag(raw_text, "sourcedisplayname") or _extract_xml_tag(raw_text, "appname")

        if app_type == 57 or ("<refermsg" in raw_text.lower() and app_type != 19):
            message_subtype = "reply"
            refer_match = re.search(r"(<refermsg\b[^>]*>.*?</refermsg>)", raw_text, flags=re.IGNORECASE | re.DOTALL)
            refer_block = refer_match.group(1) if refer_match else ""
            without_refer = re.sub(r"<refermsg\b[^>]*>.*?</refermsg>", "", raw_text, flags=re.IGNORECASE | re.DOTALL)
            reply_text = _extract_xml_tag(without_refer, "title") or title or "[引用消息]"
            ref_name = _extract_xml_tag_or_attr(refer_block, "displayname")
            ref_type = _extract_xml_tag_or_attr(refer_block, "type")
            ref_content = _extract_xml_tag(refer_block, "content")
            if ref_type == "3":
                ref_content = "[图片]"
            elif ref_type == "34":
                ref_content = "[语音]"
            elif ref_type in ("43", "62"):
                ref_content = "[视频]"
            elif ref_type == "47":
                ref_content = "[动画表情]"
            elif ref_content.lstrip().startswith("<"):
                ref_content = _extract_xml_tag(ref_content, "title") or _extract_xml_tag(ref_content, "des") or "[消息]"
            quote_info = {
                "source_sender_name": ref_name,
                "source_preview": ref_content,
                "source_server_id": _extract_xml_tag_or_attr(refer_block, "svrid"),
                "reply_text": reply_text,
            }
            text = reply_text
        elif app_type == 19:
            message_subtype = "forwarded"
            record_xml = _extract_xml_tag(raw_text, "recorditem")
            if expand_forwarded:
                from forwarded import decode_forwarded

                decoded = decode_forwarded(
                    record_xml,
                    cid=cid,
                    fallback_title=title or "聊天记录",
                    fallback_summary=des,
                )
                forwarded_messages = decoded["messages"]
                forwarded_info = {k: v for k, v in decoded.items() if k != "messages"}
                forwarded_info["total"] = len(forwarded_messages)
                forwarded_info["tool"] = "get_forwarded_messages"
                parse_status = forwarded_info["parse_status"]
                text = "\n".join(p for p in (forwarded_info.get("title"), forwarded_info.get("summary")) if p) or "[合并转发]"
            else:
                text = "\n".join(p for p in (title, des) if p) or "[合并转发]"
        elif app_type in (6, 74):
            message_subtype = "file"
            fname = title or "未知文件"
            size_str = _extract_xml_tag(raw_text, "totallen")
            fsize = int(size_str) if size_str.isdigit() else 0
            fmd5 = _extract_md5_from_blob(packed_info) or _extract_xml_tag_or_attr(raw_text, "md5").lower()
            from attachment import resolve_local_media_path

            local_p = resolve_local_media_path("file", fmd5, cid=cid, filename=fname, ctx=ctx)
            if local_p is None:
                alt_md5 = _extract_xml_tag_or_attr(raw_text, "md5").lower()
                if alt_md5 and alt_md5 != fmd5:
                    local_p = resolve_local_media_path("file", alt_md5, cid=cid, filename=fname, ctx=ctx)
            local_ok = local_p is not None and local_p.is_file()
            att = {
                "type": 49,
                "filename": fname,
                "file_size": fsize,
                "file_type": _extract_xml_tag(raw_text, "fileext"),
                "md5": fmd5,
                "local_available": local_ok,
            }
            if local_ok:
                att["local_path"] = str(local_p)
            attachments.append(att)
            text = f"[文件] {fname}"
        elif app_type == 87:
            message_subtype = "announcement"
            ann = _extract_xml_tag(raw_text, "textannouncement") or title or des
            text = f"[群公告] {ann}".strip()
        elif app_type == 2000 or "<wcpayinfo" in raw_text.lower() and "feedesc" in raw_text.lower():
            message_subtype = "transfer"
            amount = _extract_xml_tag_or_attr(raw_text, "feedesc")
            memo = _extract_xml_tag_or_attr(raw_text, "pay_memo")
            transfer_info = {"amount": amount, "memo": memo}
            text = f"[转账 {amount}] {memo}".strip() if amount else "[转账]"
        elif app_type in (2001, 2003):
            message_subtype = "red_packet"
            rp_title = _extract_xml_tag(raw_text, "sendertitle") or title or "红包"
            text = f"[红包] {rp_title}"
        elif app_type in (33, 36):
            message_subtype = "mini_program"
            link_info = {"title": title or des, "url": url, "from": source_display, "link_type": "mini_program"}
            text = f"[小程序] {title or des}".strip()
        elif app_type == 51:
            message_subtype = "finder"
            finder_desc = _extract_xml_tag(raw_text, "desc") or des or title
            finder_nick = _extract_xml_tag(raw_text, "nickname") or source_display or "视频号"
            link_info = {"title": finder_desc, "url": url, "from": finder_nick, "link_type": "finder"}
            text = f"[视频号] {finder_nick}: {finder_desc}".strip(": ")
        elif app_type in (3, 4, 5, 68):
            message_subtype = "link"
            link_info = {"title": title, "desc": des, "url": url, "from": source_display, "link_type": "article" if "mp.weixin.qq.com" in url else "web_link"}
            text = title or des or url or "[链接]"
        else:
            text = title or des or "[应用消息]"
            if not (title or des):
                parse_status = "unsupported"
    else:
        if raw_text and not raw_text.lstrip().startswith("<"):
            text = raw_text
        else:
            t_xml = _extract_xml_tag(raw_text, "title")
            d_xml = _extract_xml_tag(raw_text, "des")
            text = t_xml or d_xml
            if not text:
                parse_status = "unsupported"

    text = _clean_surrogates(text)
    type_name = config.CONTENT_TYPE_NAMES.get(local_type) or config.CONTENT_TYPE_NAMES.get(base_type) or f"未知({local_type})"
    if not text:
        text = f"[{type_name}：正文尚未解析]"
        parse_status = "unsupported"

    msg = {
        "id": local_id,
        "server_id": server_id,
        "cid": cid,
        "sender_id": sender_username,
        "sender_name": _clean_surrogates(sender_name),
        "is_self": is_self,
        "content_type": base_type,
        "local_type": local_type,
        "content_type_name": type_name,
        "message_subtype": message_subtype,
        "text": text,
        "created_at": created_at,
        "created_at_str": _format_timestamp(created_at),
        "at_ids": at_ids,
        "attachments": attachments,
        "parse_status": parse_status,
    }
    if forwarded_info is not None:
        msg["forwarded_info"] = forwarded_info
        msg["forwarded_messages"] = forwarded_messages
    if image_info is not None:
        msg["image_info"] = image_info
    if audio_info is not None:
        msg["audio_info"] = audio_info
    if video_info is not None:
        msg["video_info"] = video_info
    if quote_info is not None:
        msg["quote_info"] = quote_info
    if link_info is not None:
        msg["link_info"] = link_info
    if location_info is not None:
        msg["location_info"] = location_info
    if contact_info is not None:
        msg["contact_info"] = contact_info
    if transfer_info is not None:
        msg["transfer_info"] = transfer_info

    from message_content import build_agent_content
    msg["content"] = build_agent_content(msg)
    return msg


def _select_columns_sql(msg_conn: sqlite3.Connection, table: str) -> str:
    cols = {r[1].lower(): r[1] for r in msg_conn.execute(f"PRAGMA table_info({_quote_ident(table)})")}
    wanted = [
        ("local_id", "0"),
        ("server_id", "0"),
        ("local_type", "0"),
        ("sort_seq", "0"),
        ("real_sender_id", "0"),
        ("create_time", "0"),
        ("message_content", "''"),
        ("compress_content", "NULL"),
        ("packed_info_data", "NULL"),
        ("source", "''"),
    ]
    parts = []
    for name, default in wanted:
        if name in cols:
            parts.append(cols[name])
        else:
            parts.append(f"{default} AS {name}")
    return ", ".join(parts)


def get_messages(ctx, cid, limit=50, offset=0, since_time=None, until_time=None, include_forwarded=False):
    """Get messages for a conversation across all time-sharded message DBs."""
    _validate_pagination(limit, offset)
    shards = _find_msg_tables(ctx, cid)
    if not shards:
        return _page_result("messages", [], 0, limit, offset, ctx)

    where = "WHERE 1=1"
    params = []
    if since_time is not None:
        where += " AND create_time > ?"
        params.append(_ms_to_sec_floor(since_time))
    if until_time is not None:
        where += " AND create_time <= ?"
        params.append(_ms_to_sec_floor(until_time))

    is_group = cid.endswith("@chatroom")
    group_nicks, _, _ = _get_chatroom_info(ctx, cid) if is_group else ({}, 0, "")

    # Fast path: single shard
    if len(shards) == 1:
        msg_conn, table, db_stem = shards[0]
        quoted = _quote_ident(table)
        total = msg_conn.execute(f"SELECT COUNT(*) FROM {quoted} {where}", params).fetchone()[0]
        select_sql = _select_columns_sql(msg_conn, table)
        rows = msg_conn.execute(
            f"SELECT {select_sql} FROM {quoted} {where} ORDER BY create_time DESC, sort_seq DESC, local_id DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
        name2id, self_rowid = _load_name2id(msg_conn, db_stem, ctx)
        sender_usernames = [name2id.get(int(r["real_sender_id"] or 0), "") for r in rows] + [cid]
        contacts = _load_contacts_map(ctx, sender_usernames)
        messages = [
            _parse_message_row(
                r, ctx, cid=cid, is_group=is_group,
                name2id=name2id, self_rowid=self_rowid,
                contacts=contacts, group_nicks=group_nicks,
                expand_forwarded=True,
            )
            for r in reversed(rows)
        ]
    else:
        # Multi-shard merge: each shard only needs top (offset + limit) lightweight keys
        total = 0
        key_entries = []
        fetch_cap = offset + limit
        for shard_idx, (msg_conn, table, db_stem) in enumerate(shards):
            quoted = _quote_ident(table)
            try:
                cnt = int(msg_conn.execute(f"SELECT COUNT(*) FROM {quoted} {where}", params).fetchone()[0] or 0)
            except sqlite3.Error:
                continue
            if cnt == 0:
                continue
            total += cnt
            cols = {r[1].lower() for r in msg_conn.execute(f"PRAGMA table_info({quoted})")}
            sort_col = "sort_seq" if "sort_seq" in cols else "0"
            rows = msg_conn.execute(
                f"SELECT create_time, {sort_col} AS sort_seq, local_id FROM {quoted} {where} "
                f"ORDER BY create_time DESC, {sort_col} DESC, local_id DESC LIMIT ?",
                [*params, fetch_cap],
            ).fetchall()
            for r in rows:
                key_entries.append((
                    int(r["create_time"] or 0),
                    int(r["sort_seq"] or 0),
                    int(r["local_id"] or 0),
                    db_stem,
                    shard_idx,
                ))

        key_entries.sort(reverse=True)
        page_keys = key_entries[offset:offset + limit]

        # Batch fetch full rows per shard
        ids_by_shard: dict[int, list[int]] = {}
        for _, _, lid, _, shard_idx in page_keys:
            ids_by_shard.setdefault(shard_idx, []).append(lid)

        rows_by_key = {}
        sender_usernames = [cid]
        shard_meta = {}
        for shard_idx, lids in ids_by_shard.items():
            msg_conn, table, db_stem = shards[shard_idx]
            quoted = _quote_ident(table)
            select_sql = _select_columns_sql(msg_conn, table)
            name2id, self_rowid = _load_name2id(msg_conn, db_stem, ctx)
            shard_meta[shard_idx] = (name2id, self_rowid)
            for i in range(0, len(lids), 500):
                chunk = lids[i:i + 500]
                ph = ",".join("?" * len(chunk))
                for r in msg_conn.execute(
                    f"SELECT {select_sql} FROM {quoted} WHERE local_id IN ({ph})",
                    chunk,
                ).fetchall():
                    rows_by_key[(shard_idx, int(r["local_id"] or 0))] = r
                    sender_usernames.append(name2id.get(int(r["real_sender_id"] or 0), ""))

        contacts = _load_contacts_map(ctx, sender_usernames)
        messages = []
        for _, _, lid, _, shard_idx in reversed(page_keys):
            r = rows_by_key.get((shard_idx, lid))
            if r is None:
                continue
            name2id, self_rowid = shard_meta[shard_idx]
            messages.append(
                _parse_message_row(
                    r, ctx, cid=cid, is_group=is_group,
                    name2id=name2id, self_rowid=self_rowid,
                    contacts=contacts, group_nicks=group_nicks,
                    expand_forwarded=True,
                )
            )

    if not include_forwarded:
        for m in messages:
            m.pop("forwarded_messages", None)

    return _page_result("messages", messages, total, limit, offset, ctx)


def get_forwarded_messages(ctx, cid, message_id, limit=100, offset=0):
    """Read child messages of a merged-forward message in preorder."""
    _validate_pagination(limit, offset)
    shards = _find_msg_tables(ctx, cid)
    if not shards:
        raise ValueError("未找到指定会话的消息表")

    try:
        mid_int = int(message_id)
    except (TypeError, ValueError):
        raise ValueError("无效的消息 ID") from None

    found = None
    # Prefer matching by server_id or a forwarded local_type across all shards
    for msg_conn, table, db_stem in shards:
        select_sql = _select_columns_sql(msg_conn, table)
        quoted = _quote_ident(table)
        row = msg_conn.execute(
            f"SELECT {select_sql} FROM {quoted} WHERE server_id = ? LIMIT 1",
            (mid_int,),
        ).fetchone()
        if row is not None:
            found = (row, msg_conn, db_stem)
            break
    if found is None:
        fallback = None
        for msg_conn, table, db_stem in shards:
            select_sql = _select_columns_sql(msg_conn, table)
            quoted = _quote_ident(table)
            row = msg_conn.execute(
                f"SELECT {select_sql} FROM {quoted} WHERE local_id = ? LIMIT 1",
                (mid_int,),
            ).fetchone()
            if row is not None:
                lt = int(row["local_type"] or 0)
                if lt == config.LOCAL_TYPE_FORWARDED or (lt & 0xFFFFFFFF) == 49:
                    found = (row, msg_conn, db_stem)
                    break
                if fallback is None:
                    fallback = (row, msg_conn, db_stem)
        if found is None:
            found = fallback

    if found is None:
        raise ValueError("未找到指定的消息")

    row, msg_conn, db_stem = found
    is_group = cid.endswith("@chatroom")
    name2id, self_rowid = _load_name2id(msg_conn, db_stem, ctx)
    group_nicks, _, _ = _get_chatroom_info(ctx, cid) if is_group else ({}, 0, "")
    contacts = _load_contacts_map(ctx, [cid, name2id.get(int(row["real_sender_id"] or 0), "")])
    root = _parse_message_row(
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
    if "forwarded_info" not in root:
        raise ValueError("指定消息不是合并转发聊天记录")

    children = root.get("forwarded_messages") or []
    return {
        **_page_result("messages", children[offset:offset + limit], len(children), limit, offset, ctx),
        "conversation_id": cid,
        "message_id": root["id"],
        **root["forwarded_info"],
    }


def _iter_conversation_tables(ctx):
    """Yield (cid, msg_conn, table_name, db_stem) for all sessions across all message DB shards."""
    convs = get_conversations(ctx, limit=100000, offset=0, include_official=True)["conversations"]
    seen_tables = set()
    for conv in convs:
        cid = conv["cid"]
        for msg_conn, table, db_stem in _find_msg_tables(ctx, cid):
            key = (db_stem.lower(), table.lower())
            if key not in seen_tables:
                seen_tables.add(key)
                yield cid, msg_conn, table, db_stem


def get_new_messages(ctx, since_time, cid=None):
    """Get all new messages after since_time (ms) chronologically."""
    since_sec = _ms_to_sec_floor(since_time)
    targets = []
    if cid:
        for msg_conn, table, db_stem in _find_msg_tables(ctx, cid):
            targets.append((cid, msg_conn, table, db_stem))
    else:
        targets = list(_iter_conversation_tables(ctx))

    messages = []
    for conv_cid, msg_conn, table, db_stem in targets:
        select_sql = _select_columns_sql(msg_conn, table)
        quoted = _quote_ident(table)
        try:
            rows = msg_conn.execute(
                f"SELECT {select_sql} FROM {quoted} WHERE create_time > ? ORDER BY create_time ASC, sort_seq ASC, local_id ASC",
                (since_sec,),
            ).fetchall()
        except sqlite3.Error:
            continue
        if not rows:
            continue
        is_group = conv_cid.endswith("@chatroom")
        name2id, self_rowid = _load_name2id(msg_conn, db_stem, ctx)
        group_nicks, _, _ = _get_chatroom_info(ctx, conv_cid) if is_group else ({}, 0, "")
        contacts = _load_contacts_map(ctx, [conv_cid] + [name2id.get(int(r["real_sender_id"] or 0), "") for r in rows])
        for r in rows:
            messages.append(
                _parse_message_row(
                    r,
                    ctx,
                    cid=conv_cid,
                    is_group=is_group,
                    name2id=name2id,
                    self_rowid=self_rowid,
                    contacts=contacts,
                    group_nicks=group_nicks,
                    expand_forwarded=True,
                )
            )
    messages.sort(key=lambda m: (m["created_at"], m["cid"], m["id"]))
    return messages


def _search_raw_messages(ctx, keyword: str, limit: int, offset: int):
    kw_lower = keyword.casefold()
    matches = []
    for cid, msg_conn, table, db_stem in _iter_conversation_tables(ctx):
        select_sql = _select_columns_sql(msg_conn, table)
        quoted = _quote_ident(table)
        try:
            rows = msg_conn.execute(f"SELECT {select_sql} FROM {quoted}").fetchall()
        except sqlite3.Error:
            continue
        for r in rows:
            raw = _decode_message_content(r["compress_content"], r["message_content"])
            if kw_lower in raw.casefold():
                matches.append((_sec_to_ms(r["create_time"]), cid, int(r["local_id"] or 0), msg_conn, table, db_stem, r))

    matches.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    total = len(matches)
    page_items = matches[offset:offset + limit]
    messages = []
    for _, cid, _, msg_conn, _, db_stem, r in page_items:
        is_group = cid.endswith("@chatroom")
        name2id, self_rowid = _load_name2id(msg_conn, db_stem, ctx)
        group_nicks, _, _ = _get_chatroom_info(ctx, cid) if is_group else ({}, 0, "")
        contacts = _load_contacts_map(ctx, [cid, name2id.get(int(r["real_sender_id"] or 0), "")])
        msg = _parse_message_row(
            r,
            ctx,
            cid=cid,
            is_group=is_group,
            name2id=name2id,
            self_rowid=self_rowid,
            contacts=contacts,
            group_nicks=group_nicks,
            expand_forwarded=False,
        )
        messages.append(msg)
    return {"query": keyword, "mode": "raw", **_page_result("messages", messages, total, limit, offset, ctx)}


def search_messages_page(ctx, keyword: str, limit=50, offset=0, mode="text"):
    """Search messages in 'text' (indexed readable content) or 'raw' mode."""
    _validate_pagination(limit, offset)
    if not keyword:
        raise ValueError("keyword 不能为空")
    if mode not in ("text", "raw"):
        raise ValueError("mode 必须为 text 或 raw")
    if mode == "raw":
        return _search_raw_messages(ctx, keyword, limit=limit, offset=offset)

    from search_index import search_indexed_messages
    return search_indexed_messages(ctx, keyword, limit=limit, offset=offset)


def get_conversation_stats(ctx) -> dict:
    """Return summary stats: total conversations, single/group counts, total messages, contact count."""
    convs = get_conversations(ctx, limit=100000, offset=0)["conversations"]
    group_count = sum(1 for c in convs if c["type"] == "group")
    single_count = sum(1 for c in convs if c["type"] == "single")

    total_messages = 0
    table_count = 0
    for db_path in ctx.message_db_paths():
        conn = ctx.message_conn(db_path)
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
            name = str(row[0] or "")
            if name.lower().startswith(("msg_", "chat_")):
                table_count += 1
                try:
                    total_messages += int(conn.execute(f"SELECT COUNT(*) FROM {_quote_ident(name)}").fetchone()[0] or 0)
                except sqlite3.Error:
                    continue

    contact_count = 0
    try:
        contact_count = int(ctx.contact_conn.execute("SELECT COUNT(*) FROM contact").fetchone()[0] or 0)
    except sqlite3.Error:
        pass

    return {
        "total_conversations": len(convs),
        "single_conversations": single_count,
        "group_conversations": group_count,
        "total_messages": total_messages,
        "message_tables": table_count,
        "total_contacts": contact_count,
        "message_databases": len(ctx.message_db_paths()),
    }
