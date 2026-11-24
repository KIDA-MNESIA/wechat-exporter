"""Synthetic WeChat 4.x database & SQLCipher 4.0 encryption helpers for tests."""

import hashlib
import os
from pathlib import Path
import sqlite3
import struct

from Crypto.Cipher import AES
from Crypto.Util import Padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import zstandard as zstd

import key_extractor

SELF_WXID = "wxid_self_0001"
ALICE_WXID = "wxid_alice_0002"
BOB_WXID = "wxid_bob_0003"
GROUP_CID = "123456789@chatroom"


def _encode_varint(val: int) -> bytes:
    out = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _pb_bytes(field_no: int, payload: bytes) -> bytes:
    tag = (field_no << 3) | 2
    return _encode_varint(tag) + _encode_varint(len(payload)) + payload


def _pb_varint(field_no: int, val: int) -> bytes:
    tag = (field_no << 3) | 0
    return _encode_varint(tag) + _encode_varint(val)


def build_chatroom_ext_buffer(members: list[tuple[str, str]]) -> bytes:
    out = bytearray()
    for uname, nick in members:
        sub = _pb_bytes(1, uname.encode("utf-8"))
        if nick:
            sub += _pb_bytes(2, nick.encode("utf-8"))
        out.extend(_pb_bytes(1, sub))
    return bytes(out)


def build_voice_packed_info(transcript: str) -> bytes:
    inner = _pb_varint(1, 2) + _pb_bytes(2, transcript.encode("utf-8"))
    return _pb_bytes(5, inner)


def encrypt_sqlcipher4_db(plain_db_path: str | Path, out_path: str | Path, key_hex: str) -> None:
    """Encrypt a plain 4096-page SQLite DB using WeChat 4.x SQLCipher 4.0 parameters."""
    raw = Path(plain_db_path).read_bytes()
    page_size = key_extractor.PAGE_SIZE
    reserve = key_extractor.RESERVE_SIZE
    salt = os.urandom(16)
    key_bytes = bytes.fromhex(key_hex)
    enc_key = key_extractor.derive_sqlcipher_enc_key(key_bytes, salt)
    mac_key = key_extractor.derive_mac_key(enc_key, salt)

    total_pages = (len(raw) + page_size - 1) // page_size
    out = bytearray()
    for cur in range(total_pages):
        page_num = cur + 1
        page = bytearray(raw[cur * page_size:(cur + 1) * page_size])
        if len(page) < page_size:
            page.extend(b"\x00" * (page_size - len(page)))
        iv = os.urandom(16)
        offset = 16 if page_num == 1 else 0
        plaintext = bytes(page[offset:page_size - reserve])
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(plaintext) + enc.finalize()

        enc_page = bytearray()
        if page_num == 1:
            enc_page.extend(salt)
        enc_page.extend(ct)
        enc_page.extend(iv)
        # Placeholder for 64-byte HMAC
        enc_page.extend(b"\x00" * 64)
        page_mac = key_extractor.compute_page_hmac(mac_key, bytes(enc_page), page_num)
        enc_page[-64:] = page_mac
        out.extend(enc_page)

    Path(out_path).write_bytes(bytes(out))


def make_v2_dat_image(plain_jpeg: bytes, xor_key: int, aes_key: str) -> bytes:
    """Create a synthetic WeChat 4.x V2 encrypted .dat image."""
    aes_plain_len = min(len(plain_jpeg), 1024)
    head = plain_jpeg[:aes_plain_len]
    tail = plain_jpeg[aes_plain_len:]
    xor_len = min(len(tail), 64)
    mid = tail[:-xor_len] if xor_len else tail
    xor_part = bytes(b ^ xor_key for b in tail[-xor_len:]) if xor_len else b""

    cipher = AES.new(aes_key.encode("ascii")[:16], AES.MODE_ECB)
    enc_head = cipher.encrypt(Padding.pad(head, 16))
    header = struct.pack("<6sLLx", bytes((0x07, 0x08, 0x56, 0x32, 0x08, 0x07)), aes_plain_len, xor_len)
    return header + enc_head + mid + xor_part


def _open_sqlcipher_layout_db(path: Path) -> sqlite3.Connection:
    """Create a plain 4096-byte-page SQLite DB with 80 bytes reserved per page (SQLCipher 4 layout)."""
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA page_size=4096")
    conn.execute("CREATE TABLE _init (id INTEGER)")
    conn.execute("DROP TABLE _init")
    conn.commit()
    conn.close()
    # Set SQLite header byte 20 (reserved space per page) = 80 so SQLite never
    # places B-tree cell payload inside the 80-byte SQLCipher IV+HMAC trailer.
    data = bytearray(path.read_bytes())
    data[20] = key_extractor.RESERVE_SIZE
    # Update leaf page-1 cell content area (header offset 105..107) if empty
    data[105:107] = struct.pack(">H", key_extractor.PAGE_SIZE - key_extractor.RESERVE_SIZE)
    path.write_bytes(bytes(data))
    return sqlite3.connect(path)


def create_synthetic_snapshot(root_dir: str | Path, *, wechat_data_dir: str | Path | None = None) -> Path:
    """Build a complete synthetic WeChat 4.x multi-DB snapshot directory."""
    root = Path(root_dir)
    root.mkdir(parents=True, exist_ok=True)
    compressor = zstd.ZstdCompressor()

    # 1. session.db
    sconn = _open_sqlcipher_layout_db(root / "session.db")
    sconn.executescript("""
        CREATE TABLE SessionTable (
            username TEXT PRIMARY KEY,
            type INTEGER DEFAULT 0,
            unread_count INTEGER DEFAULT 0,
            is_hidden INTEGER DEFAULT 0,
            summary TEXT DEFAULT '',
            draft TEXT DEFAULT '',
            status INTEGER DEFAULT 0,
            last_timestamp INTEGER DEFAULT 0,
            sort_timestamp INTEGER DEFAULT 0,
            last_msg_type INTEGER DEFAULT 1,
            last_msg_sub_type INTEGER DEFAULT 0
        );
    """)
    sconn.executemany(
        "INSERT INTO SessionTable(username, type, unread_count, is_hidden, summary, last_timestamp, sort_timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (ALICE_WXID, 0, 2, 0, "最新一条文本消息", 1700001000, 1700001000),
            (GROUP_CID, 2, 0, 0, "合并转发记录", 1700002000, 1700002000),
            (BOB_WXID, 0, 0, 0, "hi bob", 1700000500, 1700000500),
            ("notifymessage", 0, 0, 0, "system", 1700003000, 1700003000),
        ],
    )
    sconn.commit()
    sconn.close()

    # 2. contact.db
    cconn = _open_sqlcipher_layout_db(root / "contact.db")
    cconn.executescript("""
        CREATE TABLE contact (
            id INTEGER PRIMARY KEY,
            username TEXT,
            local_type INTEGER DEFAULT 1,
            alias TEXT DEFAULT '',
            flag INTEGER DEFAULT 0,
            remark TEXT DEFAULT '',
            nick_name TEXT DEFAULT '',
            big_head_url TEXT DEFAULT '',
            small_head_url TEXT DEFAULT ''
        );
        CREATE TABLE stranger (
            id INTEGER PRIMARY KEY,
            username TEXT,
            alias TEXT DEFAULT '',
            flag INTEGER DEFAULT 0,
            remark TEXT DEFAULT '',
            nick_name TEXT DEFAULT '',
            big_head_url TEXT DEFAULT '',
            small_head_url TEXT DEFAULT ''
        );
        CREATE TABLE chat_room (
            id INTEGER PRIMARY KEY,
            username TEXT,
            owner TEXT,
            ext_buffer BLOB
        );
    """)
    cconn.executemany(
        "INSERT INTO contact(username, alias, flag, remark, nick_name) VALUES (?, ?, ?, ?, ?)",
        [
            (SELF_WXID, "my_alias", 0, "", "我自己"),
            (ALICE_WXID, "alice_wx", 2048, "爱丽丝备注", "Alice"),
            (BOB_WXID, "bob_wx", 0, "", "Bob"),
            (GROUP_CID, "", 0, "", "研发讨论群"),
        ],
    )
    ext_buf = build_chatroom_ext_buffer([(SELF_WXID, "群内我"), (ALICE_WXID, "群内爱丽丝"), (BOB_WXID, "群内鲍勃")])
    cconn.execute(
        "INSERT INTO chat_room(username, owner, ext_buffer) VALUES (?, ?, ?)",
        (GROUP_CID, ALICE_WXID, ext_buf),
    )
    cconn.commit()
    cconn.close()

    # 3. hardlink.db (optional image & file entries if wechat_data_dir provided)
    img_md5 = "a" * 32
    file_md5 = "b" * 32
    if wechat_data_dir is not None:
        wdir = Path(wechat_data_dir)
        alice_hash = hashlib.md5(ALICE_WXID.encode("utf-8")).hexdigest()
        img_folder = wdir / "msg" / "attach" / alice_hash / "2026-11" / "Img"
        img_folder.mkdir(parents=True, exist_ok=True)
        # Valid minimal JPEG bytes
        minimal_jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"
        (img_folder / f"{img_md5}.dat").write_bytes(make_v2_dat_image(minimal_jpeg, 0x5A, "0123456789abcdef"))

        file_folder = wdir / "msg" / "file" / "2026-11"
        file_folder.mkdir(parents=True, exist_ok=True)
        (file_folder / "report.txt").write_text("hello wechat report", encoding="utf-8")

    hconn = _open_sqlcipher_layout_db(root / "hardlink.db")
    hconn.executescript("""
        CREATE TABLE dir2id (username TEXT);
        CREATE TABLE image_hardlink_info_v4 (
            md5 TEXT, file_name TEXT, file_size INTEGER, modify_time INTEGER, dir1 INTEGER, dir2 INTEGER
        );
        CREATE TABLE file_hardlink_info_v4 (
            md5 TEXT, file_name TEXT, file_size INTEGER, modify_time INTEGER, dir1 INTEGER, dir2 INTEGER
        );
    """)
    alice_hash = hashlib.md5(ALICE_WXID.encode("utf-8")).hexdigest()
    hconn.execute("INSERT INTO dir2id(rowid, username) VALUES (1, ?)", (alice_hash,))
    hconn.execute("INSERT INTO dir2id(rowid, username) VALUES (2, '2026-11')")
    hconn.execute(
        "INSERT INTO image_hardlink_info_v4 VALUES (?, ?, 100, 1700000100, 1, 2)",
        (img_md5, f"{img_md5}.dat"),
    )
    hconn.execute(
        "INSERT INTO file_hardlink_info_v4 VALUES (?, 'report.txt', 19, 1700000200, 2, 2)",
        (file_md5,),
    )
    hconn.commit()
    hconn.close()

    # 4. message_0.db (Alice & Bob)
    m0 = _open_sqlcipher_layout_db(root / "message_0.db")
    m0.execute("CREATE TABLE Name2Id (user_name TEXT, is_session INTEGER DEFAULT 1)")
    m0.executemany(
        "INSERT INTO Name2Id(rowid, user_name, is_session) VALUES (?, ?, 1)",
        [(1, SELF_WXID), (2, ALICE_WXID), (3, BOB_WXID)],
    )

    def create_msg_table(conn, cid):
        tname = f"Msg_{hashlib.md5(cid.encode('utf-8')).hexdigest()}"
        conn.execute(f"""
            CREATE TABLE "{tname}" (
                local_id INTEGER PRIMARY KEY,
                server_id INTEGER DEFAULT 0,
                local_type INTEGER DEFAULT 1,
                sort_seq INTEGER DEFAULT 0,
                real_sender_id INTEGER DEFAULT 0,
                create_time INTEGER DEFAULT 0,
                message_content TEXT,
                compress_content BLOB,
                packed_info_data BLOB,
                source TEXT DEFAULT ''
            )
        """)
        return tname

    alice_tbl = create_msg_table(m0, ALICE_WXID)
    quote_xml = (
        "<msg><appmsg><title>回复你的问题 needle</title><type>57</type>"
        "<refermsg><type>1</type><svrid>101</svrid><displayname>Alice</displayname>"
        "<content>原始问题内容</content></refermsg></appmsg></msg>"
    )
    file_xml = (
        "<msg><appmsg><title>report.txt</title><type>6</type>"
        f"<appattach><totallen>19</totallen><fileext>txt</fileext><md5>{file_md5}</md5></appattach>"
        "</appmsg></msg>"
    )
    img_xml = f'<msg><img md5="{img_md5}" length="100" /></msg>'
    voice_xml = '<msg><voicemsg voicelength="5200" /></msg>'

    m0.executemany(
        f'INSERT INTO "{alice_tbl}" (local_id, server_id, local_type, sort_seq, real_sender_id, create_time, message_content, compress_content, packed_info_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
            (1, 101, 1, 1001, 2, 1700000100, "你好世界 needle", None, None),
            (2, 102, 3, 1002, 2, 1700000200, img_xml, None, None),
            (3, 103, 34, 1003, 2, 1700000300, voice_xml, None, build_voice_packed_info("语音转文字测试")),
            (4, 104, 244813135921, 1004, 1, 1700000400, "", compressor.compress(quote_xml.encode("utf-8")), None),
            (5, 105, 25769803825, 1005, 2, 1700000500, "", compressor.compress(file_xml.encode("utf-8")), None),
            (6, 106, 1, 1006, 1, 1700001000, "最新一条文本消息", None, None),
        ],
    )

    bob_tbl = create_msg_table(m0, BOB_WXID)
    m0.execute(
        f'INSERT INTO "{bob_tbl}" (local_id, server_id, local_type, sort_seq, real_sender_id, create_time, message_content) VALUES (1, 201, 1, 2001, 3, 1700000500, "hi bob")'
    )
    m0.commit()
    m0.close()

    # 5. message_1.db (Group chat with nested merged-forward recorditem)
    m1 = _open_sqlcipher_layout_db(root / "message_1.db")
    m1.execute("CREATE TABLE Name2Id (user_name TEXT, is_session INTEGER DEFAULT 1)")
    m1.executemany(
        "INSERT INTO Name2Id(rowid, user_name, is_session) VALUES (?, ?, 1)",
        [(1, SELF_WXID), (2, ALICE_WXID), (3, BOB_WXID)],
    )
    grp_tbl = create_msg_table(m1, GROUP_CID)
    nested_record = (
        "<recordinfo><title>内层记录</title><datalist count='1'>"
        "<dataitem datatype='1' dataid='sub1'><sourcename>Bob</sourcename>"
        "<sourcetime>2026-11-20 10:05:00</sourcetime><datadesc>内层转发关键词 needle</datadesc></dataitem>"
        "</datalist></recordinfo>"
    )
    outer_record = (
        "<recordinfo><title>群聊的聊天记录</title><desc>Alice: 第一条\nBob: 内层记录</desc>"
        "<datalist count='2'>"
        "<dataitem datatype='1' dataid='f1'><sourcename>Alice</sourcename>"
        "<sourcetime>2026-11-20 10:00:00</sourcetime><datadesc>转发第一条内容</datadesc></dataitem>"
        f"<dataitem datatype='17' dataid='f2'><sourcename>Bob</sourcename><datatitle>内层记录</datatitle>"
        f"<recordxml><![CDATA[{nested_record}]]></recordxml></dataitem>"
        "</datalist></recordinfo>"
    )
    fwd_app_xml = (
        f"{ALICE_WXID}:\n<msg><appmsg><title>群聊的聊天记录</title><des>Alice: 第一条</des>"
        f"<type>19</type><recorditem><![CDATA[{outer_record}]]></recorditem></appmsg></msg>"
    )
    m1.executemany(
        f'INSERT INTO "{grp_tbl}" (local_id, server_id, local_type, sort_seq, real_sender_id, create_time, message_content, compress_content) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [
            (1, 301, 1, 3001, 2, 1700001500, f"{ALICE_WXID}:\n大家好，这是一条群消息", None),
            (2, 302, 81604378673, 3002, 2, 1700002000, "", compressor.compress(fwd_app_xml.encode("utf-8"))),
        ],
    )
    m1.commit()
    m1.close()

    return root
