import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import attachment
import config
import decrypt
import exporter
import forwarded
import jobs
import parser
import scheduler
import search_index
import snapshots
from tests.fixtures import (
    ALICE_WXID,
    BOB_WXID,
    GROUP_CID,
    SELF_WXID,
    create_synthetic_snapshot,
    encrypt_sqlcipher4_db,
    make_v2_dat_image,
)
from web.api import app


class WeChatExporterTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.wechat_data_dir = self.root / "wechat_account"
        self.db_storage = self.wechat_data_dir / "db_storage"
        self.plain_dir = self.root / "plain_snapshot"
        self.data_dir = self.root / "app_data"
        self.decrypted_dir = self.data_dir / "decrypted"
        self.export_dir = self.data_dir / "exports"
        self.media_cache = self.data_dir / "media_cache"
        for d in (self.data_dir, self.decrypted_dir, self.export_dir, self.media_cache):
            d.mkdir(parents=True, exist_ok=True)

        create_synthetic_snapshot(self.plain_dir, wechat_data_dir=self.wechat_data_dir)

        patches = [
            patch.object(config, "USER_WXID", SELF_WXID),
            patch.object(config, "USER_UID", SELF_WXID),
            patch.object(config, "USER_NICKNAME", "我自己"),
            patch.object(config, "WECHAT_DATA_DIR", str(self.wechat_data_dir)),
            patch.object(config, "ENCRYPTED_DB_DIR", str(self.db_storage)),
            patch.object(config, "DATA_DIR", str(self.data_dir)),
            patch.object(config, "DECRYPTED_DIR", str(self.decrypted_dir)),
            patch.object(config, "EXPORT_DIR", str(self.export_dir)),
            patch.object(config, "MEDIA_CACHE_DIR", str(self.media_cache)),
            patch.object(config, "KEYS_FILE", str(self.data_dir / "keys.json")),
            patch.object(config, "SYNC_STATE_FILE", str(self.data_dir / "sync_state.json")),
            patch.object(config, "WECHAT_IMAGE_XOR_KEY", "0x5A"),
            patch.object(config, "WECHAT_IMAGE_AES_KEY", "0123456789abcdef"),
            patch.object(config, "COPY_RETRY_DELAY", 0),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_sqlcipher4_decrypt_and_snapshot_publish_and_reuse(self):
        key_hex = "0123456789abcdef" * 4
        # Encrypt all synthetic DBs into db_storage structure
        mapping = {
            "session.db": self.db_storage / "session" / "session.db",
            "contact.db": self.db_storage / "contact" / "contact.db",
            "hardlink.db": self.db_storage / "hardlink" / "hardlink.db",
            "message_0.db": self.db_storage / "message" / "message_0.db",
            "message_1.db": self.db_storage / "message" / "message_1.db",
        }
        for fname, dst in mapping.items():
            dst.parent.mkdir(parents=True, exist_ok=True)
            encrypt_sqlcipher4_db(self.plain_dir / fname, dst, key_hex)

        first = decrypt.refresh_database(db_storage_dir=self.db_storage, key_hex=key_hex)
        self.assertEqual(first["outcome"], "updated")
        self.assertEqual(first["latest_message_at"], 1700002000 * 1000)

        # Second refresh with unchanged source must return unchanged
        second = decrypt.refresh_database(db_storage_dir=self.db_storage, key_hex=key_hex)
        self.assertEqual(second["outcome"], "unchanged")
        self.assertEqual(second["snapshot_id"], first["snapshot_id"])

        # Bad key must fallback to previous snapshot rather than losing it
        bad_key = "fedcba9876543210" * 4
        fallback = decrypt.refresh_database(db_storage_dir=self.db_storage, key_hex=bad_key)
        self.assertEqual(fallback["outcome"], "fallback")
        self.assertEqual(fallback["snapshot_id"], first["snapshot_id"])

    def test_conversations_messages_forwarded_and_search(self):
        pub = snapshots.publish_snapshot(self.plain_dir)
        sid = pub["snapshot_id"]

        with parser.get_connection(snapshot_id=sid) as ctx:
            convs = parser.get_conversations(ctx)
            # notifymessage filtered out -> 3 conversations
            self.assertEqual(convs["total"], 3)
            # Alice is pinned (flag & 2048), so Alice appears first despite older timestamp
            self.assertEqual(convs["conversations"][0]["cid"], ALICE_WXID)
            self.assertEqual(convs["conversations"][0]["title"], "爱丽丝备注")

            # Keyword filter matches alias / nick_name / remark
            alice_kw = parser.get_conversations(ctx, keyword="alice_wx")
            self.assertEqual(alice_kw["total"], 1)
            self.assertEqual(alice_kw["conversations"][0]["cid"], ALICE_WXID)

            # Messages for Alice
            msgs = parser.get_messages(ctx, ALICE_WXID, limit=10)
            self.assertEqual(msgs["total"], 6)
            self.assertEqual(msgs["messages"][0]["text"], "你好世界 needle")
            self.assertEqual(msgs["messages"][1]["content_type"], 3)
            self.assertTrue(msgs["messages"][1]["image_info"]["cached"])
            self.assertEqual(msgs["messages"][2]["audio_info"]["transcript"], "语音转文字测试")
            self.assertEqual(msgs["messages"][3]["message_subtype"], "reply")
            self.assertEqual(msgs["messages"][3]["quote_info"]["source_preview"], "原始问题内容")
            self.assertTrue(msgs["messages"][4]["attachments"][0]["local_available"])

            # Group messages & group nicknames & nested forwarded
            grp = parser.get_messages(ctx, GROUP_CID, limit=10)
            self.assertEqual(grp["total"], 2)
            self.assertEqual(grp["messages"][0]["sender_name"], "群内爱丽丝")
            self.assertEqual(grp["messages"][1]["message_subtype"], "forwarded")
            self.assertEqual(grp["messages"][1]["forwarded_info"]["total"], 3)

            fwd = parser.get_forwarded_messages(ctx, GROUP_CID, 2)
            self.assertEqual(fwd["total"], 3)
            self.assertEqual(fwd["parse_status"], "complete")
            self.assertEqual(fwd["messages"][0]["path"], [0])
            self.assertEqual(fwd["messages"][1]["path"], [1])
            self.assertEqual(fwd["messages"][2]["path"], [1, 0])
            self.assertEqual(fwd["messages"][2]["parent_path"], [1])
            self.assertIn("needle", fwd["messages"][2]["text"])

            # Search index finds root messages AND nested forwarded child with matched_paths
            search_res = parser.search_messages_page(ctx, "needle", mode="text")
            self.assertEqual(search_res["total"], 3)
            fwd_hit = next(m for m in search_res["messages"] if m["cid"] == GROUP_CID)
            self.assertEqual(fwd_hit["matched_paths"], [[1, 0]])

            stats = parser.get_conversation_stats(ctx)
            self.assertEqual(stats["total_conversations"], 3)
            self.assertEqual(stats["group_conversations"], 1)
            self.assertEqual(stats["single_conversations"], 2)
            self.assertEqual(stats["total_messages"], 9)

    def test_dat_decryption_and_export_packaging(self):
        pub = snapshots.publish_snapshot(self.plain_dir)
        out_dir = exporter.export_by_cids([ALICE_WXID, GROUP_CID], snapshot_id=pub["snapshot_id"])
        export_json = json.loads((Path(out_dir) / "export.json").read_text(encoding="utf-8"))
        self.assertEqual(export_json["total_conversations"], 2)

        alice_conv = export_json["conversations"][0]
        img_msg = alice_conv["messages"][1]
        self.assertTrue(img_msg["attachment_export_path"].startswith("images/"))
        exported_img = Path(out_dir) / img_msg["attachment_export_path"]
        self.assertTrue(exported_img.is_file())
        self.assertTrue(exported_img.read_bytes().startswith(b"\xff\xd8\xff"))

        file_msg = alice_conv["messages"][4]
        self.assertEqual(file_msg["attachments"][0]["export_path"], "files/report.txt")
        self.assertEqual((Path(out_dir) / "files" / "report.txt").read_text(encoding="utf-8"), "hello wechat report")

    def test_web_api_and_jobs(self):
        pub = snapshots.publish_snapshot(self.plain_dir)
        client = TestClient(app)

        self.assertEqual(client.get("/").status_code, 200)
        cfg = client.get("/api/config").json()
        self.assertEqual(cfg["user_wxid"], SELF_WXID)

        convs = client.get("/api/conversations").json()
        self.assertEqual(convs["total"], 3)

        msgs = client.get(f"/api/conversations/{GROUP_CID}/messages").json()
        self.assertEqual(msgs["total"], 2)

        fwd = client.get(f"/api/conversations/{GROUP_CID}/messages/2/forwarded").json()
        self.assertEqual(fwd["total"], 3)

        # Decrypted image serving
        img_resp = client.get(f"/api/media/image/{'a'*32}?cid={ALICE_WXID}")
        self.assertEqual(img_resp.status_code, 200)
        self.assertTrue(img_resp.content.startswith(b"\xff\xd8\xff"))

        # Export selected via job API
        exp = client.post("/api/export/selected", json={"cids": [ALICE_WXID]}).json()
        self.assertEqual(exp["status"], "started")
        job_id = exp["job_id"]
        for _ in range(50):
            job = client.get(f"/api/jobs/{job_id}").json()
            if job["status"] != "running":
                break
            time.sleep(0.05)
        self.assertEqual(job["status"], "succeeded")
        self.assertTrue(Path(job["result"]["export_path"]).is_dir())

        exports_list = client.get("/api/exports").json()["exports"]
        self.assertEqual(len(exports_list), 1)
        dl = client.get(exports_list[0]["download_url"])
        self.assertEqual(dl.status_code, 200)
        self.assertEqual(dl.headers["content-type"], "application/zip")

    def test_multi_shard_conversation_messages_merge_chronologically(self):
        import hashlib
        # Add an extra table for ALICE_WXID inside message_1.db with newer messages
        tname = f"Msg_{hashlib.md5(ALICE_WXID.encode('utf-8')).hexdigest()}"
        m1 = sqlite3.connect(self.plain_dir / "message_1.db")
        m1.execute(f"""
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
        m1.execute(
            f'INSERT INTO "{tname}" (local_id, server_id, local_type, sort_seq, real_sender_id, create_time, message_content) '
            'VALUES (1, 9001, 1, 9001, 2, 1700009999, "newer shard message")'
        )
        m1.commit()
        m1.close()

        pub = snapshots.publish_snapshot(self.plain_dir)
        with parser.get_connection(snapshot_id=pub["snapshot_id"]) as ctx:
            page = parser.get_messages(ctx, ALICE_WXID, limit=2, offset=0)
            self.assertEqual(page["total"], 7)
            self.assertEqual(page["messages"][-1]["text"], "newer shard message")
            self.assertEqual(page["messages"][0]["text"], "最新一条文本消息")
            self.assertTrue(page["has_more"])
            older = parser.get_messages(ctx, ALICE_WXID, limit=10, offset=page["next_offset"])
            self.assertEqual(older["returned"], 5)
            self.assertFalse(older["has_more"])


if __name__ == "__main__":
    unittest.main()
