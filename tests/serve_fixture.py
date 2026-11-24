"""Serve MCP over stdio backed by a synthetic snapshot directory."""

import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import config
import mcp_server
import snapshots
from tests.fixtures import SELF_WXID

if __name__ == "__main__":
    snapshot_src = sys.argv[1]
    data_dir = Path(sys.argv[2])
    config.USER_WXID = SELF_WXID
    config.USER_UID = SELF_WXID
    config.DATA_DIR = str(data_dir)
    config.DECRYPTED_DIR = str(data_dir / "decrypted")
    config.EXPORT_DIR = str(data_dir / "exports")
    config.MEDIA_CACHE_DIR = str(data_dir / "media_cache")
    config.SYNC_STATE_FILE = str(data_dir / "sync_state.json")
    os.makedirs(config.DECRYPTED_DIR, exist_ok=True)
    snapshots.publish_snapshot(snapshot_src)
    mcp_server.mcp.run(transport="stdio")
