import logging
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from log_utils import log_event
from web.api import app

import uvicorn

# Configure logging
log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=log_format,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            os.path.join(config.LOGS_DIR, "wechat-exporter.log"),
            encoding="utf-8",
        ),
    ],
)

logger = logging.getLogger(__name__)


if __name__ == "__main__":
    runtime_diag = config.get_runtime_diagnostics()
    log_event(
        logger,
        "info",
        "app.starting",
        host=config.WEB_HOST,
        port=config.WEB_PORT,
        data_dir=config.WECHAT_DATA_DIR,
        sync_interval_hours=config.SYNC_INTERVAL_HOURS,
        config_source=runtime_diag["config_source"],
        candidates=runtime_diag["candidate_count"],
        selected_wxid_masked=runtime_diag["user_wxid_masked"],
        wechat_version=runtime_diag.get("wechat_version"),
    )
    if not os.path.isdir(config.ENCRYPTED_DB_DIR):
        log_event(
            logger,
            "warning",
            "app.encrypted_db_missing",
            path=config.ENCRYPTED_DB_DIR,
        )

    uvicorn.run(
        app,
        host=config.WEB_HOST,
        port=config.WEB_PORT,
        log_level="info",
    )
