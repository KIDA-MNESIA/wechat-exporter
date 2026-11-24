import json
import logging
import os
import uuid
from contextlib import closing
from datetime import datetime

import config
from attachment import process_all_attachments
from log_utils import log_event
from parser import (
    _format_timestamp,
    get_connection,
    get_conversation_info,
    get_conversations,
    get_messages,
    get_new_messages,
)

logger = logging.getLogger(__name__)


def _create_export_dir(base_dir, prefix):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_dir = os.path.join(base_dir, f"{prefix}_{timestamp}_{uuid.uuid4().hex[:8]}")
    os.makedirs(export_dir, exist_ok=False)
    return export_dir


def _write_export_json(export_data, export_dir):
    json_path = os.path.join(export_dir, "export.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, ensure_ascii=False, indent=2)
    return json_path


def _chronological_messages(ctx, cid, batch_size, since_time=None, until_time=None):
    """Reverse page order, preserving the complete database tie-break order."""
    pages = []
    offset = 0
    while True:
        result = get_messages(
            ctx,
            cid,
            limit=batch_size,
            offset=offset,
            since_time=since_time,
            until_time=until_time,
            include_forwarded=True,
        )
        pages.append(result["messages"])
        if not result["has_more"]:
            break
        offset = result["next_offset"]
    return [message for page in reversed(pages) for message in page]


def _attachment_messages(messages):
    for message in messages:
        yield message
        yield from message.get("forwarded_messages", [])


def _serialize_message(msg):
    """Serialize a message dict for AI-friendly JSON export."""
    result = {
        "message_id": msg.get("id"),
        "server_id": msg.get("server_id"),
        "sender_id": msg.get("sender_id"),
        "sender_name": msg.get("sender_name"),
        "is_self": bool(msg.get("is_self", False)),
        "content_type": msg.get("content_type"),
        "content_type_name": msg.get("content_type_name"),
        "message_subtype": msg.get("message_subtype"),
        "text": msg.get("text", ""),
        "created_at": msg.get("created_at"),
        "created_at_str": msg.get("created_at_str"),
        "attachments": msg.get("attachments", []),
        "at_ids": msg.get("at_ids", {}),
        "parse_status": msg.get("parse_status", "unsupported"),
    }
    for key in (
        "path",
        "parent_path",
        "forwarded_info",
        "video_info",
        "contact_info",
        "link_info",
        "location_info",
        "transfer_info",
        "image_info",
        "audio_info",
        "quote_info",
        "attachment_export_path",
        "image_export_paths",
    ):
        if key in msg and msg[key] is not None:
            result[key] = msg[key]
    if "forwarded_messages" in msg:
        result["forwarded_messages"] = [_serialize_message(child) for child in msg["forwarded_messages"]]

    from message_content import build_agent_content
    result["content"] = build_agent_content(msg, exported=True)
    return result


def export_all(base_dir=None, batch_size=500, snapshot_id=None, db_dir=None):
    """Export all conversations and messages as a self-contained directory with attachments."""
    if base_dir is None:
        base_dir = config.EXPORT_DIR
    os.makedirs(base_dir, exist_ok=True)

    with closing(get_connection(db_dir=db_dir, snapshot_id=snapshot_id)) as ctx:
        export_dir = _create_export_dir(base_dir, "full_export")
        log_event(logger, "info", "export.full_started", export_dir=export_dir, batch_size=batch_size)

        convs_result = get_conversations(ctx, limit=10000)
        total_convs = convs_result["total"]
        log_event(logger, "info", "export.full_conversations_loaded", total_conversations=total_convs)

        export_data = {
            "export_time": datetime.now().isoformat(),
            "export_type": "full",
            "total_conversations": total_convs,
            "conversations": [],
        }
        from snapshots import connection_metadata
        export_data.update(connection_metadata(ctx))

        all_raw_messages = []
        msg_by_cid = {}

        for idx, conv in enumerate(convs_result["conversations"]):
            cid = conv["cid"]
            msgs = _chronological_messages(ctx, cid, batch_size)
            msg_by_cid[cid] = msgs
            all_raw_messages.extend(msgs)
            export_data["conversations"].append({
                "conversation_id": cid,
                "title": conv["title"],
                "type": conv["type"],
                "member_count": conv.get("member_count", 0),
                "message_count": len(msgs),
                "messages": [],
            })
            if (idx + 1) % 50 == 0:
                log_event(
                    logger,
                    "info",
                    "export.full_progress",
                    fetched_conversations=idx + 1,
                    total_conversations=total_convs,
                )

        log_event(
            logger,
            "info",
            "export.attachments_processing",
            mode="full",
            message_count=len(all_raw_messages),
            export_dir=export_dir,
        )
        stats = process_all_attachments(list(_attachment_messages(all_raw_messages)), export_dir, ctx=ctx)
        log_event(logger, "info", "export.attachments_processed", mode="full", stats=stats)

        for conv_data in export_data["conversations"]:
            cid = conv_data["conversation_id"]
            conv_data["messages"] = [_serialize_message(m) for m in msg_by_cid.get(cid, [])]

        json_path = _write_export_json(export_data, export_dir)
        log_event(
            logger,
            "info",
            "export.full_completed",
            export_dir=export_dir,
            json_path=json_path,
            total_conversations=total_convs,
            total_messages=len(all_raw_messages),
        )
        return export_dir


def export_incremental(since_time, base_dir=None, snapshot_id=None, db_dir=None):
    """Export only new messages since the given millisecond timestamp, with attachments."""
    if base_dir is None:
        base_dir = config.EXPORT_DIR
    os.makedirs(base_dir, exist_ok=True)

    with closing(get_connection(db_dir=db_dir, snapshot_id=snapshot_id)) as ctx:
        export_dir = _create_export_dir(base_dir, "incremental")
        since_str = datetime.fromtimestamp(since_time / 1000).isoformat() if since_time else "beginning"
        log_event(
            logger,
            "info",
            "export.incremental_started",
            export_dir=export_dir,
            since_time=since_time,
            since_time_str=since_str,
        )

        all_messages = get_new_messages(ctx, since_time)
        log_event(logger, "info", "export.incremental_messages_loaded", total_messages=len(all_messages))

        if not all_messages:
            log_event(logger, "info", "export.incremental_skipped", reason="no_new_messages")
            try:
                os.rmdir(export_dir)
            except OSError:
                pass
            return {
                "path": None,
                "message_count": 0,
                "min_created_at": None,
                "max_created_at": None,
            }

        stats = process_all_attachments(list(_attachment_messages(all_messages)), export_dir, ctx=ctx)
        log_event(logger, "info", "export.attachments_processed", mode="incremental", stats=stats)

        conv_messages = {}
        for msg in all_messages:
            cid = msg["cid"]
            if cid not in conv_messages:
                info = get_conversation_info(ctx, cid)
                conv_messages[cid] = {
                    "conversation_id": cid,
                    "title": info.get("title", cid),
                    "type": info.get("type", "group" if cid.endswith("@chatroom") else "single"),
                    "messages": [],
                }
            conv_messages[cid]["messages"].append(_serialize_message(msg))

        export_data = {
            "export_time": datetime.now().isoformat(),
            "export_type": "incremental",
            "from_time": since_str,
            "total_messages": len(all_messages),
            "conversations": list(conv_messages.values()),
        }
        from snapshots import connection_metadata
        export_data.update(connection_metadata(ctx))

        json_path = _write_export_json(export_data, export_dir)
        log_event(
            logger,
            "info",
            "export.incremental_completed",
            export_dir=export_dir,
            json_path=json_path,
            total_messages=len(all_messages),
            total_conversations=len(conv_messages),
        )
        return {
            "path": export_dir,
            "message_count": len(all_messages),
            "min_created_at": all_messages[0]["created_at"],
            "max_created_at": all_messages[-1]["created_at"],
        }


def export_by_cids(cids, base_dir=None, batch_size=500, since_time=None, until_time=None, snapshot_id=None, db_dir=None):
    """Export only the selected conversations by cid (username) list, with attachments."""
    if base_dir is None:
        base_dir = config.EXPORT_DIR
    os.makedirs(base_dir, exist_ok=True)

    with closing(get_connection(db_dir=db_dir, snapshot_id=snapshot_id)) as ctx:
        export_dir = _create_export_dir(base_dir, "export")
        time_desc = f" (since {_format_timestamp(since_time)})" if since_time else ""
        log_event(
            logger,
            "info",
            "export.selected_started",
            export_dir=export_dir,
            conversation_count=len(cids),
            since_time=since_time,
            until_time=until_time,
            time_desc=time_desc.strip() or None,
            batch_size=batch_size,
        )

        export_data = {
            "export_time": datetime.now().isoformat(),
            "export_type": "selected",
            "since_time": since_time,
            "until_time": until_time,
            "total_conversations": len(cids),
            "conversations": [],
        }
        from snapshots import connection_metadata
        export_data.update(connection_metadata(ctx))

        all_raw_messages = []
        msg_by_cid = {}

        for cid in cids:
            info = get_conversation_info(ctx, cid)
            msgs = _chronological_messages(ctx, cid, batch_size, since_time, until_time)
            msg_by_cid[cid] = msgs
            all_raw_messages.extend(msgs)
            export_data["conversations"].append({
                "conversation_id": cid,
                "title": info.get("title", cid),
                "type": info.get("type", "group" if cid.endswith("@chatroom") else "single"),
                "member_count": info.get("member_count", 0),
                "message_count": len(msgs),
                "messages": [],
            })

        stats = process_all_attachments(list(_attachment_messages(all_raw_messages)), export_dir, ctx=ctx)
        log_event(logger, "info", "export.attachments_processed", mode="selected", stats=stats)

        for conv_data in export_data["conversations"]:
            cid = conv_data["conversation_id"]
            conv_data["messages"] = [_serialize_message(m) for m in msg_by_cid.get(cid, [])]
            conv_data["message_count"] = len(conv_data["messages"])

        json_path = _write_export_json(export_data, export_dir)
        log_event(
            logger,
            "info",
            "export.selected_completed",
            export_dir=export_dir,
            json_path=json_path,
            total_conversations=len(cids),
            total_messages=len(all_raw_messages),
        )
        return export_dir


if __name__ == "__main__":
    import io
    import sys

    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    logging.basicConfig(level=logging.INFO)
    path = export_all()
    print(f"导出结果已保存到：{path}")
