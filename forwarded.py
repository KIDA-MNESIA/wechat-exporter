"""Decode WeChat merged-forward (<recorditem> / <recordinfo>) XML payloads.

Produces bounded, preorder child messages with path/parent_path, parse_status,
and explicit errors matching the dingtalk-exporter contract.
"""

from datetime import datetime
import html
import re
import xml.etree.ElementTree as ET

from message_content import build_agent_content

_RECORDINFO_RE = re.compile(r"(<recordinfo\b[^>]*>.*</recordinfo>)", re.IGNORECASE | re.DOTALL)
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

# Mapping of WeChat recorditem dataitem datatype -> normalized content_type / label
_DATATYPE_META = {
    1: (1, "文本", ""),
    2: (3, "图片", "image"),
    3: (34, "语音", "voice"),
    4: (43, "视频", "video"),
    5: (49, "链接", "link"),
    6: (48, "位置", "location"),
    7: (49, "音乐", "music"),
    8: (49, "文件", "file"),
    10: (49, "商品", "product"),
    11: (49, "商品", "product"),
    14: (47, "动画表情", "emoji"),
    16: (42, "名片", "contact"),
    17: (49, "合并转发", "forwarded"),
    19: (49, "小程序", "mini_program"),
    22: (49, "视频号", "finder"),
    23: (49, "视频号直播", "finder"),
    24: (49, "笔记", "note"),
}


def _clean_xml(raw):
    text = str(raw or "").strip()
    if not text:
        return ""
    if text.startswith("<![CDATA[") and text.endswith("]]>"):
        text = text[9:-3].strip()
    if "&lt;recordinfo" in text.lower() and "<recordinfo" not in text.lower():
        text = html.unescape(text)
    return _CONTROL_CHARS_RE.sub("", text)


def _child_text(elem, *names):
    for name in names:
        node = elem.find(name)
        if node is not None and node.text is not None:
            value = node.text.strip()
            if value:
                return value
        for child in elem:
            if isinstance(child.tag, str) and child.tag.lower() == name.lower():
                value = "".join(child.itertext()).strip()
                if value:
                    return value
    return ""


def _parse_timestamp_ms(elem):
    raw_sec = _child_text(elem, "srcMsgCreateTime")
    if raw_sec and raw_sec.isdigit():
        val = int(raw_sec)
        return val * 1000 if val < 10_000_000_000 else val
    source_time = _child_text(elem, "sourcetime")
    if source_time:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M"):
            try:
                return int(datetime.strptime(source_time, fmt).timestamp() * 1000)
            except ValueError:
                continue
    return 0


def _format_ts(ts_ms, fallback=""):
    if ts_ms:
        try:
            return datetime.fromtimestamp(ts_ms / 1000).strftime("%Y-%m-%d %H:%M:%S")
        except (OSError, ValueError, OverflowError):
            pass
    return fallback


def _extract_recordinfo_element(xml_text):
    cleaned = _clean_xml(xml_text)
    if not cleaned:
        return None, "missing_payload"
    match = _RECORDINFO_RE.search(cleaned)
    fragment = match.group(1) if match else cleaned
    try:
        root = ET.fromstring(fragment)
    except ET.ParseError:
        try:
            unescaped = _CONTROL_CHARS_RE.sub("", html.unescape(fragment))
            match2 = _RECORDINFO_RE.search(unescaped)
            root = ET.fromstring(match2.group(1) if match2 else unescaped)
        except ET.ParseError:
            return None, "invalid_xml"
    if root.tag.lower() != "recordinfo":
        found = root.find(".//recordinfo")
        if found is None:
            return None, "missing_recordinfo"
        root = found
    return root, None


class _RecordDecoder:
    def __init__(self, max_depth, max_messages, max_payload_bytes, max_total_bytes):
        self.max_depth = max_depth
        self.max_messages = max_messages
        self.max_payload_bytes = max_payload_bytes
        self.max_total_bytes = max_total_bytes
        self.total_bytes = 0
        self.visited = 0
        self.messages = []
        self.errors = []

    def error(self, path, code):
        item = {"path": list(path), "code": code}
        if item not in self.errors and len(self.errors) < self.max_messages + 1:
            self.errors.append(item)

    def _parse_dataitem(self, item, path, parent_path, depth, cid):
        dt_raw = item.attrib.get("datatype") or _child_text(item, "datatype") or "0"
        try:
            datatype = int(str(dt_raw).strip())
        except ValueError:
            datatype = 0

        data_id = item.attrib.get("dataid") or _child_text(item, "dataid") or ""
        sender_name = _child_text(item, "sourcename")
        source_time_str = _child_text(item, "sourcetime")
        created_at = _parse_timestamp_ms(item)
        created_at_str = _format_ts(created_at, source_time_str)

        source_node = item.find("dataitemsource")
        sender_id = ""
        if source_node is not None:
            sender_id = _child_text(source_node, "realchatname", "fromusr")

        title = _child_text(item, "datatitle")
        desc = _child_text(item, "datadesc")
        full_md5 = _child_text(item, "fullmd5", "md5", "cdnthumbmd5").lower()
        thumb_md5 = _child_text(item, "thumbfullmd5", "cdnthumbmd5").lower()
        data_size_str = _child_text(item, "datasize", "fullsize")
        try:
            data_size = int(data_size_str) if data_size_str else 0
        except ValueError:
            data_size = 0

        content_type, type_name, subtype = _DATATYPE_META.get(datatype, (0, f"未知({datatype})", ""))
        parse_status = "complete"
        text = ""
        attachments = []
        image_info = None
        video_info = None
        link_info = None
        forwarded_info = None

        if datatype == 1:
            text = desc or title
            if not text:
                parse_status = "partial"
        elif datatype == 2:
            text = "[图片]"
            if full_md5 or thumb_md5:
                image_info = {
                    "md5": full_md5 or thumb_md5,
                    "thumb_md5": thumb_md5,
                    "cached": False,
                    "images": [{"md5": full_md5 or thumb_md5, "thumb_md5": thumb_md5, "cached": False}],
                }
        elif datatype == 3:
            dur = _child_text(item, "duration")
            text = desc or (f"[语音 {dur}秒]" if dur else "[语音]")
        elif datatype == 4:
            text = "[视频]"
            dur = _child_text(item, "duration")
            video_info = {"duration": int(dur) if dur.isdigit() else 0, "md5": full_md5}
        elif datatype == 5:
            url = _child_text(item, "link")
            text = title or desc or "[链接]"
            link_info = {"title": title, "desc": desc, "url": url, "link_type": "web_link"}
        elif datatype == 6:
            loc = item.find("locitem")
            poiname = _child_text(loc, "poiname") if loc is not None else ""
            label = _child_text(loc, "label") if loc is not None else ""
            text = f"[位置] {poiname or label}".strip()
        elif datatype == 8:
            fname = title or desc or "未知文件"
            text = f"[文件] {fname}"
            attachments.append({
                "type": 49,
                "filename": fname,
                "file_size": data_size,
                "file_type": _child_text(item, "datafmt"),
                "md5": full_md5,
                "local_available": False,
            })
        elif datatype == 14:
            text = "[动画表情]"
        elif datatype == 16:
            text = f"[名片] {title or desc}".strip()
        elif datatype == 17:
            nested_xml = _child_text(item, "recordxml")
            if not nested_xml:
                rec_node = item.find("recordinfo")
                if rec_node is not None:
                    nested_xml = ET.tostring(rec_node, encoding="unicode")
            text = title or desc or "[合并转发]"
        elif datatype in (19, 22, 23, 7, 10, 11, 24):
            text = title or desc or f"[{type_name}]"
        else:
            text = desc or title or f"[未知转发消息({datatype})]"
            if not (desc or title):
                parse_status = "unsupported"
                self.error(path, "unsupported_content_type")

        msg = {
            "id": data_id or f"fwd_{'_'.join(str(p) for p in path)}",
            "cid": cid,
            "sender_id": sender_id,
            "sender_name": sender_name or sender_id or "未知发送者",
            "content_type": content_type,
            "content_type_name": type_name,
            "message_subtype": subtype,
            "text": text,
            "created_at": created_at,
            "created_at_str": created_at_str,
            "attachments": attachments,
            "at_ids": {},
            "path": list(path),
            "parent_path": list(parent_path),
            "parse_status": parse_status,
        }
        if image_info is not None:
            msg["image_info"] = image_info
        if video_info is not None:
            msg["video_info"] = video_info
        if link_info is not None:
            msg["link_info"] = link_info

        self.messages.append(msg)

        if datatype == 17:
            nested_xml = ""
            rec_xml_node = item.find("recordxml")
            if rec_xml_node is not None:
                inner_rec = rec_xml_node.find("recordinfo")
                if inner_rec is not None:
                    nested_xml = ET.tostring(inner_rec, encoding="unicode")
                else:
                    nested_xml = "".join(rec_xml_node.itertext()).strip()
            if not nested_xml:
                rec_node = item.find("recordinfo")
                if rec_node is not None:
                    nested_xml = ET.tostring(rec_node, encoding="unicode")
            if depth >= self.max_depth:
                self.error(path, "depth_limit")
                forwarded_info = {
                    "title": title or "聊天记录",
                    "summary": desc,
                    "total": 0,
                    "parse_status": "partial",
                    "errors": [{"path": list(path), "code": "depth_limit"}],
                }
            elif nested_xml:
                forwarded_info = self.visit(nested_xml, path, depth + 1, cid, fallback_title=title, fallback_summary=desc)
            else:
                self.error(path, "missing_payload")
                forwarded_info = {
                    "title": title or "聊天记录",
                    "summary": desc,
                    "total": 0,
                    "parse_status": "partial",
                    "errors": [{"path": list(path), "code": "missing_payload"}],
                }
            msg["forwarded_info"] = forwarded_info
            if forwarded_info["parse_status"] != "complete":
                msg["parse_status"] = forwarded_info["parse_status"]

        msg["content"] = build_agent_content(msg)
        return msg

    def visit(self, record_xml, parent_path, depth, cid, fallback_title="", fallback_summary=""):
        error_start = len(self.errors)
        message_start = len(self.messages)

        raw_str = str(record_xml or "")
        payload_bytes = len(raw_str.encode("utf-8", errors="ignore"))
        if payload_bytes > self.max_payload_bytes:
            self.error(parent_path, "payload_size_limit")
            return {
                "title": fallback_title or "聊天记录",
                "summary": fallback_summary,
                "total": 0,
                "parse_status": "partial" if (fallback_title or fallback_summary) else "unsupported",
                "errors": self.errors[error_start:],
            }
        if self.total_bytes + payload_bytes > self.max_total_bytes:
            self.error(parent_path, "total_size_limit")
            return {
                "title": fallback_title or "聊天记录",
                "summary": fallback_summary,
                "total": 0,
                "parse_status": "partial" if (fallback_title or fallback_summary) else "unsupported",
                "errors": self.errors[error_start:],
            }
        self.total_bytes += payload_bytes

        root, err_code = _extract_recordinfo_element(raw_str)
        if root is None:
            self.error(parent_path, err_code or "missing_payload")
            return {
                "title": fallback_title or "聊天记录",
                "summary": fallback_summary,
                "total": 0,
                "parse_status": "partial" if (fallback_title or fallback_summary) else "unsupported",
                "errors": self.errors[error_start:],
            }

        title = _child_text(root, "title") or fallback_title or "聊天记录"
        summary = _child_text(root, "desc") or fallback_summary

        datalist = root.find("datalist")
        items = list(datalist.findall("dataitem")) if datalist is not None else list(root.findall("dataitem"))
        if not items:
            self.error(parent_path, "missing_payload")

        for index, item in enumerate(items):
            path = [*parent_path, index]
            if self.visited >= self.max_messages:
                self.error(path, "message_limit")
                break
            self.visited += 1
            self._parse_dataitem(item, path, parent_path, depth, cid)

        errors = self.errors[error_start:]
        total = len(self.messages) - message_start
        if errors:
            status = "partial" if (total or title or summary) else "unsupported"
        elif any(m.get("parse_status") != "complete" for m in self.messages[message_start:]):
            status = "partial"
        else:
            status = "complete"

        return {
            "title": title,
            "summary": summary,
            "total": total,
            "parse_status": status,
            "errors": errors,
        }


def decode_forwarded(
    record_xml,
    *,
    cid="",
    fallback_title="",
    fallback_summary="",
    max_depth=8,
    max_messages=1000,
    max_payload_bytes=2 * 1024 * 1024,
    max_total_bytes=8 * 1024 * 1024,
):
    """Return bounded, preorder child messages and explicit decoding gaps."""
    if max_depth < 0 or min(max_messages, max_payload_bytes, max_total_bytes) < 1:
        raise ValueError("forwarded decoding limits must be positive (depth may be zero)")
    decoder = _RecordDecoder(max_depth, max_messages, max_payload_bytes, max_total_bytes)
    info = decoder.visit(
        record_xml,
        [],
        0,
        cid,
        fallback_title=fallback_title,
        fallback_summary=fallback_summary,
    )
    info["messages"] = decoder.messages
    return info
