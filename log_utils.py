import json


def _event_text(event, fields):
    templates = {
        "app.starting": "应用启动，正在初始化微信聊天记录导出 Web 服务",
        "app.partial_environment_override": "环境变量覆盖配置不完整，将继续使用自动检测结果",
        "app.encrypted_db_missing": "未找到微信加密数据库目录，请确认微信客户端已登录且数据目录正确",
        "api.startup_completed": "Web API 启动完成",
        "api.shutdown_completed": "Web API 已停止",
        "api.local_file_failed": "读取本地附件失败",
        "api.open_export_folder_failed": "打开导出目录失败",
        "api.delete_export_failed": "删除导出项失败",
        "attachment.copy_failed": "复制或解密附件失败",
        "attachment.processed": "附件处理完成",
        "config.source_environment": "已通过环境变量指定微信数据目录",
        "config.auto_detected": "已自动识别到微信数据目录",
        "config.multiple_accounts_detected": "检测到多个微信账号目录，已优先选择最近更新的账号",
        "config.global_config_loaded": "已从微信 global_config 读取最近登录账号信息",
        "key.cache_hit": "已命中本地缓存且通过校验的微信数据库密钥",
        "key.cache_invalid": "本地缓存密钥校验未通过，准备重新提取",
        "key.dll_scan_completed": "已完成 Weixin.dll 辅助密钥扫描",
        "key.v4_scan_started": "开始从运行中的微信进程内存扫描数据库密钥",
        "key.v4_scan_succeeded": "已从运行中的微信进程内存成功提取并校验数据库密钥",
        "key.v4_scan_failed": "微信 V4 内存扫描密钥失败",
        "key.hook_fallback_started": "尝试通过 wx_key Hook 获取微信数据库密钥",
        "key.image_resolved": "已通过本地 kvcomm 与 V2 模板校验解析图片密钥",
        "decrypt.copy_succeeded": "已复制加密数据库到临时目录",
        "decrypt.copy_retry_failed": "复制加密数据库失败，准备重试",
        "decrypt.db_reused": "源数据库未变化，已复用上一快照的解密文件",
        "decrypt.db_completed": "单个微信数据库解密完成",
        "decrypt.db_failed": "单个微信数据库解密失败",
        "decrypt.refresh_completed": "微信数据库刷新完成",
        "decrypt.refresh_failed": "微信数据库刷新失败",
        "decrypt.copy_cleanup_failed": "清理临时加密副本失败",
        "export.full_started": "开始执行全量导出",
        "export.full_conversations_loaded": "已加载会话列表，准备导出消息",
        "export.full_progress": "全量导出进行中",
        "export.attachments_processing": "开始处理附件导出",
        "export.attachments_processed": "附件导出处理完成",
        "export.full_completed": "全量导出完成",
        "export.incremental_started": "开始执行增量导出",
        "export.incremental_messages_loaded": "已加载增量消息",
        "export.incremental_skipped": "本次增量导出跳过，没有发现新消息",
        "export.incremental_completed": "增量导出完成",
        "export.selected_started": "开始导出指定会话",
        "export.selected_completed": "指定会话导出完成",
        "mcp.starting": "正在启动微信聊天记录 MCP 服务",
        "parser.db_inspect_failed": "读取解密快照信息失败",
        "parser.db_not_usable": "解密快照当前不可用",
        "scheduler.state_load_failed": "读取同步状态文件失败",
        "scheduler.state_save_failed": "保存同步状态文件失败",
    }
    return templates.get(event, event)


def _format_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple, dict)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    text = str(value).replace("\r", "\\r").replace("\n", "\\n")
    if any(ch.isspace() for ch in text) or "|" in text or "=" in text:
        return json.dumps(text, ensure_ascii=False)
    return text


def format_fields(**fields):
    parts = []
    for key, value in fields.items():
        if value is None:
            continue
        parts.append(f"{key}={_format_value(value)}")
    return " ".join(parts)


def log_event(logger, level, event, **fields):
    message = _event_text(event, fields)
    details = format_fields(event=event, **fields)
    if details:
        message = f"{message} | {details}"
    getattr(logger, level)(message)
