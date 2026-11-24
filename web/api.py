import io as _io
import logging
import os
import shutil
import stat
import subprocess
import sys
import zipfile
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

import config
from attachment import get_or_decrypt_cached_image
from log_utils import log_event
from parser import (
    DatabaseNotReadyError,
    get_connection,
    get_conversation_stats,
    get_conversations,
    get_database_status,
    get_forwarded_messages,
    get_messages,
    search_messages_page,
)
from scheduler import (
    get_sync_state,
    setup_scheduler,
    start_export,
    start_refresh,
    start_sync,
)

logger = logging.getLogger(__name__)

app = FastAPI(title="微信聊天记录导出", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_scheduler = None


def _remove_readonly(func, path, exc_info):
    exc = exc_info[1]
    if not isinstance(exc, PermissionError):
        raise exc
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        raise exc


def _query_db(callback, snapshot_id=None):
    try:
        ctx = get_connection(snapshot_id=snapshot_id)
    except DatabaseNotReadyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        from snapshots import connection_metadata

        result = callback(ctx)
        if isinstance(result, dict):
            result.update(connection_metadata(ctx))
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        ctx.close()


@app.on_event("startup")
async def startup():
    global _scheduler
    _scheduler = setup_scheduler(app)
    _scheduler.start()
    log_event(logger, "info", "api.startup_completed")


@app.on_event("shutdown")
async def shutdown():
    global _scheduler
    if _scheduler:
        _scheduler.shutdown()
        log_event(logger, "info", "api.shutdown_completed")


# --- Static files ---

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(html_path):
        return FileResponse(html_path)
    return HTMLResponse("<h1>WeChat Exporter</h1><p>Frontend not found</p>")


if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# --- API Routes ---

def _job_response(result):
    if result["status"] == "already_running":
        raise HTTPException(status_code=409, detail="已有刷新或导出任务正在运行，请等待完成后重试。")
    if result["status"] == "failed":
        raise HTTPException(status_code=503, detail=result.get("error") or "无法启动后台任务")
    return result


@app.get("/api/config")
async def api_config():
    """Return public configuration for the frontend."""
    return {
        "user_uid": config.USER_WXID,
        "user_wxid": config.USER_WXID,
        "user_nickname": config.USER_NICKNAME,
        "wechat_version": config.WECHAT_VERSION,
    }


@app.get("/api/conversations")
async def api_conversations(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    keyword: str = Query(None),
    snapshot_id: str = Query(None),
):
    return _query_db(
        lambda ctx: get_conversations(ctx, limit=limit, offset=offset, keyword=keyword),
        snapshot_id=snapshot_id,
    )


@app.get("/api/conversations/{cid}/messages")
async def api_messages(
    cid: str,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    since: int = Query(None, description="Since timestamp (ms)"),
    until: int = Query(None, description="Until timestamp (ms)"),
    snapshot_id: str = Query(None),
):
    return _query_db(
        lambda ctx: get_messages(
            ctx, cid, limit=limit, offset=offset, since_time=since, until_time=until
        ),
        snapshot_id=snapshot_id,
    )


@app.get("/api/conversations/{cid}/messages/{mid}/forwarded")
async def api_forwarded_messages(
    cid: str,
    mid: str,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    snapshot_id: str = Query(None),
):
    return _query_db(
        lambda ctx: get_forwarded_messages(ctx, cid, mid, limit=limit, offset=offset),
        snapshot_id=snapshot_id,
    )


@app.get("/api/search")
async def api_search(
    q: str = Query(..., min_length=1),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    mode: Literal["text", "raw"] = "text",
    snapshot_id: str = Query(None),
):
    return _query_db(
        lambda ctx: search_messages_page(ctx, q, limit=limit, offset=offset, mode=mode),
        snapshot_id=snapshot_id,
    )


@app.get("/api/stats")
async def api_stats(snapshot_id: str = Query(None)):
    return _query_db(get_conversation_stats, snapshot_id=snapshot_id)


@app.get("/api/sync/status")
async def api_sync_status():
    state = get_sync_state()
    db_status = get_database_status()
    state["database_ready"] = db_status["ready"]
    state["database_error"] = db_status["error"]
    state["database"] = db_status
    state["runtime"] = config.get_runtime_diagnostics()
    return state


@app.post("/api/sync/trigger")
async def api_sync_trigger(full: bool = Query(False)):
    result = start_sync(full=full)
    return {**_job_response(result), "full": full}


@app.post("/api/database/refresh")
async def api_refresh_database():
    return _job_response(start_refresh())


@app.get("/api/jobs/{job_id}")
async def api_job_status(job_id: str):
    from jobs import JobNotFoundError, get_job_status

    try:
        return get_job_status(job_id)
    except JobNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/export/selected")
async def api_export_selected(body: dict):
    cids = body.get("cids", [])
    since_time = body.get("since_time")
    until_time = body.get("until_time")
    if not cids:
        raise HTTPException(status_code=400, detail="No conversations selected")
    result = start_export(
        cids,
        since_time=since_time,
        until_time=until_time,
        snapshot_id=body.get("snapshot_id"),
    )
    return {**_job_response(result), "selected_count": len(cids)}


@app.get("/api/media/image/{md5}")
async def api_media_image(
    md5: str,
    cid: str = Query(""),
    snapshot_id: str = Query(None),
):
    """Decrypt (on demand) and serve a WeChat image by its MD5."""
    ctx = None
    try:
        try:
            ctx = get_connection(snapshot_id=snapshot_id)
        except DatabaseNotReadyError:
            ctx = None
        img_path = get_or_decrypt_cached_image(md5, cid=cid, ctx=ctx)
        if img_path is None or not img_path.is_file():
            raise HTTPException(status_code=404, detail="Image not found or unable to decrypt")
        return FileResponse(str(img_path))
    finally:
        if ctx is not None:
            ctx.close()


@app.get("/api/local-file")
async def api_local_file(path: str = Query(..., min_length=1)):
    """Serve a local downloaded file from WeChat's data or export directory."""
    try:
        full_path = os.path.normpath(path)
        if full_path.startswith("\\\\"):
            raise HTTPException(status_code=403, detail="UNC paths not allowed")

        allowed_roots = [
            os.path.normpath(config.WECHAT_DATA_DIR),
            os.path.normpath(config.EXPORT_DIR),
            os.path.normpath(config.MEDIA_CACHE_DIR),
        ]
        if not any(full_path == r or full_path.startswith(r + os.sep) for r in allowed_roots):
            raise HTTPException(status_code=403, detail="Access denied")

        ext = os.path.splitext(full_path)[1].lower()
        allowed_exts = {
            ".xlsx", ".xls", ".docx", ".doc", ".pptx", ".ppt", ".pdf",
            ".txt", ".csv", ".json", ".xml", ".html", ".htm", ".md",
            ".zip", ".rar", ".7z", ".gz", ".tar",
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp",
            ".mp4", ".mp3", ".wav", ".avi", ".m4a",
        }
        if ext not in allowed_exts:
            raise HTTPException(status_code=403, detail=f"File type '{ext}' not allowed")

        if not os.path.exists(full_path):
            raise HTTPException(status_code=404, detail="File not found")

        return FileResponse(full_path, filename=os.path.basename(full_path))
    except HTTPException:
        raise
    except Exception as exc:
        log_event(logger, "error", "api.local_file_failed", path=path, error=exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/exports/{name}/download")
async def api_export_download(name: str):
    export_path = os.path.normpath(os.path.join(config.EXPORT_DIR, name))
    if not export_path.startswith(os.path.normpath(config.EXPORT_DIR)):
        raise HTTPException(status_code=403, detail="Access denied")
    if not os.path.exists(export_path):
        raise HTTPException(status_code=404, detail="Export not found")

    if os.path.isdir(export_path):
        zip_filename = f"{name}.zip"
        buf = _io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(export_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, config.EXPORT_DIR)
                    zf.write(file_path, arcname)
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename={zip_filename}"},
        )

    return FileResponse(
        export_path,
        media_type="application/json",
        filename=os.path.basename(export_path),
    )


@app.post("/api/exports/{name}/open-folder")
async def api_export_open_folder(name: str):
    export_path = os.path.normpath(os.path.join(config.EXPORT_DIR, name))
    if not export_path.startswith(os.path.normpath(config.EXPORT_DIR)):
        raise HTTPException(status_code=403, detail="Access denied")
    if not os.path.isdir(export_path):
        raise HTTPException(status_code=404, detail="Export directory not found")

    try:
        if sys.platform == "win32":
            os.startfile(export_path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", export_path])
        else:
            subprocess.Popen(["xdg-open", export_path])
    except Exception as exc:
        log_event(logger, "error", "api.open_export_folder_failed", path=export_path, error=exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {"status": "opened", "path": export_path}


@app.delete("/api/exports/{name}")
async def api_delete_export(name: str):
    export_path = os.path.normpath(os.path.join(config.EXPORT_DIR, name))
    if not export_path.startswith(os.path.normpath(config.EXPORT_DIR)):
        raise HTTPException(status_code=403, detail="Access denied")
    if not os.path.exists(export_path):
        raise HTTPException(status_code=404, detail="Export not found")

    try:
        if os.path.isdir(export_path):
            shutil.rmtree(export_path, onerror=_remove_readonly)
        else:
            os.chmod(export_path, stat.S_IWRITE)
            os.remove(export_path)
    except Exception as exc:
        log_event(logger, "error", "api.delete_export_failed", path=export_path, error=exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {"status": "deleted", "name": name}


@app.get("/api/exports/{filename}")
async def api_export_file(filename: str):
    filepath = os.path.normpath(os.path.join(config.EXPORT_DIR, filename))
    if not filepath.startswith(os.path.normpath(config.EXPORT_DIR)):
        raise HTTPException(status_code=403, detail="Access denied")
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(filepath, media_type="application/json", filename=filename)


@app.get("/api/exports")
async def api_list_exports():
    exports = []
    if os.path.isdir(config.EXPORT_DIR):
        for f in os.listdir(config.EXPORT_DIR):
            fp = os.path.join(config.EXPORT_DIR, f)
            if f == "latest.json":
                continue
            if os.path.isdir(fp):
                json_path = os.path.join(fp, "export.json")
                if os.path.exists(json_path):
                    exports.append({
                        "filename": f,
                        "type": "directory",
                        "size": os.path.getsize(json_path),
                        "modified": os.path.getmtime(fp),
                        "download_url": f"/api/exports/{f}/download",
                    })
            elif f.endswith(".json"):
                exports.append({
                    "filename": f,
                    "type": "file",
                    "size": os.path.getsize(fp),
                    "modified": os.path.getmtime(fp),
                    "download_url": f"/api/exports/{f}",
                })
    exports.sort(key=lambda item: item["modified"], reverse=True)
    return {"exports": exports}
