# 微信聊天记录导出工具 (WeChat Chat Exporter)

从微信 4.x 桌面客户端的本地加密 SQLite 数据库中提取并导出聊天记录，提供 Web 界面浏览、全文搜索、AI 友好 JSON + 附件打包导出，以及标准 MCP Server 接口。

架构设计参照 `dingtalk-exporter`，底层微信 4.x 数据库检测、密钥提取、SQLCipher 4.0 + WAL 合并解密、图片 `.dat` 解密及消息解析参照 `WeChatDataAnalysis`。

> **声明**：本工具仅供个人数据备份与本地离线分析使用，请妥善保管本地解密数据与密钥缓存。

## 功能特性

- **无重启自动提取密钥（Windows 微信 4.x）** — 自动扫描 `Weixin.dll` 辅助密钥与运行中 `Weixin.exe` 内存，并通过首页 HMAC-SHA512 验真，结果缓存于 `data/keys.json`
- **SQLCipher 4.0 + WAL 合并解密** — 不修改微信原始文件，自动读取并合并已提交 `-wal` 帧，按文件签名增量复用未变化的分库，多线程并发解密
- **固定不可变快照** — 原子发布的只读多库快照（`data/decrypted/snapshots/s-*`），校验失败或时间回退时保留原有可用快照
- **本地图片 `.dat` / `wxgf` 解密** — 通过本地 `kvcomm` 与 V2 `_t.dat` 模板自动推导并验真图片 XOR/AES 密钥，并调用本机微信内置 `VoipEngine.dll`（或 `ffmpeg` 回退）解码 `wxgf` 图片，支持 Web 预览与导出为 JPG/PNG/GIF/WebP
- **丰富消息类型支持** — 文本、图片、语音（含微信原生语音转文字）、视频、动画表情、位置、名片、通话、引用回复、文件、链接/公众号文章/小程序/视频号、转账、红包、群公告、拍一拍、系统消息、合并转发聊天记录
- **合并转发 XML 解码** — 递归解析 `<recorditem>` / `<recordinfo>` 嵌套子消息，带深度与数量保护、先序 `path`/`parent_path` 与 `parse_status`
- **可读正文索引检索** — 按快照版本生成可丢弃 SQLite 正文索引，支持检索父消息、引用、链接标题、附件名及合并转发子消息
- **Web 界面 + MCP Server** — 提供 FastAPI Web 应用（http://localhost:8090）和 FastMCP（stdio / streamable HTTP）工具，与 `dingtalk-exporter` 保持一致的接口语义

## 快速开始

### 环境要求

- Python 3.10+（推荐 Python 3.12）
- Windows 微信 4.x 桌面客户端（`Weixin.exe`）已登录（首次提取密钥需保持运行状态；也可通过环境变量 `WECHAT_DB_KEY` 手动指定 64 位十六进制密钥）

### 安装与运行

```bash
pip install -r requirements.txt

# 首次刷新解密快照（CLI）
python decrypt.py

# 启动 Web 界面 (http://localhost:8090)
python main.py
```

### 环境变量覆盖（可选）

自动检测失败或有多账号时，可通过环境变量覆盖：

```bash
set WECHAT_DATA_DIR=C:\Users\<用户名>\Documents\xwechat_files\<wxid目录>
set WECHAT_ACCOUNT=<wxid>
set WECHAT_DB_KEY=<64位十六进制密钥>
set WECHAT_INSTALL_DIR=C:\Program Files\Tencent\Weixin
set WEB_PORT=8090
```

## MCP Server（AI 工具接入）

### stdio 模式（推荐）

```json
{
  "mcpServers": {
    "wechat-exporter": {
      "command": "C:\\path\\to\\wechat-exporter\\.venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\wechat-exporter\\mcp_server.py"]
    }
  }
}
```

### Streamable HTTP 模式

```bash
python mcp_server.py --http --host 127.0.0.1 --port 8091
```

### 可用 MCP 工具

| 工具 | 说明 |
|------|------|
| `get_database_status` | 检查解密快照是否就绪 |
| `list_conversations` | 会话列表，支持按名称/备注/昵称/微信号/wxid 过滤与分页 |
| `get_messages` | 读取指定会话消息，支持毫秒时间范围、固定快照和分页 |
| `get_forwarded_messages` | 读取合并转发子消息及嵌套位置 |
| `search_messages` | 全文检索可读正文（`mode=text`）或原始内容（`mode=raw`） |
| `get_stats` | 会话/消息/联系人统计 |
| `get_sync_status` | 同步状态、上次刷新/导出路径与数据库状态 |
| `refresh_database` | 后台刷新解密快照，返回 `job_id` |
| `get_job_status` | 查询后台任务状态、结果和错误 |
| `trigger_sync` | 刷新并执行全量/增量导出，返回 `job_id` |
| `export_conversations` | 导出指定会话为自包含 JSON + 附件目录 |
| `read_attachment` | 读取本地文本类附件内容 |

## 导出格式

```
export_20261124_014500_a1b2c3d4/
├── export.json            # 结构化会话与消息，每条消息含 AI 友好的 content 字段
├── images/                # 解密后的图片附件
└── files/                 # 导出的本地文件附件
```

## 运行测试

```bash
python -m unittest discover -s tests -v
```
