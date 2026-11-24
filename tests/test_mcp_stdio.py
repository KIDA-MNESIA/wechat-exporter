import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from tests.fixtures import ALICE_WXID, GROUP_CID, create_synthetic_snapshot


class MCPStdioTests(unittest.IsolatedAsyncioTestCase):
    async def test_mcp_stdio_tools_end_to_end(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            snap_src = Path(directory) / "plain"
            app_data = Path(directory) / "app_data"
            create_synthetic_snapshot(snap_src)
            params = StdioServerParameters(
                command=sys.executable,
                args=[str(root / "tests" / "serve_fixture.py"), str(snap_src), str(app_data)],
                cwd=str(root),
                env={**os.environ, "PYTHONIOENCODING": "utf-8", "FASTMCP_CHECK_FOR_UPDATES": "off"},
            )
            with open(os.devnull, "w") as errors:
                async with stdio_client(params, errlog=errors) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()

                        async def call(name, **arguments):
                            response = (await session.call_tool(name, arguments)).model_dump(by_alias=True)
                            self.assertFalse(response.get("isError"), response)
                            return response.get("structuredContent") or json.loads(
                                "".join(item["text"] for item in response["content"] if item["type"] == "text")
                            )

                        tools = (await session.list_tools()).model_dump(by_alias=True)["tools"]
                        tool_names = {t["name"] for t in tools}
                        self.assertTrue({
                            "get_database_status",
                            "list_conversations",
                            "get_messages",
                            "get_forwarded_messages",
                            "search_messages",
                            "get_stats",
                            "refresh_database",
                            "get_job_status",
                            "trigger_sync",
                            "export_conversations",
                            "read_attachment",
                        } <= tool_names)

                        status = await call("get_database_status")
                        self.assertTrue(status["ready"])
                        sid = status["snapshot_id"]

                        convs = await call("list_conversations", limit=10, snapshot_id=sid)
                        self.assertEqual(convs["total"], 3)

                        msgs = await call("get_messages", conversation_id=ALICE_WXID, limit=10, snapshot_id=sid)
                        self.assertEqual(msgs["total"], 6)

                        fwd = await call("get_forwarded_messages", conversation_id=GROUP_CID, message_id=2, snapshot_id=sid)
                        self.assertEqual(fwd["total"], 3)
                        self.assertEqual(fwd["parse_status"], "complete")

                        search = await call("search_messages", keyword="needle", snapshot_id=sid)
                        self.assertEqual(search["total"], 3)

                        stats = await call("get_stats", snapshot_id=sid)
                        self.assertEqual(stats["total_messages"], 9)

                        # Invalid params return tool error
                        bad = (await session.call_tool("get_messages", {"conversation_id": ALICE_WXID, "limit": 0})).model_dump(by_alias=True)
                        self.assertTrue(bad.get("isError"))


if __name__ == "__main__":
    unittest.main()
