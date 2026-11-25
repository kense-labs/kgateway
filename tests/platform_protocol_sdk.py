"""Network conformance checks using the pinned Python protocol SDKs."""

import asyncio

import httpx
from a2a.client.transports.jsonrpc import JsonRpcTransport
from a2a.types.a2a_pb2 import AgentCard, Message, Part, Role, SendMessageRequest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


def check_mcp(url, key, upstream_session):
    async def run():
        async with (
            httpx.AsyncClient(
                headers={"Authorization": "Bearer " + key}, trust_env=False, timeout=10
            ) as http,
            streamable_http_client(url, http_client=http) as (read, write, session_id),
            ClientSession(read, write) as client,
        ):
            initialized = await client.initialize()
            assert initialized.protocolVersion == "2025-11-25"
            assert session_id() and session_id() != upstream_session
            tools = await client.list_tools()
            assert [tool.name for tool in tools.tools] == ["lookup"]
            result = await client.call_tool("lookup", {"id": "fixture"})
            assert [item.text for item in result.content] == ["directory lookup"]

    asyncio.run(run())


def check_a2a(url, key):
    async def run():
        async with httpx.AsyncClient(
            headers={"Authorization": "Bearer " + key}, trust_env=False, timeout=10
        ) as http:
            client = JsonRpcTransport(
                http, AgentCard(name="Fixture"), url, is_shared_httpx=True
            )
            request = SendMessageRequest(
                message=Message(
                    message_id="sdk-request",
                    role=Role.ROLE_USER,
                    parts=[Part(text="hello")],
                )
            )
            response = await client.send_message(request)
            assert response.HasField("message") and [
                part.text for part in response.message.parts
            ] == ["ok"]

    asyncio.run(run())
