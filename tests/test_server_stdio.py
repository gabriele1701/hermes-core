"""Test end-to-end del trasporto stdio (M0 passo 6b).

È la definition of done del passo: il server **parte come processo separato**
e un client MCP reale ne elenca e invoca i tool. I test in-process verificano
la logica, questo verifica che il trasporto funzioni — e sono due cose
diverse, perché un server che non parla stdio correttamente passerebbe tutti
gli altri test.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_server.executor import sha256_file

SCRIPT = "agents/echo_agent/run.py"


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture()
def config_pronta(tmp_path: Path) -> Path:
    """Repo minimo con script, config e log, pronto per essere servito."""
    (tmp_path / "agents" / "echo_agent").mkdir(parents=True)
    script = tmp_path / SCRIPT
    script.write_text("print('echo ok')\n", encoding="utf-8")
    (tmp_path / "config").mkdir()

    percorso = tmp_path / "config" / "hermes.toml"
    percorso.write_text(
        textwrap.dedent(f"""\
            [server]
            agent = "echo_dummy"
            repo_root = ".."
            log_path = "../logs/audit.jsonl"
            container_available = false

            [vault]
            backend = "stub"
            stub_secrets = ["ssh/lab-kali"]

            [[tool]]
            tool_id = "echo.ping"
            owner_agent = "echo_dummy"
            default_tier = "verde"
            personal_data = false
            requires_container = false
            exec_path = "{SCRIPT}"
            exec_sha256 = "{sha256_file(script)}"
            description = "Agente dummy."

            [[tool]]
            tool_id = "echo.rosso"
            owner_agent = "echo_dummy"
            default_tier = "rosso"
            personal_data = false
            requires_container = false
            exec_path = "{SCRIPT}"
            exec_sha256 = "{sha256_file(script)}"
            description = "Dummy a tier rosso, per verificare la sospensione."
            """),
        encoding="utf-8",
    )
    return percorso


def _parametri(config: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_server.server", str(config)],
        cwd=str(Path.cwd()),
    )


@pytest.mark.slow
@pytest.mark.anyio
async def test_client_reale_elenca_i_tool(config_pronta: Path):
    """Il server parte su stdio e un client MCP ne elenca i tool."""
    async with stdio_client(_parametri(config_pronta)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools

    nomi = {t.name for t in tools}
    assert nomi == {
        "list_available_tools",
        "describe_tool",
        "invoke_tool",
        "raise_tool_tier",
    }


@pytest.mark.slow
@pytest.mark.anyio
async def test_client_reale_vede_i_tool_registrati(config_pronta: Path):
    async with stdio_client(_parametri(config_pronta)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            esito = await session.call_tool("list_available_tools", {})

    dati = esito.structured_content
    assert dati["agent"] == "echo_dummy"
    assert dati["vault_is_stub"] is True
    assert {t["tool_id"] for t in dati["tools"]} == {"echo.ping", "echo.rosso"}


@pytest.mark.slow
@pytest.mark.anyio
async def test_client_reale_invoca_un_tool(config_pronta: Path):
    async with stdio_client(_parametri(config_pronta)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            esito = await session.call_tool("invoke_tool", {"tool_id": "echo.ping"})

    dati = esito.structured_content
    assert dati["result"]["status"] == "ok"
    assert dati["output"]["stdout"].strip() == "echo ok"
    assert dati["result"]["tool_calls"][0]["authorized_by"] == "policy"


@pytest.mark.slow
@pytest.mark.anyio
async def test_client_reale_non_puo_eseguire_un_rosso(config_pronta: Path):
    """Fail-closed attraverso il trasporto reale, non solo in-process."""
    async with stdio_client(_parametri(config_pronta)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            esito = await session.call_tool("invoke_tool", {"tool_id": "echo.rosso"})

    dati = esito.structured_content
    assert dati["result"]["status"] == "needs_confirmation"
    assert dati["result"]["tool_calls"][0]["outcome"] == "pending"
    assert dati["output"] is None


@pytest.mark.slow
@pytest.mark.anyio
async def test_client_reale_non_puo_declassare(config_pronta: Path):
    async with stdio_client(_parametri(config_pronta)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            alzato = await session.call_tool(
                "raise_tool_tier", {"tool_id": "echo.ping", "tier": "rosso"}
            )
            abbassato = await session.call_tool(
                "raise_tool_tier", {"tool_id": "echo.ping", "tier": "verde"}
            )

    assert alzato.structured_content["effective_tier"] == "rosso"
    assert abbassato.structured_content["ok"] is False


@pytest.mark.slow
@pytest.mark.anyio
async def test_log_scritto_dal_processo_server(config_pronta: Path):
    """La catena del processo server finisce nel log su disco."""
    async with stdio_client(_parametri(config_pronta)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("invoke_tool", {"tool_id": "echo.ping"})

    log = (config_pronta.parent.parent / "logs" / "audit.jsonl").read_text(
        encoding="utf-8"
    )
    assert "tool_registered" in log
    assert "agent_invoked" in log
    assert "agent_result" in log
