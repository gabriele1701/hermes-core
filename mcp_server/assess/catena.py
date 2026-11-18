"""La catena vera: il server lanciato come lo lancia Hermes, e un client MCP.

Le prove che passano di qui invocano **solo i canary** di hermes-assess. Il
server scrive le proprie righe nel log d'audit come per qualunque
invocazione: hermes-assess non scrive righe proprie, perché un client che si
annota da solo nel log che sta verificando sarebbe un testimone di parte.
"""

from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_server.assess.contesto import Contesto
from mcp_server.contracts import AgentResult

#: Tetto su un'intera sessione: avvio del server, invocazioni, chiusura.
TIMEOUT_SESSIONE = 120


@dataclass(frozen=True, slots=True)
class Invocazione:
    tool_id: str
    target: str | None
    result: AgentResult
    output: dict[str, Any] | None

    @property
    def stdout(self) -> str:
        return str((self.output or {}).get("stdout", ""))


class CatenaError(Exception):
    """La catena non ha risposto in modo interpretabile."""


@asynccontextmanager
async def sessione(ctx: Contesto) -> AsyncIterator[ClientSession]:
    argv = ctx.comando_server()
    parametri = StdioServerParameters(
        command=argv[0], args=argv[1:], cwd=str(ctx.repo)
    )
    with anyio.fail_after(TIMEOUT_SESSIONE):
        async with stdio_client(parametri) as (read, write):
            async with ClientSession(read, write) as s:
                await s.initialize()
                yield s


async def invoca(
    s: ClientSession, tool_id: str, target: str | None = None
) -> Invocazione:
    esito = await s.call_tool(
        "invoke_tool",
        {"tool_id": tool_id, "target": target, "correlation_id": str(uuid.uuid4())},
    )
    dati = esito.structured_content
    if not isinstance(dati, dict) or "result" not in dati:
        raise CatenaError(f"risposta senza 'result' invocando {tool_id}")
    output = dati.get("output")
    return Invocazione(
        tool_id=tool_id,
        target=target,
        result=AgentResult.model_validate(dati["result"]),
        output=output if isinstance(output, dict) else None,
    )


def righe_di_audit(log_path: Path, correlation_id: uuid.UUID) -> list[dict[str, Any]]:
    """Le righe del log con quel ``correlation_id``, nell'ordine del file.

    Una riga non JSON si salta: AS-14 è la prova che guarda la forma del log,
    questa cerca una catena.
    """
    cid = str(correlation_id)
    trovate = []
    with log_path.open(encoding="utf-8", errors="replace") as fh:
        for riga in fh:
            if cid not in riga:
                continue
            try:
                dati = json.loads(riga)
            except json.JSONDecodeError:
                continue
            if isinstance(dati, dict) and dati.get("correlation_id") == cid:
                trovate.append(dati)
    return trovate


__all__ = ["CatenaError", "Invocazione", "invoca", "righe_di_audit", "sessione"]
