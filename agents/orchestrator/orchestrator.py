"""Orchestratore minimo.

Invoca **un** agente e ne riceve un risultato strutturato. Non coordina più
agenti, non tiene stato, non decide strategie: quello è lavoro di milestone
successive. Qui serve a chiudere la catena e a dimostrare che le parti
costruite finora si parlano.

Come parla con un agente
------------------------

Ogni agente è un processo server MCP con la propria configurazione, lanciato
su stdio. L'orchestratore è il suo **client**: lo avvia, lo interroga, lo
spegne. Non importa il codice dell'agente e non condivide memoria con lui —
l'unica superficie fra i due è il protocollo.

Questo rende l'isolamento una conseguenza della struttura e non una
disciplina da mantenere: l'orchestratore non *può* invocare un tool di un
agente diverso da quello a cui è connesso, perché non ha un canale verso gli
altri. E quando l'agente di pentest girerà in un container, cambierà solo il
comando con cui viene lanciato.

Il risultato viene validato, non creduto
----------------------------------------

La risposta dell'agente attraversa un confine di processo, quindi è input.
Viene validata contro :class:`~mcp_server.contracts.AgentResult` prima di
essere usata: se un agente restituisse qualcosa di non conforme —
difettoso, aggiornato male o compromesso — l'orchestratore se ne accorge lì,
invece di propagare una struttura inattesa al resto della catena.

Una sola catena, due processi
-----------------------------

L'orchestratore genera il ``correlation_id`` e lo passa all'agente, così le
righe che scrivono i due processi finiscono sotto un'unica catena nello
stesso file di log. È ciò che rende il log append-only del passo 2 utile per
davvero: due scrittori indipendenti, nessun lock, nessuna riga spezzata.
"""

from __future__ import annotations

import sys
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import ValidationError

from mcp_server.audit import AuditLog, LogAction
from mcp_server.contracts import AgentResult, AgentStatus, CallOutcome, OwnerAgent


class OrchestratorError(Exception):
    """Errore nel dialogo con un agente."""


class MalformedAgentResult(OrchestratorError):
    """L'agente ha restituito qualcosa che non è un AgentResult."""


@dataclass(frozen=True, slots=True)
class AgentEndpoint:
    """Come raggiungere un agente: il comando che lo lancia.

    Oggi è un processo Python locale. Quando l'agente di pentest girerà
    isolato, qui cambierà il comando — ``docker run …`` — e nient'altro.
    """

    agent: OwnerAgent
    config_path: Path
    command: str = sys.executable
    args: tuple[str, ...] = ("-m", "mcp_server.server")
    cwd: Path | None = None

    def parametri_stdio(self) -> StdioServerParameters:
        return StdioServerParameters(
            command=self.command,
            args=[*self.args, str(self.config_path)],
            cwd=str(self.cwd) if self.cwd else None,
        )


@dataclass(frozen=True, slots=True)
class Invocation:
    """Esito completo di un'invocazione: risultato validato e output grezzo."""

    result: AgentResult
    output: dict[str, Any] | None = None

    @property
    def riuscita(self) -> bool:
        return self.result.status is AgentStatus.OK

    @property
    def in_attesa_di_conferma(self) -> bool:
        return self.result.status is AgentStatus.NEEDS_CONFIRMATION

    @property
    def stdout(self) -> str:
        return (self.output or {}).get("stdout", "")


class Orchestrator:
    """Invoca un agente e ne riceve un risultato strutturato.

    Parameters
    ----------
    audit:
        Log su cui l'orchestratore registra le proprie righe. È lo stesso
        file su cui scrive l'agente: due processi, un solo log.
    """

    def __init__(self, audit: AuditLog) -> None:
        self._audit = audit

    @asynccontextmanager
    async def connetti(self, endpoint: AgentEndpoint) -> AsyncIterator[ClientSession]:
        """Avvia l'agente e apre una sessione MCP, chiudendola all'uscita."""
        async with stdio_client(endpoint.parametri_stdio()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session

    async def elenca_tool(self, endpoint: AgentEndpoint) -> list[dict[str, Any]]:
        """Chiede all'agente quali tool espone."""
        async with self.connetti(endpoint) as session:
            esito = await session.call_tool("list_available_tools", {})
        dati = esito.structured_content or {}
        return list(dati.get("tools", []))

    async def invoca(
        self,
        endpoint: AgentEndpoint,
        tool_id: str,
        *,
        target: str | None = None,
        correlation_id: uuid.UUID | None = None,
    ) -> Invocation:
        """Invoca un tool di un agente e restituisce il risultato validato."""
        cid = correlation_id or uuid.uuid4()

        self._audit.log(
            correlation_id=cid,
            action=LogAction.AGENT_INVOKED,
            outcome=CallOutcome.OK,
            agent=OwnerAgent.ORCHESTRATOR,
            tool_id=tool_id,
            target=target,
            detail=f"orchestratore -> agente '{endpoint.agent}'",
        )

        async with self.connetti(endpoint) as session:
            esito = await session.call_tool(
                "invoke_tool",
                {
                    "tool_id": tool_id,
                    "target": target,
                    "correlation_id": str(cid),
                },
            )

        invocazione = self._valida(esito.structured_content, cid, endpoint)

        self._audit.log(
            correlation_id=cid,
            action=LogAction.AGENT_RESULT,
            outcome=_esito(invocazione.result.status),
            agent=OwnerAgent.ORCHESTRATOR,
            tool_id=tool_id,
            target=target,
            detail=(
                f"risultato da '{endpoint.agent}': {invocazione.result.status} "
                f"— {invocazione.result.summary}"
            ),
        )
        return invocazione

    # -- validazione --------------------------------------------------------- #

    def _valida(
        self,
        payload: dict[str, Any] | None,
        cid: uuid.UUID,
        endpoint: AgentEndpoint,
    ) -> Invocation:
        """Valida la risposta dell'agente contro il contratto.

        Il fallimento viene registrato prima di essere sollevato: un agente
        che risponde fuori contratto è un evento che l'audit deve conservare,
        non solo un'eccezione che risale.
        """
        if not isinstance(payload, dict) or "result" not in payload:
            self._registra_malformato(cid, endpoint, "risposta priva del campo 'result'")
            raise MalformedAgentResult(
                f"risposta non conforme da '{endpoint.agent}': manca 'result'"
            )

        try:
            risultato = AgentResult.model_validate(payload["result"])
        except ValidationError as err:
            self._registra_malformato(cid, endpoint, f"AgentResult non valido: {err}")
            raise MalformedAgentResult(
                f"risultato non conforme da '{endpoint.agent}': {err}"
            ) from err

        if risultato.agent is not endpoint.agent:
            self._registra_malformato(
                cid,
                endpoint,
                f"l'agente si è dichiarato '{risultato.agent}' invece di "
                f"'{endpoint.agent}'",
            )
            raise MalformedAgentResult(
                f"identità incoerente: atteso '{endpoint.agent}', "
                f"ricevuto '{risultato.agent}'"
            )

        output = payload.get("output")
        return Invocation(result=risultato, output=output if isinstance(output, dict) else None)

    def _registra_malformato(
        self, cid: uuid.UUID, endpoint: AgentEndpoint, motivo: str
    ) -> None:
        self._audit.log(
            correlation_id=cid,
            action=LogAction.AGENT_RESULT,
            outcome=CallOutcome.ERROR,
            agent=OwnerAgent.ORCHESTRATOR,
            detail=f"risposta non conforme da '{endpoint.agent}': {motivo}",
        )


def _esito(status: AgentStatus) -> CallOutcome:
    return {
        AgentStatus.OK: CallOutcome.OK,
        AgentStatus.ERROR: CallOutcome.ERROR,
        AgentStatus.NEEDS_CONFIRMATION: CallOutcome.PENDING,
    }[status]


__all__ = [
    "AgentEndpoint",
    "Invocation",
    "MalformedAgentResult",
    "Orchestrator",
    "OrchestratorError",
]
