"""Log d'audit JSONL di hermes-core.

Un evento per riga, JSON valido, append-only. È la traccia con cui si
ricostruisce a posteriori cosa è stato eseguito, su cosa, con quale tier
effettivo e su autorizzazione di chi.

Il modulo si chiama ``audit`` e non ``logging`` deliberatamente. Il server è
un entrypoint eseguibile: lanciarlo come ``python mcp_server/server.py`` mette
``mcp_server/`` in testa a ``sys.path``, e da quel momento qualunque
``import logging`` — nostro o di una dipendenza caricata dopo — risolverebbe
sul file locale invece che sulla stdlib. È un guasto silenzioso e sgradevole
da diagnosticare, evitabile al costo di un nome diverso.

Scelte difensive
----------------

* **Append-only.** Il file si apre sempre in append (``O_APPEND``): su POSIX
  una singola ``write`` di una riga corta è atomica rispetto ad altri
  appender, quindi scritture concorrenti non si interlacciano a metà riga. Il
  writer non espone alcuna operazione di modifica o troncamento.
* **Permessi 0600, directory 0700.** Il log contiene hostname, target e
  nomi di tool: è materiale che non deve essere leggibile da altri utenti
  della macchina.
* **Nessun valore di credenziale.** Il record non ha un campo in cui un
  segreto possa entrare "di passaggio": il vault registra il *nome* del
  segreto e l'esito dell'accesso, mai il valore. ``extra="forbid"`` fa
  fallire qualunque tentativo di aggiungere campi non dichiarati.
* **Una riga = un oggetto JSON.** ``json.dumps`` escapa newline e caratteri
  di controllo, quindi un ``detail`` multilinea non può spezzare il formato
  né iniettare una riga di log falsa.

Limiti noti
-----------

Il log è append-only a livello di API, **non tamper-evident**: chi ha accesso
in scrittura al file può riscriverlo a posteriori. La difesa non sta nel
formato, sta fuori:

* ``chattr +a`` sul file (richiede root per essere messo o tolto) impedisce
  troncamenti e riscritture a qualunque processo non privilegiato, incluso
  questo codice — che non deve girare da root;
* la spedizione a un collector esterno: una copia già fuori dall'host non è
  raggiungibile da una manomissione locale.

L'hash-chaining dei record è stato **deliberatamente escluso**. Imporrebbe di
serializzare le scritture (ogni record deve conoscere l'hash del precedente),
perdendo il writer stateless e concorrente descritto sopra; e senza un
ancoraggio esterno dell'hash di coda non sposta il modello di minaccia, perché
chi controlla file e codice ricalcola l'intera catena. Se un domani il log
dovesse reggere da solo come prova, la strada è firmare un digest periodico
con chiave esterna, che non tocca il percorso di scrittura.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import uuid
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from mcp_server.contracts import (
    AgentResult,
    AuthorizedBy,
    CallOutcome,
    OwnerAgent,
    RiskTier,
)

DEFAULT_LOG_PATH = Path("logs/hermes-audit.jsonl")

_FILE_MODE = 0o600
_DIR_MODE = 0o700


class LogAction(StrEnum):
    """Tipo di evento registrato.

    Copre i punti della catena in cui una decisione di sicurezza viene presa:
    registrazione di un tool, innalzamento del tier, accesso a un segreto,
    invocazione di un agente, esecuzione di un tool.
    """

    AGENT_INVOKED = "agent_invoked"
    AGENT_RESULT = "agent_result"
    TOOL_REGISTERED = "tool_registered"
    TOOL_REGISTRATION_REJECTED = "tool_registration_rejected"
    TOOL_ALIAS_DETECTED = "tool_alias_detected"
    OVERRIDE_SET = "override_set"
    OVERRIDE_REJECTED = "override_rejected"
    TOOL_CALL = "tool_call"
    SECRET_ACCESS = "secret_access"


def _now_iso() -> str:
    """Timestamp ISO 8601 con timezone, in UTC.

    Sempre timezone-aware: un timestamp d'audit senza fuso non è correlabile
    con nient'altro.
    """
    return _dt.datetime.now(tz=_dt.UTC).isoformat()


class LogRecord(BaseModel):
    """Una riga del log d'audit.

    I campi rispecchiano quelli di :class:`~mcp_server.contracts.ToolCall`, così
    che traccia nel risultato e riga di log siano correlabili senza rimappature.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts: str = Field(default_factory=_now_iso, description="ISO 8601 UTC.")
    correlation_id: uuid.UUID = Field(description="Catena di invocazione.")
    action: LogAction
    outcome: CallOutcome
    agent: OwnerAgent | None = None
    tool_id: str | None = Field(default=None, max_length=64)
    target: str | None = Field(default=None, max_length=256)
    tier_effective: RiskTier | None = None
    authorized_by: AuthorizedBy | None = None
    secret_name: str | None = Field(
        default=None,
        max_length=128,
        description="Nome del segreto consultato. Mai il valore.",
    )
    detail: str = Field(default="", max_length=4096)

    def to_jsonl(self) -> str:
        """Serializza il record come singola riga JSONL (newline incluso)."""
        return self.model_dump_json() + "\n"


class AuditLog:
    """Writer append-only su file JSONL.

    Pensato per essere istanziato una volta dal server MCP e passato ai
    componenti che devono registrare eventi (registry, vault, orchestratore).

    Parameters
    ----------
    path:
        File di log. La directory padre viene creata con permessi 0700 se
        assente.
    fsync:
        Se ``True``, forza il flush su disco a ogni record. Costa latenza ma
        rende la riga sopravvivente a un crash immediato: va attivato quando
        il log è usato come prova e non solo come diagnostica.
    """

    def __init__(self, path: str | os.PathLike[str] = DEFAULT_LOG_PATH, *, fsync: bool = False) -> None:
        self._path = Path(path)
        self._fsync = fsync
        self._prepara_destinazione()

    # -- API ---------------------------------------------------------------- #

    @property
    def path(self) -> Path:
        return self._path

    def write(self, record: LogRecord) -> LogRecord:
        """Appende un record al log e lo restituisce."""
        riga = record.to_jsonl().encode("utf-8")
        fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, _FILE_MODE)
        try:
            os.write(fd, riga)
            if self._fsync:
                os.fsync(fd)
        finally:
            os.close(fd)
        return record

    def log(
        self,
        *,
        correlation_id: uuid.UUID,
        action: LogAction,
        outcome: CallOutcome,
        **campi,
    ) -> LogRecord:
        """Costruisce e appende un record in un solo passaggio."""
        return self.write(
            LogRecord(
                correlation_id=correlation_id,
                action=action,
                outcome=outcome,
                **campi,
            )
        )

    def log_agent_result(self, result: AgentResult) -> tuple[LogRecord, ...]:
        """Registra un :class:`AgentResult` e ogni sua invocazione di tool.

        Emette una riga ``agent_result`` più una riga ``tool_call`` per ciascuna
        chiamata tracciata, tutte con lo stesso ``correlation_id``: è ciò che
        rende la catena ricostruibile da una singola query sul log.
        """
        righe = [
            self.log(
                correlation_id=result.correlation_id,
                action=LogAction.AGENT_RESULT,
                outcome=_esito_da_status(result),
                agent=result.agent,
                detail=result.summary,
            )
        ]
        for call in result.tool_calls:
            righe.append(
                self.log(
                    correlation_id=result.correlation_id,
                    action=LogAction.TOOL_CALL,
                    outcome=call.outcome,
                    agent=result.agent,
                    tool_id=call.tool_id,
                    target=call.target,
                    tier_effective=call.tier_effective,
                    authorized_by=call.authorized_by,
                    detail=call.detail,
                )
            )
        return tuple(righe)

    def read_all(self) -> tuple[LogRecord, ...]:
        """Rilegge e valida tutto il log. Per test e ispezione, non per hot path."""
        if not self._path.exists():
            return ()
        with self._path.open("r", encoding="utf-8") as fh:
            return tuple(
                LogRecord.model_validate_json(riga)
                for riga in fh
                if riga.strip()
            )

    # -- interno ------------------------------------------------------------ #

    def _prepara_destinazione(self) -> None:
        """Crea directory e file con permessi restrittivi, senza troncare."""
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        # O_APPEND|O_CREAT non tronca: un log esistente resta intatto.
        fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, _FILE_MODE)
        os.close(fd)
        # mkdir/open rispettano la umask: i permessi vanno imposti dopo.
        os.chmod(self._path, _FILE_MODE)
        try:
            os.chmod(self._path.parent, _DIR_MODE)
        except PermissionError:  # pragma: no cover - directory non nostra
            pass


def _esito_da_status(result: AgentResult) -> CallOutcome:
    """Mappa lo status di un agente sull'esito registrato nel log."""
    from mcp_server.contracts import AgentStatus

    match result.status:
        case AgentStatus.OK:
            return CallOutcome.OK
        case AgentStatus.ERROR:
            return CallOutcome.ERROR
        case AgentStatus.NEEDS_CONFIRMATION:
            return CallOutcome.PENDING
    raise AssertionError(f"status non gestito: {result.status}")  # pragma: no cover


__all__ = ["AuditLog", "DEFAULT_LOG_PATH", "LogAction", "LogRecord"]
