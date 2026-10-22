"""Contratti dati di hermes-core.

Questo modulo definisce il **vocabolario** e i **contratti** condivisi fra server
MCP, orchestratore e agenti. Non contiene logica di dominio: la derivazione della
confirmation policy vive in ``tiers.py``, la registrazione in ``registry.py``.

Due contratti:

* :class:`ToolSpec` — contratto di **registrazione** di un tool presso il server
  MCP. Dichiarato una volta all'integrazione del tool.
* :class:`AgentResult` — contratto di **risultato** restituito da un agente
  all'orchestratore.

Scelte difensive applicate a tutti i modelli:

* ``frozen=True`` — i contratti sono immutabili dopo la costruzione. Per
  :class:`ToolSpec` questo *è* il meccanismo che rende il risk tier non
  modificabile dopo la registrazione: un eventuale innalzamento passa dallo
  store di override del registry, mai mutando la spec.
* ``extra="forbid"`` — un payload con campi non previsti viene **rifiutato**
  invece di essere accettato ignorando l'ignoto. Un contratto permissivo è una
  superficie d'attacco: campi non dichiarati non devono poter transitare.

Nota operativa: :class:`AgentResult` è destinato a essere serializzato nei log
d'audit. Non deve mai trasportare valori di credenziali — il vault espone
l'accesso ai segreti, non i segreti stessi, e logga l'accesso senza il valore.
"""

from __future__ import annotations

import uuid
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# --------------------------------------------------------------------------- #
# Vocabolario
# --------------------------------------------------------------------------- #


class RiskTier(StrEnum):
    """Asse tecnico del rischio di un tool.

    Primo dei due assi indipendenti del contratto di metadati. Determina la
    cadenza di conferma richiesta (derivata in ``tiers.py``, non dichiarata dal
    tool). Il secondo asse è il flag ``personal_data`` di :class:`ToolSpec`.

    L'ordinamento è significativo: ``VERDE < GIALLO < ROSSO``. Il registry lo usa
    per calcolare il tier effettivo come massimo fra default e override, così un
    override può solo innalzare il rischio dichiarato, mai abbassarlo.
    """

    VERDE = "verde"
    GIALLO = "giallo"
    ROSSO = "rosso"

    @property
    def rank(self) -> int:
        """Posizione ordinale del tier, per confronti monotoni."""
        return _TIER_RANK[self]


_TIER_RANK: dict[RiskTier, int] = {
    RiskTier.VERDE: 0,
    RiskTier.GIALLO: 1,
    RiskTier.ROSSO: 2,
}


class OwnerAgent(StrEnum):
    """Agente proprietario di un tool.

    In Milestone 0 esiste solo ``ECHO_DUMMY``: gli agenti operativi arrivano
    nelle milestone successive, ma il vocabolario è già fissato perché il
    contratto di registrazione non cambi quando entrano.
    """

    ORCHESTRATOR = "orchestrator"
    ECHO_DUMMY = "echo_dummy"
    VULN_ASSESSMENT = "vuln_assessment"
    PENTEST_KALI = "pentest_kali"


class AgentStatus(StrEnum):
    """Esito complessivo dell'invocazione di un agente.

    ``NEEDS_CONFIRMATION`` è il gancio con cui una richiesta di autorizzazione
    risale dall'agente fino all'utente: l'agente si ferma e dichiara cosa
    resta in attesa, invece di procedere. In M0 è presente nello schema e
    vincolato dagli invarianti, ma non esercitato da tool reali.
    """

    OK = "ok"
    ERROR = "error"
    NEEDS_CONFIRMATION = "needs_confirmation"


class Severity(StrEnum):
    """Severità di un finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CallOutcome(StrEnum):
    """Esito di una singola invocazione di tool.

    ``DENIED`` = negata dai controlli (tier/scope). ``PENDING`` = sospesa in
    attesa di conferma utente.
    """

    OK = "ok"
    ERROR = "error"
    DENIED = "denied"
    PENDING = "pending"


class AuthorizedBy(StrEnum):
    """Origine dell'autorizzazione di una invocazione.

    ``POLICY`` = consentita dalla policy derivata dal tier, senza interazione.
    ``USER`` = consenso esplicito dell'utente. ``NONE`` = nessuna
    autorizzazione (la chiamata non è stata eseguita).
    """

    POLICY = "policy"
    USER = "user"
    NONE = "none"


# --------------------------------------------------------------------------- #
# Base comune
# --------------------------------------------------------------------------- #

_STRICT = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)


class _StrictModel(BaseModel):
    """Base immutabile che rifiuta campi non dichiarati."""

    model_config = _STRICT


# --------------------------------------------------------------------------- #
# Contratto di registrazione
# --------------------------------------------------------------------------- #

_TOOL_ID_PATTERN = r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"


class ToolSpec(_StrictModel):
    """Contratto di registrazione di un tool presso il server MCP.

    Dichiarato all'integrazione del tool. Un tool che non dichiara
    ``default_tier`` non è registrabile: l'assenza del tier non degrada a un
    default permissivo, fa fallire la registrazione.

    La ``confirmation_policy`` **non** è un campo di questo contratto: è
    derivata dal tier dal server (``tiers.derive_policy``). Se il tool potesse
    dichiararla, potrebbe auto-assegnarsi una cadenza più lassa del proprio
    rischio.
    """

    tool_id: str = Field(
        pattern=_TOOL_ID_PATTERN,
        min_length=3,
        max_length=64,
        description="Identificatore univoco del tool (lowercase, separatori . _ -).",
    )
    owner_agent: OwnerAgent = Field(
        description="Agente proprietario: solo lui può invocare il tool."
    )
    default_tier: RiskTier = Field(
        description="Risk tier tecnico dichiarato all'integrazione. Immutabile."
    )
    personal_data: bool = Field(
        description=(
            "Secondo asse: il tool tratta dati personali. Indipendente dal tier, "
            "richiede una conferma dedicata."
        )
    )
    requires_container: bool = Field(
        description=(
            "Il tool deve essere eseguito nel container isolato, non sull'host "
            "Hermes."
        )
    )
    exec_path: str = Field(
        min_length=1,
        max_length=512,
        description="Percorso dello script, relativo alla radice del repo.",
    )
    exec_sha256: str = Field(
        pattern=_SHA256_PATTERN,
        description=(
            "SHA-256 atteso dello script (64 hex lowercase). Pinna la versione "
            "eseguita: uno script modificato non corrisponde e non va eseguito."
        ),
    )
    description: str = Field(
        min_length=1,
        max_length=512,
        description="Cosa fa il tool, in una riga. Mostrato in fase di conferma.",
    )

    @field_validator("exec_path")
    @classmethod
    def _percorso_confinato(cls, v: str) -> str:
        """Rifiuta percorsi assoluti e traversal.

        Lo script eseguito deve stare dentro il repo versionato: un percorso
        assoluto o con ``..`` permetterebbe di puntare a un eseguibile
        arbitrario del filesystem, aggirando il pinning via SHA.
        """
        if v.startswith(("/", "\\")):
            raise ValueError("exec_path deve essere relativo alla radice del repo")
        if "\\" in v:
            raise ValueError("exec_path deve usare '/' come separatore")
        parts = v.split("/")
        if ".." in parts:
            raise ValueError("exec_path non può contenere '..'")
        if any(p in ("", ".") for p in parts):
            raise ValueError("exec_path non può contenere segmenti vuoti o '.'")
        return v


# --------------------------------------------------------------------------- #
# Contratto di risultato
# --------------------------------------------------------------------------- #


class Finding(_StrictModel):
    """Singola osservazione prodotta da un agente."""

    finding_id: str = Field(min_length=1, max_length=64)
    severity: Severity
    title: str = Field(min_length=1, max_length=256)
    detail: str = Field(default="", max_length=4096)
    target: str | None = Field(
        default=None,
        max_length=256,
        description="Host o risorsa cui il finding si riferisce.",
    )


class ToolCall(_StrictModel):
    """Traccia di una invocazione di tool dentro un :class:`AgentResult`.

    I campi rispecchiano quelli del log d'audit JSONL, così una riga di log e la
    traccia nel risultato siano correlabili senza rimappature.
    """

    tool_id: str = Field(pattern=_TOOL_ID_PATTERN, min_length=3, max_length=64)
    target: str | None = Field(default=None, max_length=256)
    tier_effective: RiskTier = Field(
        description="Tier applicato alla chiamata: max(default, override)."
    )
    authorized_by: AuthorizedBy
    outcome: CallOutcome
    detail: str = Field(default="", max_length=2048)

    @model_validator(mode="after")
    def _coerenza_autorizzazione(self) -> ToolCall:
        """Una chiamata eseguita deve avere un'autorizzazione tracciata.

        Un ``outcome`` di esecuzione (``OK``/``ERROR``) con ``authorized_by=NONE``
        descriverebbe un'esecuzione senza autorizzazione registrata: è
        esattamente lo stato che l'audit deve rendere impossibile da dichiarare.
        """
        if self.outcome in (CallOutcome.OK, CallOutcome.ERROR):
            if self.authorized_by is AuthorizedBy.NONE:
                raise ValueError(
                    f"outcome '{self.outcome}' richiede authorized_by "
                    f"'policy' o 'user', non 'none'"
                )
        return self


class AgentResult(_StrictModel):
    """Risultato strutturato restituito da un agente all'orchestratore.

    Unità di consegna della catena orchestratore → agente → log. Il
    ``correlation_id`` è lo stesso per tutta la catena: è ciò che permette di
    ricostruire a posteriori un'invocazione completa dai log JSONL.
    """

    correlation_id: uuid.UUID = Field(
        description="Identificatore della catena di invocazione (UUID)."
    )
    agent: OwnerAgent = Field(description="Agente che ha prodotto il risultato.")
    status: AgentStatus
    summary: str = Field(
        min_length=1,
        max_length=2048,
        description="Sintesi leggibile dell'esito. Mai valori di credenziali.",
    )
    findings: tuple[Finding, ...] = Field(default=())
    tool_calls: tuple[ToolCall, ...] = Field(default=())

    @model_validator(mode="after")
    def _coerenza_stato(self) -> AgentResult:
        """Lo stato dichiarato deve essere coerente con le chiamate tracciate.

        * ``NEEDS_CONFIRMATION`` deve avere almeno una chiamata ``PENDING``:
          altrimenti il risultato chiede una conferma senza dire su cosa.
        * ``OK`` non può avere chiamate ``PENDING``: un esito riuscito con
          qualcosa ancora in attesa di autorizzazione nasconderebbe all'utente
          una conferma non data.
        """
        pending = [c for c in self.tool_calls if c.outcome is CallOutcome.PENDING]
        if self.status is AgentStatus.NEEDS_CONFIRMATION and not pending:
            raise ValueError(
                "status 'needs_confirmation' richiede almeno una tool_call "
                "con outcome 'pending'"
            )
        if self.status is AgentStatus.OK and pending:
            raise ValueError(
                "status 'ok' non è compatibile con tool_call 'pending' "
                f"({len(pending)} in attesa)"
            )
        return self


__all__ = [
    "AgentResult",
    "AgentStatus",
    "AuthorizedBy",
    "CallOutcome",
    "Finding",
    "OwnerAgent",
    "RiskTier",
    "Severity",
    "ToolCall",
    "ToolSpec",
]
