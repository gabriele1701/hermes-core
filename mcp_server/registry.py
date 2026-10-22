"""Registro dei tool del server MCP.

Unico punto in cui un tool diventa invocabile. Tiene tre cose separate:

1. le :class:`~mcp_server.contracts.ToolSpec` registrate, immutabili;
2. gli **override di tier** dell'utente, in uno store distinto dalle spec;
3. il calcolo del **tier effettivo** e della policy che ne deriva.

Perché lo store degli override è separato
-----------------------------------------

Il tier dichiarato all'integrazione non è modificabile: la spec è ``frozen``.
Un innalzamento richiesto dall'utente finisce in uno store a parte, e il tier
effettivo è ``max(default, override)``. Da questo derivano due proprietà che
una singola struttura mutabile non darebbe:

* il tier dichiarato resta sempre ispezionabile come l'ha dichiarato
  l'integratore, utile in audit per distinguere "era rischioso" da "l'ho
  alzato io";
* un override più basso del default è **inerte anche se finisse nello store**,
  perché il massimo lo scarta. La difesa non riposa solo sul controllo
  all'ingresso.

Semantica dell'override: solo in salita
---------------------------------------

``set_override`` accetta un tier maggiore o uguale a quello effettivo e
**rifiuta** qualunque declassamento. L'invariante che ne risulta è che il tier
effettivo di un tool è monotòno non decrescente per tutta la vita del
registro. Permettere all'utente di abbassare un tier sarebbe un modo di
disattivare i controlli, cosa che il documento di scope vieta: l'override è
consenso a eseguire qualcosa di rischioso, non licenza di dichiararlo meno
rischioso di quanto sia.

Registrazione: append-only, costruita all'avvio
-----------------------------------------------

Il registro si popola all'avvio dalla configurazione versionata e non espone
deregistrazione. Registrare due volte lo stesso ``tool_id`` è **rifiutato**:
sarebbe la via più comoda per aggirare la regola sull'override, ri-registrando
un tool con un tier più basso. Aggiornare un tool (nuovo script, nuovo SHA)
significa modificare la configurazione versionata e riavviare il server, non
sovrascrivere una voce a caldo.

Isolamento fra agenti
---------------------

Ogni tool dichiara il proprio ``owner_agent``, e il registro è l'unico
componente che lo sa. :meth:`ToolRegistry.assert_can_invoke` fa valere quel
confine: senza, il campo sarebbe decorativo e l'agente di pentest potrebbe
invocare i tool dell'agente di vulnerability assessment e viceversa.
"""

from __future__ import annotations

import uuid
from types import MappingProxyType
from typing import Mapping

from pydantic import ValidationError

from mcp_server.audit import AuditLog, LogAction
from mcp_server.contracts import CallOutcome, OwnerAgent, RiskTier, ToolSpec
from mcp_server.tiers import ConfirmationPolicy, derive_policy_for

# --------------------------------------------------------------------------- #
# Errori
# --------------------------------------------------------------------------- #


class RegistryError(Exception):
    """Base degli errori del registro."""


class ToolAlreadyRegistered(RegistryError):
    """Un tool con lo stesso ``tool_id`` è già registrato."""


class ToolNotRegistered(RegistryError):
    """Il ``tool_id`` richiesto non è nel registro."""


class ToolSpecRejected(RegistryError):
    """La spec proposta non soddisfa il contratto di registrazione."""


class OverrideRefused(RegistryError):
    """L'override richiesto abbasserebbe il tier effettivo."""


class InvocationRefused(RegistryError):
    """L'agente richiedente non è il proprietario del tool."""


# --------------------------------------------------------------------------- #
# Registro
# --------------------------------------------------------------------------- #


class ToolRegistry:
    """Registro in memoria dei tool invocabili.

    Parameters
    ----------
    audit:
        Log su cui registrare registrazioni, rifiuti e override. Ogni
        decisione di sicurezza del registro lascia una riga.
    correlation_id:
        Correlazione usata per gli eventi che non nascono da una invocazione
        di agente — tipicamente il popolamento all'avvio. Se omesso ne viene
        generato uno per istanza, così gli eventi di startup restano
        raggruppabili.
    """

    def __init__(self, audit: AuditLog, *, correlation_id: uuid.UUID | None = None) -> None:
        self._audit = audit
        self._correlation_id = correlation_id or uuid.uuid4()
        self._specs: dict[str, ToolSpec] = {}
        self._overrides: dict[str, RiskTier] = {}

    # -- introspezione ------------------------------------------------------ #

    @property
    def correlation_id(self) -> uuid.UUID:
        return self._correlation_id

    @property
    def tools(self) -> Mapping[str, ToolSpec]:
        """Vista in sola lettura delle spec registrate."""
        return MappingProxyType(self._specs)

    @property
    def overrides(self) -> Mapping[str, RiskTier]:
        """Vista in sola lettura degli override attivi."""
        return MappingProxyType(self._overrides)

    def __contains__(self, tool_id: object) -> bool:
        return tool_id in self._specs

    def __len__(self) -> int:
        return len(self._specs)

    def spec(self, tool_id: str) -> ToolSpec:
        """Restituisce la spec, o solleva.

        Solleva invece di restituire ``None`` di proposito: un ``None``
        silenzioso invita allo schema ``if not spec: ...`` che finisce per
        saltare i controlli su un tool sconosciuto.
        """
        try:
            return self._specs[tool_id]
        except KeyError as err:
            raise ToolNotRegistered(f"tool non registrato: {tool_id!r}") from err

    # -- registrazione ------------------------------------------------------ #

    def register(self, spec: ToolSpec) -> ToolSpec:
        """Registra un tool già validato.

        Rifiuta un ``tool_id`` duplicato: il registro è append-only.
        """
        if spec.tool_id in self._specs:
            self._log(
                LogAction.TOOL_REGISTRATION_REJECTED,
                CallOutcome.DENIED,
                tool_id=spec.tool_id,
                tier_effective=spec.default_tier,
                detail="tool_id già registrato: il registro non ammette sovrascritture",
            )
            raise ToolAlreadyRegistered(f"tool già registrato: {spec.tool_id!r}")

        self._specs[spec.tool_id] = spec
        policy = derive_policy_for(spec)
        self._log(
            LogAction.TOOL_REGISTERED,
            CallOutcome.OK,
            agent=spec.owner_agent,
            tool_id=spec.tool_id,
            tier_effective=spec.default_tier,
            detail=(
                f"registrato; personal_data={spec.personal_data}, "
                f"requires_container={spec.requires_container}, "
                f"conferma tecnica={policy.technical}, dedicata={policy.personal}"
            ),
        )
        return spec

    def register_payload(self, payload: Mapping[str, object]) -> ToolSpec:
        """Valida un payload grezzo e lo registra.

        Un tentativo di registrazione malformato — tier assente, tier
        inventato, ``exec_path`` con traversal, campi non dichiarati — viene
        **registrato nel log** prima di essere respinto: un tool che prova a
        entrare senza i metadati richiesti è un evento che l'audit deve
        conservare, non un errore da far evaporare.
        """
        try:
            spec = ToolSpec(**payload)
        except ValidationError as err:
            self._log(
                LogAction.TOOL_REGISTRATION_REJECTED,
                CallOutcome.DENIED,
                tool_id=_tool_id_dal_payload(payload),
                detail=f"spec non conforme al contratto: {_compatta(err)}",
            )
            raise ToolSpecRejected(f"spec non conforme: {err}") from err
        return self.register(spec)

    # -- tier effettivo e override ------------------------------------------ #

    def effective_tier(self, tool_id: str) -> RiskTier:
        """Tier applicato al tool: ``max(default, override)``.

        Il massimo è il secondo presidio: anche se nello store finisse un
        override più basso del default, resterebbe inerte.
        """
        spec = self.spec(tool_id)
        override = self._overrides.get(tool_id)
        if override is None:
            return spec.default_tier
        return max(spec.default_tier, override, key=lambda t: t.rank)

    def set_override(
        self,
        tool_id: str,
        tier: RiskTier,
        *,
        correlation_id: uuid.UUID | None = None,
    ) -> RiskTier:
        """Innalza il tier di un tool. Rifiuta ogni declassamento.

        Un tier uguale a quello effettivo è accettato ed è idempotente. Uno
        inferiore viene rifiutato e registrato come evento di sicurezza:
        abbassare un tier equivarrebbe a disattivare un controllo.

        Returns
        -------
        Il tier effettivo risultante.
        """
        corrente = self.effective_tier(tool_id)  # solleva se non registrato
        if tier.rank < corrente.rank:
            self._log(
                LogAction.OVERRIDE_REJECTED,
                CallOutcome.DENIED,
                tool_id=tool_id,
                tier_effective=corrente,
                detail=(
                    f"declassamento rifiutato: richiesto '{tier}' su effettivo "
                    f"'{corrente}'; l'override può solo innalzare"
                ),
                correlation_id=correlation_id,
            )
            raise OverrideRefused(
                f"l'override non può abbassare il tier: richiesto {tier!r}, "
                f"effettivo {corrente!r}"
            )

        self._overrides[tool_id] = tier
        risultante = self.effective_tier(tool_id)
        self._log(
            LogAction.OVERRIDE_SET,
            CallOutcome.OK,
            tool_id=tool_id,
            tier_effective=risultante,
            detail=(
                f"override utente: '{corrente}' -> '{risultante}' "
                f"(dichiarato '{self.spec(tool_id).default_tier}')"
            ),
            correlation_id=correlation_id,
        )
        return risultante

    def policy_for(self, tool_id: str) -> ConfirmationPolicy:
        """Policy di conferma calcolata sul tier **effettivo**."""
        spec = self.spec(tool_id)
        return derive_policy_for(spec, effective_tier=self.effective_tier(tool_id))

    # -- isolamento fra agenti ---------------------------------------------- #

    def can_invoke(self, tool_id: str, agent: OwnerAgent) -> bool:
        """Se l'agente è il proprietario del tool."""
        return self.spec(tool_id).owner_agent is agent

    def assert_can_invoke(
        self,
        tool_id: str,
        agent: OwnerAgent,
        *,
        correlation_id: uuid.UUID | None = None,
    ) -> ToolSpec:
        """Verifica il confine fra agenti, o solleva registrando il rifiuto."""
        spec = self.spec(tool_id)
        if spec.owner_agent is not agent:
            self._log(
                LogAction.TOOL_CALL,
                CallOutcome.DENIED,
                agent=agent,
                tool_id=tool_id,
                tier_effective=self.effective_tier(tool_id),
                detail=(
                    f"invocazione rifiutata: il tool appartiene a "
                    f"'{spec.owner_agent}', richiedente '{agent}'"
                ),
                correlation_id=correlation_id,
            )
            raise InvocationRefused(
                f"{agent!r} non può invocare {tool_id!r}: appartiene a "
                f"{spec.owner_agent!r}"
            )
        return spec

    # -- interno ------------------------------------------------------------ #

    def _log(
        self,
        action: LogAction,
        outcome: CallOutcome,
        *,
        correlation_id: uuid.UUID | None = None,
        **campi,
    ) -> None:
        self._audit.log(
            correlation_id=correlation_id or self._correlation_id,
            action=action,
            outcome=outcome,
            **campi,
        )


def _tool_id_dal_payload(payload: Mapping[str, object]) -> str | None:
    """Estrae un ``tool_id`` utilizzabile nel log da un payload non valido.

    Il payload è per definizione non conforme, quindi il valore va trattato
    come non fidato: solo stringhe, troncate alla lunghezza del campo di log.
    """
    valore = payload.get("tool_id")
    if isinstance(valore, str) and valore:
        return valore[:64]
    return None


def _compatta(err: ValidationError) -> str:
    """Riassume un errore di validazione in una riga di log."""
    pezzi = [
        f"{'.'.join(str(p) for p in e['loc']) or '<root>'}: {e['msg']}"
        for e in err.errors()
    ]
    riga = "; ".join(pezzi)
    return riga[:2000]


__all__ = [
    "InvocationRefused",
    "OverrideRefused",
    "RegistryError",
    "ToolAlreadyRegistered",
    "ToolNotRegistered",
    "ToolRegistry",
    "ToolSpecRejected",
]
