"""AS-06 — il perimetro dei bersagli di rete non regge.

Tre invocazioni in una sessione, solo canary:

1. ``assess.canary`` (``target_kind = "none"``) **con** un bersaglio → deve
   essere ``denied`` (decisione 7: un argomento accettato e buttato via fa
   credere di aver limitato qualcosa);
2. ``assess.canary_host`` su un indirizzo **fuori** perimetro → ``denied``;
3. controllo positivo: ``assess.canary_host`` su un bersaglio **dentro** il
   perimetro → ``ok``. Senza, due rifiuti potrebbero venire da un canary
   rotto, non dal perimetro.

Gli indirizzi fuori perimetro si scelgono fra le reti riservate alla
documentazione (RFC 5737). Se il perimetro dell'operatore le contiene — un
esempio copiato — si prova la successiva; se le contiene tutte, la voce è
non verificabile invece di inventare un indirizzo vero.

Un ``error`` al posto di ``denied`` non è un cedimento — il canary non è
partito — ma non è nemmeno la forma promessa: un rifiuto presentato come
guasto fa riprovare chi lo legge. La voce è non verificabile, con la
ragione.
"""

from __future__ import annotations

import anyio

from mcp_server.assess import catena
from mcp_server.assess.contesto import Contesto
from mcp_server.assess.prove import Prova, Risultato
from mcp_server.assess.referto import EsitoProva, Evidenza
from mcp_server.contracts import AgentStatus
from mcp_server.scope import ScopeAllowlist, TargetRefused

CANARY = "assess.canary"
CANARY_HOST = "assess.canary_host"
FUORI_CANDIDATI = ("192.0.2.1", "198.51.100.1", "203.0.113.1")


def applicabile(ctx: Contesto) -> str | None:
    if ctx.cfg.scope_file is None:
        return "server.scope_file non configurato"
    for tool_id in (CANARY, CANARY_HOST):
        if ctx.tool(tool_id) is None:
            return f"{tool_id} non registrato per l'agente '{ctx.cfg.agent}'"
    return None


def scegli_bersagli(perimetro: ScopeAllowlist) -> tuple[str | None, str | None]:
    """``(fuori, dentro)``. ``None`` dove non si trova un candidato onesto."""
    fuori = None
    for candidato in FUORI_CANDIDATI:
        try:
            perimetro.risolvi(candidato)
        except TargetRefused:
            fuori = candidato
            break
    dentro = None
    if perimetro.alias:
        dentro = perimetro.alias[0]
    else:
        for rete in perimetro.reti:
            primo = next(iter(rete.hosts()), None) or rete.network_address
            dentro = str(primo)
            break
    return fuori, dentro


def _evidenza(inv: catena.Invocazione, attesa: AgentStatus, positivo: bool) -> Evidenza:
    return Evidenza(
        operazione="invoke_tool",
        identita="server",
        oggetto=f"{inv.tool_id} → {inv.target}",
        riuscita=inv.result.status is AgentStatus.OK,
        controllo_positivo=positivo,
        dettaglio=f"{inv.result.status} (atteso {attesa}): {inv.result.summary}",
    )


def valuta(
    con_bersaglio: catena.Invocazione,
    fuori: catena.Invocazione,
    dentro: catena.Invocazione,
) -> Risultato:
    evidenze = (
        _evidenza(dentro, AgentStatus.OK, True),
        _evidenza(con_bersaglio, AgentStatus.DENIED, False),
        _evidenza(fuori, AgentStatus.DENIED, False),
    )
    ceduti = [i for i in (con_bersaglio, fuori) if i.result.status is AgentStatus.OK]
    if ceduti:
        return Risultato(
            EsitoProva.CEDE,
            evidenze,
            "il gate ha eseguito: " + ", ".join(f"{i.tool_id} → {i.target}" for i in ceduti),
        )
    if dentro.result.status is not AgentStatus.OK:
        return Risultato(
            EsitoProva.NON_VERIFICABILE,
            evidenze,
            f"controllo positivo fallito: {CANARY_HOST} → {dentro.target} non è "
            f"stato eseguito, quindi i rifiuti non provano il perimetro",
        )
    non_negati = [
        i for i in (con_bersaglio, fuori) if i.result.status is not AgentStatus.DENIED
    ]
    if non_negati:
        return Risultato(
            EsitoProva.NON_VERIFICABILE,
            evidenze,
            "non eseguito ma non rifiutato: "
            + ", ".join(f"{i.tool_id} → {i.result.status}" for i in non_negati),
        )
    return Risultato(EsitoProva.TIENE, evidenze)


def esegui(ctx: Contesto) -> Risultato:
    assert ctx.cfg.scope_file is not None
    fuori, dentro = scegli_bersagli(ScopeAllowlist.carica(ctx.cfg.scope_file))
    if fuori is None or dentro is None:
        return Risultato(
            EsitoProva.NON_VERIFICABILE,
            (),
            "nessun indirizzo di documentazione è fuori perimetro"
            if fuori is None
            else "il perimetro non ha alias né reti da usare come controllo positivo",
        )

    async def corpo():
        async with catena.sessione(ctx) as s:
            return (
                await catena.invoca(s, CANARY, fuori),
                await catena.invoca(s, CANARY_HOST, fuori),
                await catena.invoca(s, CANARY_HOST, dentro),
            )

    return valuta(*anyio.run(corpo))


PROVA = Prova(id="AS-06", applicabile=applicabile, esegui=esegui)
