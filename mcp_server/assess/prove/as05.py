"""AS-05 — un'esecuzione avviene senza traccia completa nel log.

Si invoca ``assess.canary`` lungo la catena vera e si cercano nel log le tre
righe che il server deve scrivere con il proprio ``correlation_id``:
``agent_invoked``, ``tool_call``, ``agent_result``. Se il tool ha lasciato
esiti, il manifesto scritto nella riga ``tool_call`` deve coincidere con
quello ricalcolato sulla directory: la stessa funzione che usa il gate, non
una copia (``mcp_server.esiti``).

È una misura, non un tentativo: si esegue un'invocazione legittima e si
guarda cosa lascia. Se il canary non è andato a buon fine non c'è
un'esecuzione di cui misurare la traccia, e la voce è *non verificabile*.
"""

from __future__ import annotations

import re

import anyio

from mcp_server.assess import catena
from mcp_server.assess.contesto import Contesto
from mcp_server.assess.prove import Prova, Risultato
from mcp_server.assess.referto import EsitoProva, Evidenza
from mcp_server.contracts import AgentStatus
from mcp_server.esiti import DIR_ESITI, manifesto

CANARY = "assess.canary"
ATTESE = ("agent_invoked", "tool_call", "agent_result")
_MANIFESTO = re.compile(r"manifesto sha256:([0-9a-f]{64})")


def applicabile(ctx: Contesto) -> str | None:
    if ctx.tool(CANARY) is None:
        return f"{CANARY} non registrato per l'agente '{ctx.cfg.agent}'"
    return None


def _invoca(ctx: Contesto) -> catena.Invocazione:
    async def corpo() -> catena.Invocazione:
        async with catena.sessione(ctx) as s:
            return await catena.invoca(s, CANARY)

    return anyio.run(corpo)


def valuta(inv: catena.Invocazione, righe: list[dict], *, esiti=DIR_ESITI) -> Risultato:
    cid = inv.result.correlation_id
    if inv.result.status is not AgentStatus.OK:
        return Risultato(
            EsitoProva.NON_VERIFICABILE,
            (),
            f"il canary non è stato eseguito ({inv.result.status}): "
            f"{inv.result.summary}",
        )
    azioni = [r.get("action") for r in righe]
    evidenze = [
        Evidenza(
            operazione="riga_di_audit",
            identita="server",
            oggetto=f"{azione} · {cid}",
            riuscita=azione in azioni,
        )
        for azione in ATTESE
    ]
    mancanti = [a for a in ATTESE if a not in azioni]
    if mancanti:
        return Risultato(
            EsitoProva.CEDE,
            tuple(evidenze),
            f"esecuzione avvenuta, righe mancanti nel log: {', '.join(mancanti)}",
        )

    chiamata = next(r for r in righe if r.get("action") == "tool_call")
    trovato = _MANIFESTO.search(str(chiamata.get("detail", "")))
    if trovato is None:
        return Risultato(EsitoProva.TIENE, tuple(evidenze), "nessun esito lasciato dal tool")
    try:
        ricalcolato = manifesto(esiti / str(cid)).sha256
    except OSError as err:
        evidenze.append(
            Evidenza("manifesto", "root", str(esiti / str(cid)), False, eseguita=False,
                     dettaglio=f"{type(err).__name__}: {err}")
        )
        return Risultato(
            EsitoProva.NON_VERIFICABILE, tuple(evidenze), "esiti non rileggibili"
        )
    uguale = ricalcolato == trovato.group(1)
    evidenze.append(
        Evidenza("manifesto", "root", str(esiti / str(cid)), uguale,
                 dettaglio=f"log {trovato.group(1)[:16]}… · disco {ricalcolato[:16]}…")
    )
    if not uguale:
        return Risultato(
            EsitoProva.CEDE,
            tuple(evidenze),
            "il manifesto nel log non corrisponde agli esiti su disco",
        )
    return Risultato(EsitoProva.TIENE, tuple(evidenze))


def esegui(ctx: Contesto) -> Risultato:
    inv = _invoca(ctx)
    righe = catena.righe_di_audit(ctx.cfg.log_path, inv.result.correlation_id)
    return valuta(inv, righe)


PROVA = Prova(id="AS-05", applicabile=applicabile, esegui=esegui)
