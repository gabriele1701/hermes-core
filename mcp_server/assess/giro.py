"""Un giro: ogni minaccia del catalogo, la sua prova, una voce di referto.

Le decisioni prese qui valgono per tutte le prove allo stesso modo:

* **applicabilità** — una prova non applicabile produce una voce che dice
  perché, non sparisce;
* **eccezioni** — una prova che solleva diventa *non verificabile* con la
  causa, e il giro continua;
* **debito** — un cedimento contro una voce ACCETTATA del registro è
  *accettato*; contro una voce aperta resta un cedimento, con il rimando.

La gravità in questo passo è quella di base: i modificatori di contesto
arrivano con la valutazione (M1.3).
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Mapping

from mcp_server.assess import contesto as _contesto
from mcp_server.assess.catalogo import CATALOGO, Minaccia
from mcp_server.assess.contesto import Contesto
from mcp_server.assess.prove import Prova, Risultato, registro
from mcp_server.assess.referto import EsitoProva, Referto, Voce

PREFISSO_ACCETTATA = "ACCETTATA — "


def voce(minaccia: Minaccia, prova: Prova, ctx: Contesto) -> Voce:
    motivo = prova.applicabile(ctx)
    if motivo is not None:
        return Voce(
            minaccia.id, EsitoProva.NON_APPLICABILE, minaccia.gravita,
            minaccia.gravita, nota=motivo,
        )
    try:
        risultato = prova.esegui(ctx)
    except Exception as err:  # noqa: BLE001 - una prova rotta non ferma il giro
        risultato = Risultato(
            EsitoProva.NON_VERIFICABILE,
            nota=f"la prova non è arrivata in fondo: {type(err).__name__}: {err}",
        )
    esito, nota = risultato.esito, risultato.nota
    if esito is EsitoProva.CEDE and minaccia.debito:
        if minaccia.debito.startswith(PREFISSO_ACCETTATA):
            esito = EsitoProva.ACCETTATO
        nota = f"{nota} — registro del debito: «{minaccia.debito}»".lstrip(" —")
    return Voce(
        minaccia.id, esito, minaccia.gravita, minaccia.gravita,
        evidenze=risultato.evidenze, nota=nota,
    )


def esegui(
    ctx: Contesto,
    *,
    solo: frozenset[str] | None = None,
    prove: Mapping[str, Prova] | None = None,
) -> Referto:
    prove = registro() if prove is None else prove
    voci, non_implementate = [], []
    for minaccia in CATALOGO:
        if solo is not None and minaccia.id not in solo:
            continue
        prova = prove.get(minaccia.id)
        if prova is None:
            non_implementate.append(minaccia.id)
            continue
        voci.append(voce(minaccia, prova, ctx))

    limiti = [
        "prove locali: eseguite sull'host sorvegliato, un root compromesso può "
        "falsificarne ogni esito",
        "gravità di base: i modificatori di contesto non sono ancora applicati",
    ]
    if not ctx.root:
        limiti.append(
            "eseguito senza root: le prove sotto altre identità non sono applicabili"
        )
    if non_implementate:
        limiti.append("prove non ancora implementate: " + ", ".join(non_implementate))

    commit, pulito = _contesto.stato_del_repo(ctx.repo)
    if not pulito:
        limiti.append(
            "albero di lavoro non pulito o commit illeggibile: il codice che ha "
            "valutato non è necessariamente quello versionato"
        )
    return Referto(
        generato=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        host=_contesto.host(),
        config=str(ctx.config_path),
        commit=commit,
        albero_pulito=pulito,
        voci=tuple(voci),
        limiti=tuple(limiti),
    )


__all__ = ["esegui", "voce"]
