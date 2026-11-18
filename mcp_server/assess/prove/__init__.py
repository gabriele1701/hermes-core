"""Le prove di hermes-assess, una per modulo, agganciate al catalogo per ``id``.

Una prova ha due parti, e la separazione è il punto:

* ``applicabile(ctx)`` — ``None`` se la prova si applica, altrimenti il
  **motivo** per cui no, scritto per chi legge il referto. Non applicabile
  non è un esito buono: è un'informazione su cosa non è stato guardato;
* ``esegui(ctx)`` — il :class:`Risultato`. Non decide la gravità e non
  conosce il registro del debito: quelle sono decisioni del giro, prese allo
  stesso modo per tutte.

Un'eccezione dentro ``esegui`` non ferma il giro: la voce diventa *non
verificabile* con la causa, e si passa alla successiva. Un controllo che si
ferma al primo problema informa meno proprio quando serve.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from mcp_server.assess.contesto import Contesto
from mcp_server.assess.referto import EsitoProva, Evidenza


@dataclass(frozen=True, slots=True)
class Risultato:
    esito: EsitoProva
    evidenze: tuple[Evidenza, ...] = ()
    nota: str = ""


def da_evidenze(
    positivi: list[Evidenza], negativi: list[Evidenza], *, nota: str = ""
) -> Risultato:
    """La regola dei tentativi, uguale per tutte le prove che ne fanno.

    1. un negativo **riuscito** è un cedimento — anche se altri non sono
       verificabili: un fatto vale più di un'assenza di fatti;
    2. altrimenti, un positivo fallito o una sonda non eseguita rendono la
       prova non verificabile;
    3. solo allora *tiene*.
    """
    evidenze = tuple(positivi) + tuple(negativi)
    ceduti = [e for e in negativi if e.eseguita and e.riuscita]
    if ceduti:
        oggetti = ", ".join(e.oggetto for e in ceduti)
        return Risultato(EsitoProva.CEDE, evidenze, f"riuscito ciò che doveva fallire: {oggetti}")
    mancati = [e for e in positivi if not (e.eseguita and e.riuscita)]
    muti = [e for e in negativi if not e.eseguita]
    if mancati or muti:
        parti = []
        if mancati:
            parti.append(
                "controllo positivo fallito su "
                + ", ".join(e.oggetto for e in mancati)
            )
        if muti:
            parti.append("sonda senza risposta su " + ", ".join(e.oggetto for e in muti))
        return Risultato(EsitoProva.NON_VERIFICABILE, evidenze, "; ".join(parti))
    if not negativi:
        return Risultato(EsitoProva.NON_VERIFICABILE, evidenze, "nessun tentativo eseguito")
    return Risultato(EsitoProva.TIENE, evidenze, nota)


@dataclass(frozen=True, slots=True)
class Prova:
    id: str
    applicabile: Callable[[Contesto], str | None]
    esegui: Callable[[Contesto], Risultato]


def registro() -> dict[str, Prova]:
    """Le prove implementate. Import qui per non caricarle finché non servono."""
    from mcp_server.assess.prove import as03, as05, as06

    return {p.id: p for p in (as03.PROVA, as05.PROVA, as06.PROVA)}


__all__ = ["Prova", "Risultato", "da_evidenze", "registro"]
