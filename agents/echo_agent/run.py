#!/usr/bin/env python3
"""Script dei tool dummy dell'agente echo: la Milestone 0 in esecuzione.

Non fa nulla di reale. Esiste per esercitare la catena completa —
orchestratore, server MCP, gate di esecuzione, log d'audit — senza che alcun
tool di sicurezza venga coinvolto.

Deliberatamente privo di dipendenze
-----------------------------------

Usa solo la libreria standard e non importa nulla di ``hermes-core``. Non è
una semplificazione: il gate esegue gli script con ``python3`` e un ambiente
ridotto a una lista bianca, senza ``PYTHONPATH`` e senza il virtualenv del
server. Uno script che importasse i moduli del progetto funzionerebbe nei
test e fallirebbe in esecuzione reale.

Vale come vincolo per tutti i tool che verranno: **un tool è un eseguibile
autonomo**, non un modulo del server. Il confine è quello che permette, più
avanti, di eseguirlo dentro un container senza portarsi dietro il resto.

Lo script non dichiara il proprio ``tool_id``
---------------------------------------------

Il payload riportava ``"tool": "echo.ping"`` come costante. Dal passo 8 lo
stesso script è registrato anche come ``echo.bersaglio``, e quel campo ha
iniziato a mentire — trovato esercitando il perimetro sulla VM.

Non si corregge passando il ``tool_id`` allo script: un eseguibile **non può
sapere** sotto quale nome è stato registrato, perché quella corrispondenza
vive nel registro del server e può essere più di una. Un campo in cui lo
script la afferma sarebbe un'affermazione non verificabile dentro l'output,
cioè la stessa forma del ``correlation_id`` dichiarato dal client che HC-07 ha
chiuso. Chi ha invocato cosa lo dice il log d'audit, con il ``tool_id`` che il
registro conosce.

Vale come regola per i tool che verranno: **un tool riporta ciò che ha fatto,
non chi è**. Un campo che mente è peggio di un campo che manca.
"""

from __future__ import annotations

import json
import platform
import sys


def main(argv: list[str] | None = None) -> int:
    """Emette un payload JSON su stdout e termina con esito 0."""
    argomenti = list(argv if argv is not None else sys.argv[1:])

    payload = {
        "message": "catena di esecuzione percorsa correttamente",
        "args": argomenti,
        "python": platform.python_version(),
        "findings": [],
    }
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
