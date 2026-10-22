#!/usr/bin/env python3
"""Script del tool ``echo.ping``: agente dummy della Milestone 0.

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
"""

from __future__ import annotations

import json
import platform
import sys


def main(argv: list[str] | None = None) -> int:
    """Emette un payload JSON su stdout e termina con esito 0."""
    argomenti = list(argv if argv is not None else sys.argv[1:])

    payload = {
        "tool": "echo.ping",
        "message": "catena di esecuzione percorsa correttamente",
        "args": argomenti,
        "python": platform.python_version(),
        "findings": [],
    }
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
