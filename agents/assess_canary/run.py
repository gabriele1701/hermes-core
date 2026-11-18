#!/usr/bin/env python3
"""Canary di ``hermes-assess``: un tool che non fa niente, e lo dice.

Esiste per percorrere la catena vera — server, gate, wrapper, unità, log —
senza che nessun tool reale venga coinvolto. ``hermes-assess`` lo invoca per
verificare che la traccia sia completa (AS-05) e che il perimetro rifiuti ciò
che deve rifiutare (AS-06). Se il gate cedesse, a partire sarebbe questo
script: legge il proprio ambiente e lo stampa, **non apre connessioni e non
tocca il bersaglio che riceve**.

È registrato due volte con lo stesso SHA, come ``echo_agent``:
``assess.canary`` senza bersaglio, ``assess.canary_host`` con
``exec_args = ["--bersaglio"]``.

Cosa riporta
------------

Ciò che vede dall'interno, non ciò che è: uid, gruppi, i flag con cui
l'interprete è partito e il ``sys.path`` risultante, la directory corrente,
gli argomenti. Un tool riporta ciò che ha fatto, non chi è — vale anche qui:
non dichiara sotto quale ``tool_id`` è stato invocato, perché non può
saperlo. Lo dice il log.

Solo libreria standard, nessun import del progetto: il gate lo esegue con
``-I -S`` e un ambiente ridotto, come ogni altro tool.
"""

from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path

#: Directory degli esiti nell'unità ristretta del wrapper. Se esiste ed è
#: scrivibile il canary vi lascia una copia di ciò che stampa, così il
#: manifesto nel log ha qualcosa da coprire.
ESITI = Path("/esiti")


def osservazioni(argomenti: list[str]) -> dict[str, object]:
    return {
        "canary": "hermes-assess",
        "args": argomenti,
        "uid": os.getuid(),
        "euid": os.geteuid(),
        "gid": os.getgid(),
        "gruppi": sorted(os.getgroups()),
        "flags": {
            "isolated": sys.flags.isolated,
            "no_site": sys.flags.no_site,
            "no_user_site": sys.flags.no_user_site,
            "ignore_environment": sys.flags.ignore_environment,
        },
        "sys_path": list(sys.path),
        "cwd": os.getcwd(),
        "python": platform.python_version(),
        "eseguibile": sys.executable,
    }


def main(argv: list[str] | None = None) -> int:
    dati = osservazioni(list(argv if argv is not None else sys.argv[1:]))
    testo = json.dumps(dati, ensure_ascii=True, sort_keys=True)
    print(testo)
    if ESITI.is_dir() and os.access(ESITI, os.W_OK):
        (ESITI / "canary.json").write_text(testo + "\n", encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
