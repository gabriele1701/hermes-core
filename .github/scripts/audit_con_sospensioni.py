#!/usr/bin/env python3
"""Esegue `pip-audit` sul lockfile, onorando le sospensioni scritte.

Perché non basta `pip-audit -r requirements.txt`
-------------------------------------------------

Un controllo bloccante su cui non si può fare nulla viene disattivato. Una
CVE in una dipendenza transitiva senza correzione a monte fermerebbe tutto il
lavoro, compreso quello che la correggerebbe, e la via d'uscita comoda —
`|| true` nel workflow — spegne il controllo per sempre e in silenzio.

Qui la via d'uscita esiste ma costa: una riga in
`.github/pip-audit-sospese.txt` con tre cose obbligatorie, l'identificativo,
**perché** non ci riguarda, e **quando** va riesaminata. Senza una delle tre
questo script fallisce; con una data passata, pure.

Una sospensione senza scadenza diventa permanente senza che nessuno lo
decida. Con la scadenza, il silenzio costa una riga da riscrivere, e chi la
riscrive deve guardarla di nuovo.
"""

from __future__ import annotations

import datetime as dt
import re
import subprocess
import sys
from pathlib import Path

RADICE = Path(__file__).resolve().parents[2]
LOCKFILE = RADICE / "requirements.txt"
SOSPESE = RADICE / ".github" / "pip-audit-sospese.txt"

#: Identificativi riconosciuti. Un nome inventato non deve passare per una
#: sospensione valida: `pip-audit` lo ignorerebbe senza dire niente, e la
#: riga sembrerebbe comunque fatta.
_ID = re.compile(r"^(GHSA-[0-9a-z-]+|PYSEC-\d{4}-\d+|CVE-\d{4}-\d+)$")

#: Una motivazione deve essere una frase, non un'alzata di spalle.
_MOTIVO_MINIMO = 25


def leggi_sospensioni(testo: str) -> tuple[list[tuple[str, str, dt.date]], list[str]]:
    """`(sospensioni, errori)`: non si ferma alla prima riga sbagliata.

    Riportarle tutte insieme evita il giro «correggi, rilancia, scopri la
    successiva», che su una CI costa minuti per ogni riga.
    """
    sospensioni: list[tuple[str, str, dt.date]] = []
    errori: list[str] = []

    for numero, riga in enumerate(testo.splitlines(), start=1):
        riga = riga.strip()
        if not riga or riga.startswith("#"):
            continue

        campi = [c.strip() for c in riga.split("|")]
        if len(campi) != 3:
            errori.append(
                f"riga {numero}: servono tre campi separati da '|' "
                f"(identificativo | motivo | AAAA-MM-GG), trovati {len(campi)}"
            )
            continue

        ident, motivo, scadenza = campi
        valida = True

        if not _ID.match(ident):
            errori.append(
                f"riga {numero}: '{ident}' non è un identificativo "
                "GHSA-…, PYSEC-… o CVE-…"
            )
            valida = False
        if len(motivo) < _MOTIVO_MINIMO:
            errori.append(
                f"riga {numero}: la motivazione è di {len(motivo)} caratteri. "
                f"Ne servono almeno {_MOTIVO_MINIMO}: deve dire perché questa "
                "CVE non è sfruttabile qui, o perché non è correggibile."
            )
            valida = False
        try:
            data = dt.date.fromisoformat(scadenza)
        except ValueError:
            errori.append(
                f"riga {numero}: '{scadenza}' non è una data AAAA-MM-GG"
            )
            continue

        # Solo le righe intere entrano nell'elenco. Restituire insieme «è
        # sbagliata» e «eccola, usala» è una trappola: oggi `main` si ferma
        # agli errori, ma basta che un domani diventino un avviso perché una
        # riga malformata si trasformi in una sospensione attiva, in
        # silenzio. Trovato da un test, non dall'uso.
        if valida:
            sospensioni.append((ident, motivo, data))

    return sospensioni, errori


def scadute(
    sospensioni: list[tuple[str, str, dt.date]], oggi: dt.date
) -> list[tuple[str, str, dt.date]]:
    """Le sospensioni da riesaminare. Il giorno stesso vale ancora."""
    return [s for s in sospensioni if s[2] < oggi]


def main() -> int:
    if not LOCKFILE.exists():
        print(f"lockfile assente: {LOCKFILE}", file=sys.stderr)
        return 1

    testo = SOSPESE.read_text(encoding="utf-8") if SOSPESE.exists() else ""
    sospensioni, errori = leggi_sospensioni(testo)

    if errori:
        print(f"{SOSPESE.name}: righe non valide", file=sys.stderr)
        for errore in errori:
            print(f"  {errore}", file=sys.stderr)
        print(
            "\nUna sospensione senza motivo o senza scadenza è un controllo "
            "spento travestito da eccezione.",
            file=sys.stderr,
        )
        return 1

    vecchie = scadute(sospensioni, dt.date.today())
    if vecchie:
        print("sospensioni da riesaminare (la data è passata):", file=sys.stderr)
        for ident, motivo, data in vecchie:
            print(f"  {ident}  scaduta il {data}  — {motivo}", file=sys.stderr)
        print(
            "\nRiesaminarle e spostare la data, oppure toglierle se la CVE è "
            "stata corretta a monte. Non spostare la data senza guardare.",
            file=sys.stderr,
        )
        return 1

    argv = [
        sys.executable,
        "-m",
        "pip_audit",
        "--requirement",
        str(LOCKFILE),
        # Il lockfile è completamente fissato: non serve che pip risolva
        # niente, e non risolvere niente significa non scaricare niente.
        "--disable-pip",
        "--strict",
    ]
    for ident, _, _ in sospensioni:
        argv += ["--ignore-vuln", ident]

    if sospensioni:
        print(f"sospensioni attive: {len(sospensioni)}")
        for ident, motivo, data in sospensioni:
            print(f"  {ident}  da riesaminare entro {data}  — {motivo}")
        print()

    return subprocess.run(argv, check=False).returncode  # noqa: S603


if __name__ == "__main__":
    raise SystemExit(main())
