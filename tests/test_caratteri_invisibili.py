"""Nessun file versionato contiene caratteri invisibili o di direzione.

Un carattere di direzione bidirezionale (U+202A–U+202E, U+2066–U+2069) fa
leggere a chi revisiona un testo diverso da quello che l'interprete esegue:
è la tecnica «Trojan Source» (CVE-2021-42574). Uno a larghezza zero rende
diverse due stringhe che sembrano uguali. Nessuno dei due ha un uso
legittimo nel sorgente di questo repo: dove serve parlarne, si scrive la
sequenza di escape (``"\\u202e"``), che è ASCII e si vede.

Trovato così: il test della pulizia dei dati non fidati, scritto per
verificare che questi caratteri vengano resi visibili nel referto, li
conteneva letteralmente, e GitHub l'ha segnalato alla revisione.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent

_INVISIBILI = frozenset(
    [*range(0x200B, 0x2010), *range(0x202A, 0x202F), *range(0x2066, 0x206A)]
    + [0x2028, 0x2029, 0xFEFF]
)


def _file_versionati() -> list[Path]:
    try:
        uscita = subprocess.run(
            ["git", "-C", str(RADICE), "ls-files", "-z"],
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("non è un checkout git: l'elenco dei file versionati non c'è")
    return [RADICE / nome for nome in uscita.decode().split("\0") if nome]


def test_nessun_carattere_invisibile_nei_file_versionati():
    trovati = []
    for percorso in _file_versionati():
        try:
            testo = percorso.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binario o illeggibile: non è sorgente
        for numero, riga in enumerate(testo.splitlines(), start=1):
            for carattere in riga:
                if ord(carattere) in _INVISIBILI:
                    relativo = percorso.relative_to(RADICE)
                    trovati.append(f"{relativo}:{numero}: U+{ord(carattere):04X}")
    assert not trovati, "\n".join(trovati)
