"""Test del gate delle sospensioni di `pip-audit`.

Lo script decide se un presidio bloccante si ferma o lascia passare: è
esattamente il genere di codice che non può essere verificato solo dal fatto
che «in CI è verde», perché in CI è verde anche quando non guarda niente.

Le funzioni misurate sono pure di proposito — leggere le righe e decidere
quali sono scadute — così si possono provare senza eseguire `pip-audit` né
costruire un ambiente.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
from pathlib import Path

import pytest

_SCRIPT = (
    Path(__file__).resolve().parent.parent
    / ".github"
    / "scripts"
    / "audit_con_sospensioni.py"
)


def _modulo():
    spec = importlib.util.spec_from_file_location("audit_sospensioni", _SCRIPT)
    assert spec and spec.loader
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


mod = _modulo()

VALIDA = (
    "PYSEC-2026-1234 | transitiva di mcp, raggiungibile solo dal trasporto "
    "HTTP che questo server non usa | 2026-12-31"
)


def test_il_file_versionato_non_ha_sospensioni_attive():
    """Il file del repo deve restare vuoto finché non serve davvero.

    Se un giorno questo test cade, qualcuno ha sospeso qualcosa — ed è
    giusto che la cosa si veda qui e non solo in un file che nessuno apre.
    """
    sospensioni, errori = mod.leggi_sospensioni(
        mod.SOSPESE.read_text(encoding="utf-8")
    )
    assert errori == []
    assert sospensioni == [], f"sospensioni attive: {sospensioni}"


def test_riga_valida_letta_nei_tre_campi():
    sospensioni, errori = mod.leggi_sospensioni(VALIDA)
    assert errori == []
    (ident, motivo, data), = sospensioni
    assert ident == "PYSEC-2026-1234"
    assert "trasporto" in motivo
    assert data == dt.date(2026, 12, 31)


def test_commenti_e_righe_vuote_ignorati():
    sospensioni, errori = mod.leggi_sospensioni("# un commento\n\n   \n")
    assert (sospensioni, errori) == ([], [])


@pytest.mark.parametrize(
    "riga, atteso",
    [
        ("PYSEC-2026-1234 | manca la data", "tre campi"),
        ("boh | " + "x" * 30 + " | 2026-12-31", "non è un identificativo"),
        ("CVE-2026-1 | non ci riguarda | 2026-12-31", "almeno"),
        ("CVE-2026-1 | " + "x" * 30 + " | fra un po'", "non è una data"),
    ],
    ids=["campi-mancanti", "id-inventato", "motivo-troppo-corto", "data-illeggibile"],
)
def test_righe_non_valide_riportate(riga: str, atteso: str):
    """Ogni campo obbligatorio deve essere davvero obbligatorio.

    L'identificativo inventato è il caso meno ovvio: `pip-audit` lo
    ignorerebbe senza dire niente, e la riga sembrerebbe comunque fatta.
    """
    sospensioni, errori = mod.leggi_sospensioni(riga)
    assert sospensioni == []
    assert any(atteso in e for e in errori), errori


def test_tutte_le_righe_sbagliate_riportate_insieme():
    """Non fermarsi alla prima: su una CI ogni giro costa minuti."""
    _, errori = mod.leggi_sospensioni("boh | corto | mai\nancora | peggio\n")
    assert len(errori) >= 3


def test_sospensione_scaduta_riconosciuta():
    oggi = dt.date(2026, 12, 31)
    vecchie = mod.scadute([("CVE-2026-1", "motivo", dt.date(2026, 12, 30))], oggi)
    assert [v[0] for v in vecchie] == ["CVE-2026-1"]


def test_il_giorno_della_scadenza_vale_ancora():
    """Il confine va fissato: altrimenti lo fissa un fuso orario."""
    oggi = dt.date(2026, 12, 31)
    assert mod.scadute([("CVE-2026-1", "motivo", oggi)], oggi) == []
