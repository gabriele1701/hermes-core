"""Lo schema del referto di hermes-assess: dati non fidati e codici d'uscita."""

from __future__ import annotations

import json

import pytest

from mcp_server.assess.referto import (
    SCHEMA,
    TETTO_NON_FIDATO,
    CodiceUscita,
    EsitoProva,
    Evidenza,
    Referto,
    Voce,
    codice_uscita,
    dato_non_fidato,
    in_json,
)
from mcp_server.contracts import Severity

# --------------------------------------------------------------------------- #
# Dati non fidati
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("grezzo", "atteso"),
    [
        ("riga\nfalsa", "riga\\u000afalsa"),
        ("\x1b[31mrosso", "\\u001b[31mrosso"),
        ("a\u202eb", "a\\u202eb"),  # override destra-sinistra
        ("a\u200bb", "a\\u200bb"),  # spazio a larghezza zero
        ("a\u2028b", "a\\u2028b"),  # separatore di riga Unicode
        ("città/é", "città/é"),  # testo normale non si tocca
    ],
)
def test_i_caratteri_di_controllo_diventano_visibili(grezzo: str, atteso: str):
    assert dato_non_fidato(grezzo) == atteso


def test_il_taglio_e_dichiarato():
    valore = dato_non_fidato("x" * (TETTO_NON_FIDATO + 10))
    assert valore.startswith("x" * TETTO_NON_FIDATO)
    assert valore.endswith("[troncato: 10 caratteri]")


def test_l_evidenza_si_ripulisce_alla_costruzione():
    """L'invariante vale per ogni Evidenza, non solo per quelle stampate."""
    e = Evidenza("leggi", "hermes-tool", "/tmp/a\nb", False, dettaglio="x\x00")
    assert "\n" not in e.oggetto and "\x00" not in e.dettaglio


# --------------------------------------------------------------------------- #
# Codici d'uscita
# --------------------------------------------------------------------------- #


def _voce(esito: EsitoProva, gravita: Severity = Severity.HIGH) -> Voce:
    return Voce("AS-01", esito, gravita, gravita)


def test_i_codici_sono_distinti():
    assert len({c.value for c in CodiceUscita}) == len(CodiceUscita)


@pytest.mark.parametrize(
    ("voci", "atteso"),
    [
        ([], CodiceUscita.NESSUN_CEDIMENTO),
        ([_voce(EsitoProva.TIENE)], CodiceUscita.NESSUN_CEDIMENTO),
        ([_voce(EsitoProva.NON_APPLICABILE)], CodiceUscita.NESSUN_CEDIMENTO),
        ([_voce(EsitoProva.ACCETTATO)], CodiceUscita.NESSUN_CEDIMENTO),
        ([_voce(EsitoProva.CEDE, Severity.LOW)], CodiceUscita.CEDIMENTI),
        (
            [_voce(EsitoProva.NON_VERIFICABILE, Severity.LOW)],
            CodiceUscita.NESSUN_CEDIMENTO,
        ),
        (
            [_voce(EsitoProva.NON_VERIFICABILE, Severity.HIGH)],
            CodiceUscita.ALTE_NON_VERIFICABILI,
        ),
        (
            [_voce(EsitoProva.NON_VERIFICABILE, Severity.CRITICAL)],
            CodiceUscita.ALTE_NON_VERIFICABILI,
        ),
    ],
)
def test_codice_uscita(voci: list[Voce], atteso: CodiceUscita):
    assert codice_uscita(voci) is atteso


def test_un_cedimento_prevale_su_un_non_verificabile():
    """Non è un massimo numerico: è la regola scritta.

    Qui coincidono (1 < 2 ma vince 1): un cedimento è un fatto, un non
    verificabile un'assenza di fatti, e il referto deve portare il fatto.
    """
    voci = [_voce(EsitoProva.NON_VERIFICABILE), _voce(EsitoProva.CEDE, Severity.LOW)]
    assert codice_uscita(voci) is CodiceUscita.CEDIMENTI


def test_conta_la_gravita_nel_contesto_non_quella_di_base():
    voce = Voce("AS-09", EsitoProva.NON_VERIFICABILE, Severity.MEDIUM, Severity.HIGH)
    assert codice_uscita([voce]) is CodiceUscita.ALTE_NON_VERIFICABILI


# --------------------------------------------------------------------------- #
# Serializzazione
# --------------------------------------------------------------------------- #


def test_il_json_e_ascii_e_porta_lo_schema():
    referto = Referto(
        generato="2026-11-18T14:00:00+01:00",
        host="hermesmcp",
        config="/opt/hermes-core/config/hermes.toml",
        commit="72019a6",
        albero_pulito=True,
        voci=(
            Voce(
                "AS-03",
                EsitoProva.TIENE,
                Severity.HIGH,
                Severity.HIGH,
                evidenze=(Evidenza("leggi", "hermes-tool", "/etc/hermes/città", False),),
            ),
        ),
    )
    testo = in_json(referto)
    testo.encode("ascii")
    dati = json.loads(testo)
    assert dati["schema"] == SCHEMA
    assert dati["voci"][0]["esito"] == "tiene"
    assert dati["voci"][0]["evidenze"][0]["oggetto"] == "/etc/hermes/città"
