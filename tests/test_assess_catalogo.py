"""Il catalogo delle minacce di hermes-assess è completo e non promette il falso.

Il catalogo è una dichiarazione: una voce che non dice cosa deve riuscire,
o che manda a un documento che non esiste, produrrà una prova che dimostra
ciò che le riesce di dimostrare. Questi test non verificano le prove — in M0
non esistono — ma che ogni voce sia scritta in modo che una prova possa
esserle fedele.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mcp_server.assess.catalogo import CATALOGO, SEMPRE, Minaccia, Natura, per_id
from mcp_server.contracts import TargetKind

RADICE = Path(__file__).resolve().parent.parent
DEBITO = RADICE / "docs" / "debito-sicurezza.md"

#: Le forme di origine ammesse: finding della security review, debolezze
#: architetturali, difetti del collaudo, decisioni di progetto.
_ORIGINE = re.compile(r"^(HC-0[1-9]|A[1-6]|D-\d{2}|decisione \d{1,2})$")

#: Percorsi del repo citati nei testi: devono esistere.
_PERCORSO = re.compile(r"\b((?:docs|bin|config|mcp_server|agents)/[\w./-]*\w)")

#: Intestazioni del registro del debito che una voce può citare.
_INTESTAZIONE = re.compile(r"^## ((?:MEDIA|ALTA|ACCETTATA) — .+)$", re.MULTILINE)


def _voci() -> list[pytest.param]:
    return [pytest.param(m, id=m.id) for m in CATALOGO]


def test_gli_id_sono_progressivi_e_unici():
    attesi = [f"AS-{n:02d}" for n in range(1, len(CATALOGO) + 1)]
    assert [m.id for m in CATALOGO] == attesi
    assert len(per_id()) == len(CATALOGO)


@pytest.mark.parametrize("minaccia", _voci())
def test_i_campi_testuali_non_sono_vuoti(minaccia: Minaccia):
    for nome in ("titolo", "prova", "applicabile_se", "effetti", "rimedio"):
        valore = getattr(minaccia, nome)
        assert valore.strip(), f"{minaccia.id}: {nome} vuoto"
    assert minaccia.origine, f"{minaccia.id}: origine vuota"


@pytest.mark.parametrize("minaccia", _voci())
def test_l_origine_e_in_una_forma_riconosciuta(minaccia: Minaccia):
    for origine in minaccia.origine:
        assert _ORIGINE.fullmatch(origine), f"{minaccia.id}: origine {origine!r}"


@pytest.mark.parametrize("minaccia", _voci())
def test_un_tentativo_ha_il_suo_controllo_positivo(minaccia: Minaccia):
    """Un rifiuto senza controllo positivo non prova niente.

    È la regola di bin/hermes-collauda-percorsi: il file potrebbe non aprirsi
    comunque. E una misura deve dire perché non è un tentativo, altrimenti è
    un controllo del preflight con un altro nome.
    """
    if minaccia.natura is Natura.TENTATIVO:
        assert minaccia.controllo_positivo and minaccia.controllo_positivo.strip()
        assert minaccia.perche_misura is None
    else:
        assert minaccia.perche_misura and minaccia.perche_misura.strip()
        assert minaccia.controllo_positivo is None


@pytest.mark.parametrize("minaccia", _voci())
def test_una_prova_indiretta_e_un_tentativo(minaccia: Minaccia):
    """Indiretta vuol dire «tentata su un'esca»: una misura non tenta niente."""
    if minaccia.indiretta:
        assert minaccia.natura is Natura.TENTATIVO


@pytest.mark.parametrize("minaccia", _voci())
def test_i_percorsi_citati_esistono(minaccia: Minaccia):
    """Un rimedio che nomina ciò che non esiste manda a cercare un guasto
    diverso da quello che si ha."""
    testi = [minaccia.prova, minaccia.effetti, minaccia.rimedio]
    for testo in testi:
        for percorso in _PERCORSO.findall(testo):
            assert (RADICE / percorso).exists(), f"{minaccia.id}: {percorso}"


@pytest.mark.parametrize("minaccia", _voci())
def test_il_debito_citato_e_una_voce_del_registro(minaccia: Minaccia):
    if minaccia.debito is None:
        pytest.skip("nessun debito citato")
    intestazioni = set(_INTESTAZIONE.findall(DEBITO.read_text(encoding="utf-8")))
    assert minaccia.debito in intestazioni, (
        f"{minaccia.id}: {minaccia.debito!r} non è un'intestazione di "
        f"docs/debito-sicurezza.md — se la voce è stata chiusa, la minaccia "
        f"non va più ricondotta al debito"
    )


def test_le_intestazioni_del_registro_sono_lette():
    """Se il formato del registro cambia, il test sopra passerebbe a vuoto."""
    assert len(_INTESTAZIONE.findall(DEBITO.read_text(encoding="utf-8"))) >= 5


def test_ogni_tipo_di_bersaglio_ha_una_prova_del_perimetro():
    """Nessun kind senza prova, come nessun kind senza validatore.

    Un TargetKind aggiunto al contratto senza una minaccia che ne eserciti il
    perimetro sarebbe un perimetro che nessuno ha mai visto dire no.
    """
    coperti = set().union(*(m.target_kind for m in CATALOGO))
    assert coperti == set(TargetKind)


def test_sempre_e_un_valore_e_non_una_frase_libera():
    """«sempre» si scrive con la costante: una variante («Sempre», «sempre.»)
    sarebbe letta in M1 come una condizione da valutare."""
    for m in CATALOGO:
        if m.applicabile_se.strip().lower().rstrip(".") == SEMPRE:
            assert m.applicabile_se == SEMPRE, m.id
