"""L'adattatore per il referto di lynis: solo i gruppi concordati, nessuna fiducia nel file."""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

from mcp_server.assess import giro, lynis
from mcp_server.assess.prove import Prova, Risultato
from mcp_server.assess.referto import CodiceUscita, EsitoProva, codice_uscita

ADESSO = _dt.datetime(2026, 11, 18, 16, 0, 0)

REFERTO = """\
# Lynis Report
lynis_version=3.1.1
report_datetime_start=2026-11-18 15:00:00
warning[]=SSH-7408|Configurazione di SSH da rivedere|MaxAuthTries|-|
suggestion[]=AUTH-9230|Configure password hashing rounds|-|-|
suggestion[]=KRNL-6000|Fuori dai gruppi concordati|-|-|
suggestion[]=non-un-codice|riga malformata|-|-|
suggestion[]=SSH-7440|
hardening_index=64
"""


def test_solo_i_gruppi_ssh_e_auth():
    voci = lynis.interpreta(REFERTO, adesso=ADESSO).voci
    assert [v.test for v in voci] == ["SSH-7408", "AUTH-9230"]
    assert voci[0].tipo == "avviso" and voci[1].tipo == "suggerimento"


def test_origine_con_la_versione_dichiarata():
    voci = lynis.interpreta(REFERTO, adesso=ADESSO).voci
    assert {v.origine for v in voci} == {"lynis 3.1.1"}


def test_i_trattini_sono_campi_vuoti():
    v = lynis.interpreta(REFERTO, adesso=ADESSO).voci[1]
    assert v.dettaglio == "" and v.soluzione == ""


def test_le_righe_malformate_si_contano_non_si_inventano():
    limiti = lynis.interpreta(REFERTO, adesso=ADESSO).limiti
    assert any("2 righe di segnalazione senza la forma attesa" in l for l in limiti)


def test_il_perimetro_della_lettura_e_dichiarato():
    limiti = lynis.interpreta(REFERTO, adesso=ADESSO).limiti
    assert any("SSH-*, AUTH-*" in l for l in limiti)


def test_un_audit_vecchio_si_dice_e_non_si_scarta():
    vecchio = REFERTO.replace("2026-11-18 15:00:00", "2026-10-01 09:00:00")
    lettura = lynis.interpreta(vecchio, adesso=ADESSO)
    assert lettura.voci
    assert any("giorni fa" in l for l in lettura.limiti)


def test_i_campi_del_file_sono_dati_non_fidati():
    sporco = "lynis_version=3\x1b[2J\nsuggestion[]=SSH-7408|riga\u202efalsa|-|-|\n"
    v = lynis.interpreta(sporco, adesso=ADESSO).voci[0]
    assert "\u202e" not in v.messaggio and "\x1b" not in v.origine


def test_referto_assente_e_non_applicabile(tmp_path: Path):
    lettura = lynis.leggi(tmp_path / "lynis-report.dat")
    assert lettura.voci == ()
    assert "non applicabile" in lettura.limiti[0]


def test_referto_letto_da_file(tmp_path: Path):
    f = tmp_path / "lynis-report.dat"
    f.write_text(REFERTO)
    assert len(lynis.leggi(f).voci) == 2


def test_le_voci_esterne_non_cambiano_il_codice_d_uscita(tmp_path: Path):
    """Una segnalazione di lynis non è un cedimento di una prova."""
    f = tmp_path / "lynis-report.dat"
    f.write_text(REFERTO)
    ctx = type("Ctx", (), {"root": True, "repo": tmp_path, "config_path": tmp_path / "c"})()
    prove = {"AS-05": Prova("AS-05", lambda c: None, lambda c: Risultato(EsitoProva.TIENE))}
    referto = giro.esegui(ctx, prove=prove, referto_lynis=f)
    assert len(referto.esterne) == 2
    assert codice_uscita(referto.voci) is CodiceUscita.NESSUN_CEDIMENTO
