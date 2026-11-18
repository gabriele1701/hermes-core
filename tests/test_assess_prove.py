"""Le regole delle prove di hermes-assess, senza root e senza systemd.

Le prove si vedono cedere qui con evidenze costruite; sulla macchina vera si
vedono cedere provocando il guasto (docs/assess.md, piano).
"""

from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from mcp_server.assess import giro
from mcp_server.assess.catalogo import per_id
from mcp_server.assess.catena import Invocazione
from mcp_server.assess.prove import Prova, Risultato, da_evidenze, registro
from mcp_server.assess.prove import as03, as05, as06
from mcp_server.assess.referto import EsitoProva, Evidenza
from mcp_server.contracts import AgentResult
from mcp_server.esiti import manifesto
from mcp_server.scope import ScopeAllowlist


def _ev(riuscita: bool, *, positivo: bool = False, eseguita: bool = True, oggetto="/f"):
    return Evidenza("leggi", "t", oggetto, riuscita, controllo_positivo=positivo, eseguita=eseguita)


# --------------------------------------------------------------------------- #
# La regola dei tentativi
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("positivi", "negativi", "atteso"),
    [
        ([_ev(True, positivo=True)], [_ev(False)], EsitoProva.TIENE),
        ([_ev(True, positivo=True)], [_ev(True)], EsitoProva.CEDE),
        ([_ev(False, positivo=True)], [_ev(False)], EsitoProva.NON_VERIFICABILE),
        ([_ev(True, positivo=True)], [_ev(False, eseguita=False)], EsitoProva.NON_VERIFICABILE),
        # Un fatto vale più di un'assenza di fatti.
        ([_ev(False, positivo=True)], [_ev(True), _ev(False, eseguita=False)], EsitoProva.CEDE),
        ([], [], EsitoProva.NON_VERIFICABILE),
    ],
    ids=["tiene", "cede", "positivo-fallito", "sonda-muta", "cede-prevale", "nessun-tentativo"],
)
def test_da_evidenze(positivi, negativi, atteso):
    assert da_evidenze(positivi, negativi).esito is atteso


# --------------------------------------------------------------------------- #
# AS-03, con sonde finte
# --------------------------------------------------------------------------- #


@pytest.fixture()
def ctx_as03(tmp_path: Path):
    config = tmp_path / "hermes.toml"
    log = tmp_path / "audit.jsonl"
    stato = tmp_path / "stato"
    for f in (config, log):
        f.write_text("")
    stato.mkdir()
    (stato / "overrides.jsonl").write_text("")
    cfg = SimpleNamespace(
        log_path=log, state_dir=stato, tool_runner=Path("/w"), vault=SimpleNamespace(backend="stub")
    )
    return SimpleNamespace(cfg=cfg, config_path=config, utente_servizio="hermes", scende_di_identita=True)


def test_as03_prova_quattro_file(ctx_as03):
    assert [op for op, _ in as03.bersagli(ctx_as03)] == ["leggi", "apri_scrittura", "crea", "leggi"]


def test_as03_tiene_se_il_wrapper_e_rifiutato(ctx_as03):
    r = as03.esegui(
        ctx_as03,
        come=lambda ctx, u, op, p, controllo_positivo: _ev(True, positivo=True, oggetto=str(p)),
        dal_wrapper=lambda ctx, op, p: _ev(False, oggetto=str(p)),
    )
    assert r.esito is EsitoProva.TIENE
    assert len(r.evidenze) == 8


def test_as03_cede_se_il_tool_legge_lo_store(ctx_as03):
    store = ctx_as03.cfg.state_dir / "overrides.jsonl"
    r = as03.esegui(
        ctx_as03,
        come=lambda ctx, u, op, p, controllo_positivo: _ev(True, positivo=True, oggetto=str(p)),
        dal_wrapper=lambda ctx, op, p: _ev(p == store, oggetto=str(p)),
    )
    assert r.esito is EsitoProva.CEDE
    assert str(store) in r.nota


def test_as03_non_applicabile_senza_wrapper_o_senza_root(ctx_as03):
    assert as03.applicabile(ctx_as03) is None
    ctx_as03.scende_di_identita = False
    assert "root" in as03.applicabile(ctx_as03)
    ctx_as03.cfg.tool_runner = None
    assert "tool_runner" in as03.applicabile(ctx_as03)


# --------------------------------------------------------------------------- #
# Risultati della catena, costruiti
# --------------------------------------------------------------------------- #


def _inv(status: str, tool_id="assess.canary", target=None, cid=None) -> Invocazione:
    esito_call = {"ok": "ok", "denied": "denied", "error": "error"}[status]
    calls = [{
        "tool_id": tool_id, "target": target, "tier_effective": "verde",
        "authorized_by": "none" if status == "denied" else "policy", "outcome": esito_call,
    }]
    result = AgentResult.model_validate({
        "correlation_id": str(cid or uuid.uuid4()), "agent": "echo_dummy",
        "status": status, "summary": f"esito {status}", "tool_calls": calls,
    })
    return Invocazione(tool_id, target, result, {"stdout": ""})


def _righe(cid, *azioni, detail=""):
    return [{"correlation_id": str(cid), "action": a, "detail": detail} for a in azioni]


def test_as05_tiene_con_le_tre_righe():
    inv = _inv("ok")
    cid = inv.result.correlation_id
    r = as05.valuta(inv, _righe(cid, "agent_invoked", "tool_call", "agent_result"))
    assert r.esito is EsitoProva.TIENE


def test_as05_cede_se_manca_la_riga_tool_call():
    """È HC-01: lo script ha girato, la traccia no."""
    inv = _inv("ok")
    r = as05.valuta(inv, _righe(inv.result.correlation_id, "agent_invoked", "agent_result"))
    assert r.esito is EsitoProva.CEDE
    assert "tool_call" in r.nota


def test_as05_non_verificabile_se_il_canary_non_e_andato():
    assert as05.valuta(_inv("error"), []).esito is EsitoProva.NON_VERIFICABILE


def test_as05_confronta_il_manifesto(tmp_path: Path):
    inv = _inv("ok")
    cid = inv.result.correlation_id
    (tmp_path / str(cid)).mkdir()
    (tmp_path / str(cid) / "canary.json").write_text("{}\n")
    giusto = manifesto(tmp_path / str(cid)).sha256
    tre = ("agent_invoked", "tool_call", "agent_result")

    ok = as05.valuta(inv, _righe(cid, *tre, detail=f"esiti: 1 file, 3 byte, manifesto sha256:{giusto}"),
                     esiti=tmp_path)
    assert ok.esito is EsitoProva.TIENE

    (tmp_path / str(cid) / "canary.json").write_text("{manomesso}\n")
    ko = as05.valuta(inv, _righe(cid, *tre, detail=f"manifesto sha256:{giusto}"), esiti=tmp_path)
    assert ko.esito is EsitoProva.CEDE


def test_as06_tiene_con_due_rifiuti_e_il_positivo():
    r = as06.valuta(_inv("denied"), _inv("denied", "assess.canary_host"), _inv("ok", "assess.canary_host"))
    assert r.esito is EsitoProva.TIENE


@pytest.mark.parametrize("quale", [0, 1])
def test_as06_cede_se_un_canary_parte(quale):
    invocazioni = [_inv("denied"), _inv("denied", "assess.canary_host")]
    invocazioni[quale] = _inv("ok", invocazioni[quale].tool_id)
    r = as06.valuta(*invocazioni, _inv("ok", "assess.canary_host"))
    assert r.esito is EsitoProva.CEDE


def test_as06_i_rifiuti_senza_positivo_non_provano_niente():
    r = as06.valuta(_inv("denied"), _inv("denied", "assess.canary_host"), _inv("denied", "assess.canary_host"))
    assert r.esito is EsitoProva.NON_VERIFICABILE


def test_as06_un_errore_non_e_un_rifiuto():
    r = as06.valuta(_inv("error"), _inv("denied", "assess.canary_host"), _inv("ok", "assess.canary_host"))
    assert r.esito is EsitoProva.NON_VERIFICABILE


def _perimetro(tmp_path: Path, reti: list[str]) -> ScopeAllowlist:
    f = tmp_path / "scope.toml"
    f.write_text("reti = [" + ", ".join(f'"{r}"' for r in reti) + "]\n")
    return ScopeAllowlist.carica(f)


def test_as06_salta_le_reti_di_documentazione_dentro_il_perimetro(tmp_path: Path):
    fuori, dentro = as06.scegli_bersagli(_perimetro(tmp_path, ["192.0.2.0/24", "10.0.0.0/24"]))
    assert fuori == "198.51.100.1"
    assert dentro == "192.0.2.1"


def test_as06_non_inventa_un_indirizzo(tmp_path: Path):
    reti = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]
    fuori, _ = as06.scegli_bersagli(_perimetro(tmp_path, reti))
    assert fuori is None


# --------------------------------------------------------------------------- #
# Il giro
# --------------------------------------------------------------------------- #


def _prova(id_, *, applicabile=None, esegui=None):
    return Prova(id_, lambda ctx: applicabile, esegui or (lambda ctx: Risultato(EsitoProva.TIENE)))


def test_le_prove_registrate_sono_voci_del_catalogo():
    assert set(registro()) <= set(per_id())


def test_una_prova_non_applicabile_dice_perche():
    v = giro.voce(per_id()["AS-03"], _prova("AS-03", applicabile="manca il wrapper"), None)
    assert v.esito is EsitoProva.NON_APPLICABILE and v.nota == "manca il wrapper"


def test_una_prova_che_solleva_non_ferma_il_giro():
    def rotta(ctx):
        raise RuntimeError("kaputt")

    v = giro.voce(per_id()["AS-05"], _prova("AS-05", esegui=rotta), None)
    assert v.esito is EsitoProva.NON_VERIFICABILE
    assert "RuntimeError: kaputt" in v.nota


def test_un_cedimento_contro_debito_aperto_resta_cedimento_col_rimando():
    m = per_id()["AS-09"]  # debito MEDIA
    v = giro.voce(m, _prova("AS-09", esegui=lambda ctx: Risultato(EsitoProva.CEDE, nota="connesso")), None)
    assert v.esito is EsitoProva.CEDE
    assert m.debito in v.nota


def test_un_cedimento_contro_debito_accettato_e_accettato():
    from dataclasses import replace

    m = replace(per_id()["AS-09"], debito="ACCETTATA — il registro si fida della propria configurazione")
    v = giro.voce(m, _prova("AS-09", esegui=lambda ctx: Risultato(EsitoProva.CEDE)), None)
    assert v.esito is EsitoProva.ACCETTATO
