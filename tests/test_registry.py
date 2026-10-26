"""Test del registro dei tool (M0 passo 4).

Il registro è il punto in cui la semantica di tier e override diventa
eseguibile. I test insistono su ciò che deve essere **impossibile**:
declassare un tier, ri-registrare un tool con metadati più laschi, invocare
il tool di un altro agente, far entrare una spec senza tier.
"""

from __future__ import annotations

import uuid

import pytest

from mcp_server.audit import AuditLog, LogAction
from mcp_server.contracts import CallOutcome, OwnerAgent, RiskTier, ToolSpec
from mcp_server.overrides import OverrideScope, OverrideStore
from mcp_server.registry import (
    CHIAVE_OVERRIDE,
    InvocationRefused,
    OverrideRefused,
    ToolAlreadyRegistered,
    ToolNotRegistered,
    ToolRegistry,
    ToolSpecRejected,
)
from mcp_server.tiers import ConfirmationCadence

SHA = "a" * 64


def _payload(**override) -> dict:
    base = {
        "tool_id": "echo.ping",
        "owner_agent": OwnerAgent.ECHO_DUMMY,
        "default_tier": RiskTier.VERDE,
        "personal_data": False,
        "requires_container": False,
        "exec_path": "agents/echo_agent/run.py",
        "exec_sha256": SHA,
        "description": "Tool dummy.",
    }
    return base | override


def _spec(**override) -> ToolSpec:
    return ToolSpec(**_payload(**override))


@pytest.fixture()
def audit(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture()
def reg(audit: AuditLog) -> ToolRegistry:
    return ToolRegistry(audit)


def _azioni(audit: AuditLog) -> list[LogAction]:
    return [r.action for r in audit.read_all()]


# --------------------------------------------------------------------------- #
# Registrazione
# --------------------------------------------------------------------------- #


def test_registra_e_ritrova(reg: ToolRegistry):
    spec = reg.register(_spec())
    assert reg.spec("echo.ping") is spec
    assert "echo.ping" in reg
    assert len(reg) == 1


def test_registrazione_loggata(reg: ToolRegistry, audit: AuditLog):
    reg.register(_spec())
    righe = audit.read_all()
    assert [r.action for r in righe] == [LogAction.TOOL_REGISTERED]
    assert righe[0].tool_id == "echo.ping"
    assert righe[0].tier_effective is RiskTier.VERDE
    assert righe[0].outcome is CallOutcome.OK


def test_tool_sconosciuto_solleva(reg: ToolRegistry):
    """Solleva invece di restituire None: un None invita a saltare i controlli."""
    with pytest.raises(ToolNotRegistered):
        reg.spec("mai.registrato")
    with pytest.raises(ToolNotRegistered):
        reg.effective_tier("mai.registrato")
    with pytest.raises(ToolNotRegistered):
        reg.policy_for("mai.registrato")


def test_duplicato_rifiutato(reg: ToolRegistry, audit: AuditLog):
    """Ri-registrare e' la via piu' comoda per aggirare la regola sull'override."""
    reg.register(_spec(default_tier=RiskTier.ROSSO))
    with pytest.raises(ToolAlreadyRegistered):
        reg.register(_spec(default_tier=RiskTier.VERDE))
    # La spec originale resta, col suo tier.
    assert reg.spec("echo.ping").default_tier is RiskTier.ROSSO
    assert reg.effective_tier("echo.ping") is RiskTier.ROSSO
    assert LogAction.TOOL_REGISTRATION_REJECTED in _azioni(audit)


def test_registro_non_espone_deregistrazione(reg: ToolRegistry):
    """Append-only: aggiornare un tool significa cambiare config e riavviare."""
    for vietato in ("unregister", "deregister", "remove", "clear", "pop", "replace"):
        assert not hasattr(reg, vietato)


def test_viste_in_sola_lettura(reg: ToolRegistry):
    reg.register(_spec())
    with pytest.raises(TypeError):
        reg.tools["altro"] = _spec(tool_id="altro.tool")  # type: ignore[index]
    with pytest.raises(TypeError):
        reg.overrides["echo.ping"] = RiskTier.VERDE  # type: ignore[index]


# --------------------------------------------------------------------------- #
# Payload non conformi
# --------------------------------------------------------------------------- #


def test_payload_senza_tier_rifiutato_e_loggato(reg: ToolRegistry, audit: AuditLog):
    """Definition of done: nessun tier -> nessuna registrazione, con traccia."""
    payload = _payload()
    del payload["default_tier"]
    with pytest.raises(ToolSpecRejected):
        reg.register_payload(payload)
    assert len(reg) == 0
    righe = audit.read_all()
    assert righe[0].action is LogAction.TOOL_REGISTRATION_REJECTED
    assert righe[0].outcome is CallOutcome.DENIED
    assert "default_tier" in righe[0].detail


@pytest.mark.parametrize(
    "guasto",
    [
        {"default_tier": "arancione"},
        {"exec_path": "../../etc/passwd"},
        {"exec_path": "/usr/bin/nmap"},
        {"exec_sha256": "non-un-hash"},
        {"tool_id": "Echo.Ping"},
        {"confirmation_policy": "nessuna"},
    ],
)
def test_payload_malformati_rifiutati(reg: ToolRegistry, audit: AuditLog, guasto: dict):
    with pytest.raises(ToolSpecRejected):
        reg.register_payload(_payload(**guasto))
    assert len(reg) == 0
    assert _azioni(audit) == [LogAction.TOOL_REGISTRATION_REJECTED]


def test_tool_id_non_fidato_troncato_nel_log(reg: ToolRegistry, audit: AuditLog):
    """Il payload è per definizione non conforme: il valore va trattato come tale."""
    with pytest.raises(ToolSpecRejected):
        reg.register_payload(_payload(tool_id="x" * 500))
    registrato = audit.read_all()[0].tool_id
    assert registrato is not None and len(registrato) <= 64


def test_tool_id_non_stringa_non_rompe_il_log(reg: ToolRegistry, audit: AuditLog):
    with pytest.raises(ToolSpecRejected):
        reg.register_payload(_payload(tool_id={"iniezione": True}))
    assert audit.read_all()[0].tool_id is None


# --------------------------------------------------------------------------- #
# Tier effettivo e override
# --------------------------------------------------------------------------- #


def test_tier_effettivo_senza_override_e_il_dichiarato(reg: ToolRegistry):
    reg.register(_spec(default_tier=RiskTier.GIALLO))
    assert reg.effective_tier("echo.ping") is RiskTier.GIALLO


def test_override_innalza(reg: ToolRegistry):
    reg.register(_spec(default_tier=RiskTier.VERDE))
    assert reg.set_override("echo.ping", RiskTier.ROSSO) is RiskTier.ROSSO
    assert reg.effective_tier("echo.ping") is RiskTier.ROSSO


def test_override_non_muta_la_spec(reg: ToolRegistry):
    """Il tier dichiarato resta ispezionabile: distingue 'era rischioso' da 'l'ho alzato io'."""
    spec = reg.register(_spec(default_tier=RiskTier.VERDE))
    reg.set_override("echo.ping", RiskTier.ROSSO)
    assert spec.default_tier is RiskTier.VERDE
    assert reg.spec("echo.ping").default_tier is RiskTier.VERDE
    assert reg.overrides["echo.ping"] is RiskTier.ROSSO


@pytest.mark.parametrize(
    ("default", "richiesto"),
    [
        (RiskTier.ROSSO, RiskTier.GIALLO),
        (RiskTier.ROSSO, RiskTier.VERDE),
        (RiskTier.GIALLO, RiskTier.VERDE),
    ],
)
def test_declassamento_rifiutato(
    reg: ToolRegistry, audit: AuditLog, default: RiskTier, richiesto: RiskTier
):
    """Abbassare un tier equivarrebbe a disattivare un controllo."""
    reg.register(_spec(default_tier=default))
    with pytest.raises(OverrideRefused):
        reg.set_override("echo.ping", richiesto)
    assert reg.effective_tier("echo.ping") is default
    assert "echo.ping" not in reg.overrides
    assert LogAction.OVERRIDE_REJECTED in _azioni(audit)


def test_declassamento_dopo_innalzamento_rifiutato(reg: ToolRegistry):
    """Nemmeno tornando al tier dichiarato: l'effettivo non scende."""
    reg.register(_spec(default_tier=RiskTier.VERDE))
    reg.set_override("echo.ping", RiskTier.ROSSO)
    with pytest.raises(OverrideRefused):
        reg.set_override("echo.ping", RiskTier.VERDE)
    assert reg.effective_tier("echo.ping") is RiskTier.ROSSO


def test_override_uguale_idempotente(reg: ToolRegistry):
    reg.register(_spec(default_tier=RiskTier.GIALLO))
    assert reg.set_override("echo.ping", RiskTier.GIALLO) is RiskTier.GIALLO
    assert reg.set_override("echo.ping", RiskTier.GIALLO) is RiskTier.GIALLO
    assert reg.effective_tier("echo.ping") is RiskTier.GIALLO


def test_tier_effettivo_monotono_non_decrescente(reg: ToolRegistry):
    """L'invariante del registro, provato su una sequenza di tentativi."""
    reg.register(_spec(default_tier=RiskTier.VERDE))
    osservati = [reg.effective_tier("echo.ping").rank]
    for tier in (RiskTier.GIALLO, RiskTier.VERDE, RiskTier.ROSSO, RiskTier.GIALLO):
        try:
            reg.set_override("echo.ping", tier)
        except OverrideRefused:
            pass
        osservati.append(reg.effective_tier("echo.ping").rank)
    assert osservati == sorted(osservati)
    assert osservati[-1] == RiskTier.ROSSO.rank


def test_override_piu_basso_nello_store_resta_inerte(audit: AuditLog, tmp_path):
    """Secondo presidio: il max() scarta un override basso anche se c'è.

    Lo store è un file su disco, quindi può contenere una riga vecchia,
    manomessa o relativa a una versione precedente della spec. La difesa non
    riposa solo sul controllo all'ingresso: il tier dichiarato è un pavimento.
    """
    percorso = tmp_path / "overrides.jsonl"
    percorso.write_text(
        '{"tool_id": "echo.ping", "tier": "verde"}\n', encoding="utf-8"
    )
    reg = ToolRegistry(audit, store=OverrideStore(percorso))
    reg.register(_spec(default_tier=RiskTier.ROSSO))
    assert reg.effective_tier("echo.ping") is RiskTier.ROSSO


def test_override_su_tool_sconosciuto_solleva(reg: ToolRegistry):
    with pytest.raises(ToolNotRegistered):
        reg.set_override("mai.registrato", RiskTier.ROSSO)


def test_override_loggato_con_dichiarato_ed_effettivo(reg: ToolRegistry, audit: AuditLog):
    reg.register(_spec(default_tier=RiskTier.VERDE))
    reg.set_override("echo.ping", RiskTier.ROSSO)
    riga = [r for r in audit.read_all() if r.action is LogAction.OVERRIDE_SET][0]
    assert riga.tier_effective is RiskTier.ROSSO
    assert "verde" in riga.detail  # il dichiarato resta tracciato


def test_override_registra_chi_lo_ha_chiesto(reg: ToolRegistry, audit: AuditLog):
    """Un innalzamento di tier è una modifica ai controlli: va attribuita.

    Difetto trovato leggendo un log reale: la riga `override_set` diceva che
    il tier era cambiato, ma con `agent: null` — cioè senza dire per mano di
    chi, sull'unico evento in cui la provenienza è il dato che conta.
    """
    reg.register(_spec())
    reg.set_override("echo.ping", RiskTier.ROSSO, agent=OwnerAgent.VULN_ASSESSMENT)
    riga = [r for r in audit.read_all() if r.action is LogAction.OVERRIDE_SET][0]
    assert riga.agent is OwnerAgent.VULN_ASSESSMENT


def test_override_rifiutato_registra_chi_lo_ha_chiesto(
    reg: ToolRegistry, audit: AuditLog
):
    """Vale a maggior ragione per un tentativo rifiutato."""
    reg.register(_spec(default_tier=RiskTier.ROSSO))
    with pytest.raises(OverrideRefused):
        reg.set_override("echo.ping", RiskTier.VERDE, agent=OwnerAgent.PENTEST_KALI)
    riga = [r for r in audit.read_all() if r.action is LogAction.OVERRIDE_REJECTED][0]
    assert riga.agent is OwnerAgent.PENTEST_KALI


def test_override_usa_il_correlation_id_passato(reg: ToolRegistry, audit: AuditLog):
    reg.register(_spec())
    cid = uuid.uuid4()
    reg.set_override("echo.ping", RiskTier.ROSSO, correlation_id=cid)
    riga = [r for r in audit.read_all() if r.action is LogAction.OVERRIDE_SET][0]
    assert riga.correlation_id == cid


def test_eventi_di_startup_condividono_un_correlation_id(reg: ToolRegistry, audit: AuditLog):
    reg.register(_spec())
    reg.register(_spec(tool_id="echo.pong"))
    assert {r.correlation_id for r in audit.read_all()} == {reg.correlation_id}


# --------------------------------------------------------------------------- #
# Policy sul tier effettivo
# --------------------------------------------------------------------------- #


def test_policy_segue_il_tier_effettivo(reg: ToolRegistry):
    """Ignorare l'override applicherebbe conferme più lasse di quelle richieste."""
    reg.register(_spec(default_tier=RiskTier.VERDE))
    assert reg.policy_for("echo.ping").technical is ConfirmationCadence.NESSUNA

    reg.set_override("echo.ping", RiskTier.ROSSO)
    pol = reg.policy_for("echo.ping")
    assert pol.tier is RiskTier.ROSSO
    assert pol.technical is ConfirmationCadence.PUNTUALE
    assert pol.unattended_safe is False


def test_policy_propaga_i_dati_personali(reg: ToolRegistry):
    reg.register(_spec(personal_data=True))
    pol = reg.policy_for("echo.ping")
    assert pol.technical is ConfirmationCadence.NESSUNA
    assert pol.personal is ConfirmationCadence.UNA_TANTUM_PER_SCOPE
    assert pol.requires_confirmation is True


# --------------------------------------------------------------------------- #
# Aliasing sullo stesso script
# --------------------------------------------------------------------------- #


def _alias(audit: AuditLog):
    return [r for r in audit.read_all() if r.action is LogAction.TOOL_ALIAS_DETECTED]


def test_alias_a_tier_inferiore_segnalato(reg: ToolRegistry, audit: AuditLog):
    """Secondo tool_id sullo stesso script a tier più basso: declassamento mascherato."""
    reg.register(_spec(tool_id="nmap.aggressive", default_tier=RiskTier.ROSSO,
                       exec_path="tools/nmap.py"))
    reg.register(_spec(tool_id="nmap.sneaky", default_tier=RiskTier.VERDE,
                       exec_path="tools/nmap.py"))

    righe = _alias(audit)
    assert len(righe) == 1
    assert righe[0].tool_id == "nmap.sneaky"
    assert "nmap.aggressive=rosso" in righe[0].detail
    assert "declassamento mascherato" in righe[0].detail


def test_alias_segnalato_ma_non_bloccante(reg: ToolRegistry):
    """Rilevamento, non rifiuto: il pattern legittimo non deve rompersi."""
    reg.register(_spec(tool_id="nmap.aggressive", default_tier=RiskTier.ROSSO,
                       exec_path="tools/nmap.py"))
    reg.register(_spec(tool_id="nmap.sneaky", default_tier=RiskTier.VERDE,
                       exec_path="tools/nmap.py"))
    assert len(reg) == 2
    assert reg.effective_tier("nmap.sneaky") is RiskTier.VERDE


def test_sottocomandi_a_rischio_crescente_non_segnalati(reg: ToolRegistry, audit: AuditLog):
    """Il caso legittimo: stesso script, tier crescente. Nessun falso positivo."""
    reg.register(_spec(tool_id="nmap.ping-sweep", default_tier=RiskTier.VERDE,
                       exec_path="tools/nmap.py"))
    reg.register(_spec(tool_id="nmap.aggressive", default_tier=RiskTier.ROSSO,
                       exec_path="tools/nmap.py"))
    assert _alias(audit) == []


def test_stesso_tier_sullo_stesso_script_non_segnalato(reg: ToolRegistry, audit: AuditLog):
    reg.register(_spec(tool_id="nmap.uno", default_tier=RiskTier.GIALLO,
                       exec_path="tools/nmap.py"))
    reg.register(_spec(tool_id="nmap.due", default_tier=RiskTier.GIALLO,
                       exec_path="tools/nmap.py"))
    assert _alias(audit) == []


def test_script_diversi_non_segnalati(reg: ToolRegistry, audit: AuditLog):
    reg.register(_spec(tool_id="tool.uno", default_tier=RiskTier.ROSSO,
                       exec_path="tools/uno.py"))
    reg.register(_spec(tool_id="tool.due", default_tier=RiskTier.VERDE,
                       exec_path="tools/due.py"))
    assert _alias(audit) == []


def test_alias_confrontato_col_tier_effettivo_non_col_dichiarato(
    reg: ToolRegistry, audit: AuditLog
):
    """Un override alzato su un fratello rende sospetto un alias basso successivo."""
    reg.register(_spec(tool_id="nmap.uno", default_tier=RiskTier.VERDE,
                       exec_path="tools/nmap.py"))
    reg.set_override("nmap.uno", RiskTier.ROSSO)
    reg.register(_spec(tool_id="nmap.due", default_tier=RiskTier.VERDE,
                       exec_path="tools/nmap.py"))

    righe = _alias(audit)
    assert len(righe) == 1
    assert "nmap.uno=rosso" in righe[0].detail


def test_sha_incoerente_sullo_stesso_path_segnalato(reg: ToolRegistry, audit: AuditLog):
    """Lo stesso file non può avere due hash: una delle due spec è sbagliata."""
    reg.register(_spec(tool_id="nmap.uno", exec_path="tools/nmap.py", exec_sha256="a" * 64))
    reg.register(_spec(tool_id="nmap.due", exec_path="tools/nmap.py", exec_sha256="b" * 64))

    righe = _alias(audit)
    assert len(righe) == 1
    assert righe[0].outcome is CallOutcome.DENIED
    assert "integrità incoerente" in righe[0].detail
    assert "nmap.uno" in righe[0].detail


def test_sha_coerente_non_segnalato(reg: ToolRegistry, audit: AuditLog):
    reg.register(_spec(tool_id="nmap.uno", exec_path="tools/nmap.py"))
    reg.register(_spec(tool_id="nmap.due", exec_path="tools/nmap.py"))
    assert _alias(audit) == []


def test_alias_e_sha_incoerente_insieme(reg: ToolRegistry, audit: AuditLog):
    """Due anomalie distinte sullo stesso evento producono due righe."""
    reg.register(_spec(tool_id="nmap.uno", default_tier=RiskTier.ROSSO,
                       exec_path="tools/nmap.py", exec_sha256="a" * 64))
    reg.register(_spec(tool_id="nmap.due", default_tier=RiskTier.VERDE,
                       exec_path="tools/nmap.py", exec_sha256="b" * 64))

    righe = _alias(audit)
    assert len(righe) == 2
    assert {r.outcome for r in righe} == {CallOutcome.OK, CallOutcome.DENIED}


def test_tools_sharing_exec(reg: ToolRegistry):
    reg.register(_spec(tool_id="nmap.uno", exec_path="tools/nmap.py"))
    reg.register(_spec(tool_id="nmap.due", exec_path="tools/nmap.py"))
    reg.register(_spec(tool_id="altro.tool", exec_path="tools/altro.py"))

    assert reg.tools_sharing_exec("nmap.uno") == ("nmap.due",)
    assert reg.tools_sharing_exec("altro.tool") == ()


def test_tools_sharing_exec_su_sconosciuto_solleva(reg: ToolRegistry):
    with pytest.raises(ToolNotRegistered):
        reg.tools_sharing_exec("mai.registrato")


# --------------------------------------------------------------------------- #
# Isolamento fra agenti
# --------------------------------------------------------------------------- #


def test_proprietario_puo_invocare(reg: ToolRegistry):
    reg.register(_spec(owner_agent=OwnerAgent.ECHO_DUMMY))
    assert reg.can_invoke("echo.ping", OwnerAgent.ECHO_DUMMY) is True
    assert reg.assert_can_invoke("echo.ping", OwnerAgent.ECHO_DUMMY).tool_id == "echo.ping"


def test_altro_agente_rifiutato(reg: ToolRegistry, audit: AuditLog):
    """Senza questo confine il campo owner_agent sarebbe decorativo."""
    reg.register(_spec(owner_agent=OwnerAgent.VULN_ASSESSMENT))
    assert reg.can_invoke("echo.ping", OwnerAgent.PENTEST_KALI) is False
    with pytest.raises(InvocationRefused):
        reg.assert_can_invoke("echo.ping", OwnerAgent.PENTEST_KALI)

    riga = [r for r in audit.read_all() if r.action is LogAction.TOOL_CALL][0]
    assert riga.outcome is CallOutcome.DENIED
    assert riga.agent is OwnerAgent.PENTEST_KALI
    assert "vuln_assessment" in riga.detail


def test_invocazione_tool_sconosciuto_solleva(reg: ToolRegistry):
    with pytest.raises(ToolNotRegistered):
        reg.assert_can_invoke("mai.registrato", OwnerAgent.ECHO_DUMMY)


# --------------------------------------------------------------------------- #
# override_tier in configurazione versionata
# --------------------------------------------------------------------------- #


def test_override_di_config_innalza(reg: ToolRegistry):
    reg.register_payload(_payload(default_tier="verde", **{CHIAVE_OVERRIDE: "rosso"}))
    assert reg.effective_tier("echo.ping") is RiskTier.ROSSO
    assert reg.override_scope("echo.ping") is OverrideScope.CONFIG


def test_override_di_config_non_entra_nella_spec(reg: ToolRegistry):
    """La spec deve restare quella dichiarata dall'integratore.

    Altrimenti in audit non si distingue più «era rischioso» da «l'ho alzato
    io», che è l'intera ragione per cui gli override stanno fuori dalla spec.
    """
    spec = reg.register_payload(
        _payload(default_tier="verde", **{CHIAVE_OVERRIDE: "rosso"})
    )
    assert spec.default_tier is RiskTier.VERDE
    assert not hasattr(spec, CHIAVE_OVERRIDE)


def test_override_di_config_inventato_fa_fallire_l_avvio(
    reg: ToolRegistry, audit: AuditLog
):
    """Qui l'operatore crede di aver alzato un tier e non l'ha alzato."""
    with pytest.raises(ToolSpecRejected, match="override_tier non valido"):
        reg.register_payload(_payload(**{CHIAVE_OVERRIDE: "rossa"}))
    assert "echo.ping" not in reg
    assert LogAction.TOOL_REGISTRATION_REJECTED in _azioni(audit)


def test_override_di_config_piu_basso_e_inerte_ma_non_fatale(
    reg: ToolRegistry, audit: AuditLog
):
    """L'esito è il tier dichiarato, cioè il più stretto: non si cade per questo."""
    reg.register_payload(_payload(default_tier="rosso", **{CHIAVE_OVERRIDE: "verde"}))
    assert reg.effective_tier("echo.ping") is RiskTier.ROSSO
    assert reg.override_scope("echo.ping") is OverrideScope.NONE

    riga = [r for r in audit.read_all() if r.action is LogAction.OVERRIDE_REJECTED][0]
    assert riga.outcome is CallOutcome.DENIED
    assert "inerte" in riga.detail


def test_override_di_config_ridondante_non_risulta_attivo(reg: ToolRegistry):
    """Un override che coincide col dichiarato non cambia nulla: non va mostrato."""
    reg.register_payload(_payload(default_tier="giallo", **{CHIAVE_OVERRIDE: "giallo"}))
    assert reg.override_scope("echo.ping") is OverrideScope.NONE
    assert "echo.ping" not in reg.overrides


def test_runtime_puo_salire_sopra_l_override_di_config(
    audit: AuditLog, tmp_path
):
    """Le fonti non si escludono: il tier effettivo è il massimo di tutte."""
    store = OverrideStore.in_directory(tmp_path / "stato")
    reg = ToolRegistry(audit, store=store)
    reg.register_payload(_payload(default_tier="verde", **{CHIAVE_OVERRIDE: "giallo"}))
    reg.set_override("echo.ping", RiskTier.ROSSO)
    assert reg.effective_tier("echo.ping") is RiskTier.ROSSO
    assert reg.override_scope("echo.ping") is OverrideScope.PERSISTENT


def test_config_vince_se_e_la_fonte_piu_alta(audit: AuditLog, tmp_path):
    """Lo scope segnalato è quello della fonte che regge il tier corrente."""
    percorso = tmp_path / "overrides.jsonl"
    percorso.write_text('{"tool_id": "echo.ping", "tier": "giallo"}\n', encoding="utf-8")
    reg = ToolRegistry(audit, store=OverrideStore(percorso))
    reg.register_payload(_payload(default_tier="verde", **{CHIAVE_OVERRIDE: "rosso"}))
    assert reg.effective_tier("echo.ping") is RiskTier.ROSSO
    assert reg.override_scope("echo.ping") is OverrideScope.CONFIG


def test_store_con_tool_mai_registrato_non_disturba(audit: AuditLog, tmp_path):
    """Un tool rimosso dalla config lascia la sua riga: deve restare inerte."""
    percorso = tmp_path / "overrides.jsonl"
    percorso.write_text('{"tool_id": "sparito.vecchio", "tier": "rosso"}\n', encoding="utf-8")
    reg = ToolRegistry(audit, store=OverrideStore(percorso))
    reg.register(_spec())
    assert reg.effective_tier("echo.ping") is RiskTier.VERDE
    with pytest.raises(ToolNotRegistered):
        reg.effective_tier("sparito.vecchio")
