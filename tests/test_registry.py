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
from mcp_server.registry import (
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


def test_override_piu_basso_nello_store_resta_inerte(reg: ToolRegistry):
    """Secondo presidio: il max() scarta un override basso anche se c'è.

    Simula uno store corrotto scrivendo direttamente nella struttura interna:
    la difesa non riposa solo sul controllo all'ingresso.
    """
    reg.register(_spec(default_tier=RiskTier.ROSSO))
    reg._overrides["echo.ping"] = RiskTier.VERDE  # noqa: SLF001 - corruzione simulata
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
