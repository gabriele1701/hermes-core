"""Test del contratto dati (M0 passo 1).

L'obiettivo non è dimostrare che il caso felice passa, ma che i vincoli
**rifiutano** ciò che deve essere rifiutato: un contratto che accetta un
payload malformato è un controllo che non c'è.
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from mcp_server.contracts import (
    AgentResult,
    AgentStatus,
    AuthorizedBy,
    CallOutcome,
    Finding,
    OwnerAgent,
    RiskTier,
    Severity,
    ToolCall,
    ToolSpec,
)

SHA_OK = "a" * 64


def _tool_spec(**override) -> dict:
    """Spec valida minima, sovrascrivibile campo per campo."""
    base = {
        "tool_id": "echo.ping",
        "owner_agent": OwnerAgent.ECHO_DUMMY,
        "default_tier": RiskTier.VERDE,
        "personal_data": False,
        "requires_container": False,
        "exec_path": "agents/echo_agent/run.py",
        "exec_sha256": SHA_OK,
        "description": "Tool dummy che restituisce un risultato conforme.",
    }
    return base | override


def _agent_result(**override) -> dict:
    base = {
        "correlation_id": uuid.uuid4(),
        "agent": OwnerAgent.ECHO_DUMMY,
        "status": AgentStatus.OK,
        "summary": "Catena completata senza findings.",
    }
    return base | override


# --------------------------------------------------------------------------- #
# RiskTier — ordinamento
# --------------------------------------------------------------------------- #


def test_tier_ordinamento_monotono():
    """L'ordinamento serve al registry per max(default, override)."""
    assert RiskTier.VERDE.rank < RiskTier.GIALLO.rank < RiskTier.ROSSO.rank


def test_tier_serializza_come_stringa():
    """I tier finiscono nei log JSONL: devono serializzare in chiaro."""
    assert RiskTier.ROSSO.value == "rosso"
    assert f"{RiskTier.GIALLO}" == "giallo"


# --------------------------------------------------------------------------- #
# ToolSpec
# --------------------------------------------------------------------------- #


def test_toolspec_valida():
    spec = ToolSpec(**_tool_spec())
    assert spec.tool_id == "echo.ping"
    assert spec.default_tier is RiskTier.VERDE
    assert spec.personal_data is False


def test_toolspec_senza_tier_rifiutata():
    """Definition of done del passo: nessun tier → nessuna registrazione.

    L'assenza del tier non deve degradare a un default permissivo.
    """
    payload = _tool_spec()
    del payload["default_tier"]
    with pytest.raises(ValidationError) as err:
        ToolSpec(**payload)
    assert "default_tier" in str(err.value)


def test_toolspec_tier_invalido_rifiutato():
    with pytest.raises(ValidationError):
        ToolSpec(**_tool_spec(default_tier="arancione"))


def test_toolspec_immutabile():
    """Il tier non è modificabile dopo la registrazione.

    Un innalzamento passa dallo store di override del registry, non dalla spec.
    """
    spec = ToolSpec(**_tool_spec())
    with pytest.raises(ValidationError):
        spec.default_tier = RiskTier.VERDE  # type: ignore[misc]
    with pytest.raises(ValidationError):
        spec.personal_data = True  # type: ignore[misc]


def test_toolspec_rifiuta_campi_non_dichiarati():
    """Un campo ignoto non deve transitare silenziosamente.

    In particolare il tool non può dichiarare la propria confirmation policy:
    quella è derivata dal server.
    """
    with pytest.raises(ValidationError):
        ToolSpec(**_tool_spec(confirmation_policy="nessuna"))


@pytest.mark.parametrize(
    "cattivo",
    [
        "/usr/bin/nmap",  # assoluto
        "../../etc/passwd",  # traversal
        "agents/../../../bin/sh",  # traversal annidato
        "agents//run.py",  # segmento vuoto
        "./agents/run.py",  # segmento '.'
        "agents\\echo\\run.py",  # separatore Windows
    ],
)
def test_toolspec_exec_path_confinato(cattivo: str):
    """exec_path deve restare dentro il repo versionato.

    Un percorso assoluto o con traversal aggirerebbe il pinning via SHA
    puntando a un eseguibile arbitrario del filesystem.
    """
    with pytest.raises(ValidationError):
        ToolSpec(**_tool_spec(exec_path=cattivo))


@pytest.mark.parametrize(
    "cattivo",
    [
        "",  # vuoto
        "A" * 64,  # uppercase
        "a" * 63,  # troppo corto
        "a" * 65,  # troppo lungo
        "z" * 64,  # non esadecimale
    ],
)
def test_toolspec_sha_malformato_rifiutato(cattivo: str):
    with pytest.raises(ValidationError):
        ToolSpec(**_tool_spec(exec_sha256=cattivo))


@pytest.mark.parametrize(
    "cattivo",
    ["Echo.Ping", "echo ping", "echo/ping", "ec", "echo..ping", "_echo"],
)
def test_toolspec_tool_id_malformato_rifiutato(cattivo: str):
    with pytest.raises(ValidationError):
        ToolSpec(**_tool_spec(tool_id=cattivo))


def test_toolspec_due_assi_indipendenti():
    """personal_data è ortogonale al tier: un tool verde può trattarne."""
    spec = ToolSpec(**_tool_spec(default_tier=RiskTier.VERDE, personal_data=True))
    assert spec.default_tier is RiskTier.VERDE
    assert spec.personal_data is True


# --------------------------------------------------------------------------- #
# ToolCall
# --------------------------------------------------------------------------- #


def test_toolcall_eseguita_richiede_autorizzazione():
    """Un'esecuzione senza autorizzazione tracciata non è dichiarabile."""
    for esito in (CallOutcome.OK, CallOutcome.ERROR):
        with pytest.raises(ValidationError):
            ToolCall(
                tool_id="echo.ping",
                tier_effective=RiskTier.VERDE,
                authorized_by=AuthorizedBy.NONE,
                outcome=esito,
            )


def test_toolcall_negata_senza_autorizzazione_ammessa():
    """Una chiamata negata o sospesa può non avere autorizzazione."""
    for esito in (CallOutcome.DENIED, CallOutcome.PENDING):
        call = ToolCall(
            tool_id="echo.ping",
            tier_effective=RiskTier.ROSSO,
            authorized_by=AuthorizedBy.NONE,
            outcome=esito,
        )
        assert call.outcome is esito


# --------------------------------------------------------------------------- #
# AgentResult
# --------------------------------------------------------------------------- #


def test_agentresult_valido():
    cid = uuid.uuid4()
    res = AgentResult(**_agent_result(correlation_id=cid))
    assert res.correlation_id == cid
    assert res.status is AgentStatus.OK
    assert res.findings == ()
    assert res.tool_calls == ()


def test_agentresult_schema_completo():
    """Lo schema concordato: correlation_id, agent, status, summary, findings, tool_calls."""
    res = AgentResult(
        **_agent_result(
            findings=[
                Finding(
                    finding_id="f-001",
                    severity=Severity.MEDIUM,
                    title="Servizio SSH con autenticazione a password",
                    detail="Password auth abilitata su lab-kali.",
                    target="lab-kali",
                )
            ],
            tool_calls=[
                ToolCall(
                    tool_id="echo.ping",
                    target="lab-kali",
                    tier_effective=RiskTier.VERDE,
                    authorized_by=AuthorizedBy.POLICY,
                    outcome=CallOutcome.OK,
                )
            ],
        )
    )
    assert set(res.model_dump().keys()) == {
        "correlation_id",
        "agent",
        "status",
        "summary",
        "findings",
        "tool_calls",
    }
    assert res.findings[0].severity is Severity.MEDIUM
    assert res.tool_calls[0].tier_effective is RiskTier.VERDE


def test_agentresult_round_trip_json():
    """Il risultato finisce nei log JSONL: round-trip senza perdita."""
    res = AgentResult(
        **_agent_result(
            tool_calls=[
                ToolCall(
                    tool_id="echo.ping",
                    tier_effective=RiskTier.GIALLO,
                    authorized_by=AuthorizedBy.USER,
                    outcome=CallOutcome.OK,
                )
            ]
        )
    )
    assert AgentResult.model_validate_json(res.model_dump_json()) == res


def test_agentresult_correlation_id_malformato_rifiutato():
    """Senza un correlation_id valido la catena non è ricostruibile dai log."""
    with pytest.raises(ValidationError):
        AgentResult(**_agent_result(correlation_id="non-un-uuid"))


def test_agentresult_status_invalido_rifiutato():
    with pytest.raises(ValidationError):
        AgentResult(**_agent_result(status="forse"))


def test_agentresult_summary_vuoto_rifiutato():
    with pytest.raises(ValidationError):
        AgentResult(**_agent_result(summary="   "))


def test_agentresult_rifiuta_campi_non_dichiarati():
    with pytest.raises(ValidationError):
        AgentResult(**_agent_result(raw_stdout="..."))


def test_agentresult_immutabile():
    res = AgentResult(**_agent_result())
    with pytest.raises(ValidationError):
        res.status = AgentStatus.ERROR  # type: ignore[misc]


# --- invarianti stato/chiamate ---------------------------------------------- #


def _pending_call() -> ToolCall:
    return ToolCall(
        tool_id="echo.ping",
        tier_effective=RiskTier.ROSSO,
        authorized_by=AuthorizedBy.NONE,
        outcome=CallOutcome.PENDING,
    )


def test_needs_confirmation_richiede_chiamata_pending():
    """Chiedere conferma senza dire su cosa non è un contratto utile."""
    with pytest.raises(ValidationError) as err:
        AgentResult(**_agent_result(status=AgentStatus.NEEDS_CONFIRMATION))
    assert "pending" in str(err.value)


def test_needs_confirmation_con_pending_valido():
    res = AgentResult(
        **_agent_result(
            status=AgentStatus.NEEDS_CONFIRMATION,
            summary="Il tool richiede conferma puntuale (tier rosso).",
            tool_calls=[_pending_call()],
        )
    )
    assert res.status is AgentStatus.NEEDS_CONFIRMATION
    assert res.tool_calls[0].outcome is CallOutcome.PENDING


def test_ok_con_pending_rifiutato():
    """Un esito 'ok' con qualcosa in attesa nasconderebbe una conferma non data."""
    with pytest.raises(ValidationError) as err:
        AgentResult(**_agent_result(status=AgentStatus.OK, tool_calls=[_pending_call()]))
    assert "pending" in str(err.value)


def test_error_con_pending_ammesso():
    """Un agente può fallire lasciando una chiamata non autorizzata."""
    res = AgentResult(
        **_agent_result(
            status=AgentStatus.ERROR,
            summary="Interrotto prima della conferma.",
            tool_calls=[_pending_call()],
        )
    )
    assert res.status is AgentStatus.ERROR
