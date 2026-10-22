"""Test del log d'audit JSONL (M0 passo 2).

Verifica le proprietà che rendono il log utilizzabile come traccia d'audit:
una riga = un oggetto JSON, append-only, permessi restrittivi, correlazione
preservata, nessun campo in cui un segreto possa entrare.
"""

from __future__ import annotations

import json
import stat
import uuid

import pytest
from pydantic import ValidationError

from mcp_server.audit import AuditLog, LogAction, LogRecord
from mcp_server.contracts import (
    AgentResult,
    AgentStatus,
    AuthorizedBy,
    CallOutcome,
    OwnerAgent,
    RiskTier,
    ToolCall,
)


@pytest.fixture()
def log(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit" / "hermes-audit.jsonl")


def _cid() -> uuid.UUID:
    return uuid.uuid4()


# --------------------------------------------------------------------------- #
# LogRecord
# --------------------------------------------------------------------------- #


def test_record_timestamp_timezone_aware():
    """Un timestamp d'audit senza fuso non è correlabile con nient'altro."""
    import datetime as dt

    rec = LogRecord(
        correlation_id=_cid(), action=LogAction.AGENT_INVOKED, outcome=CallOutcome.OK
    )
    parsed = dt.datetime.fromisoformat(rec.ts)
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == dt.timedelta(0)


def test_record_immutabile():
    rec = LogRecord(
        correlation_id=_cid(), action=LogAction.TOOL_CALL, outcome=CallOutcome.OK
    )
    with pytest.raises(ValidationError):
        rec.outcome = CallOutcome.DENIED  # type: ignore[misc]


def test_record_rifiuta_campi_non_dichiarati():
    """Nessun campo di passaggio in cui un valore di credenziale possa entrare."""
    with pytest.raises(ValidationError):
        LogRecord(
            correlation_id=_cid(),
            action=LogAction.SECRET_ACCESS,
            outcome=CallOutcome.OK,
            secret_value="hunter2",
        )


def test_record_jsonl_una_sola_riga():
    riga = LogRecord(
        correlation_id=_cid(), action=LogAction.TOOL_CALL, outcome=CallOutcome.OK
    ).to_jsonl()
    assert riga.endswith("\n")
    assert riga.count("\n") == 1


# --------------------------------------------------------------------------- #
# Formato del file
# --------------------------------------------------------------------------- #


def test_ogni_riga_e_json_valido(log: AuditLog):
    for _ in range(3):
        log.log(
            correlation_id=_cid(), action=LogAction.TOOL_CALL, outcome=CallOutcome.OK
        )
    righe = log.path.read_text(encoding="utf-8").splitlines()
    assert len(righe) == 3
    for riga in righe:
        assert json.loads(riga)["action"] == "tool_call"


def test_detail_multilinea_non_spezza_il_formato(log: AuditLog):
    """Un detail con newline non deve poter iniettare una riga di log falsa."""
    veleno = 'riga1\nriga2\n{"action": "tool_call", "outcome": "ok"}'
    log.log(
        correlation_id=_cid(),
        action=LogAction.AGENT_RESULT,
        outcome=CallOutcome.ERROR,
        detail=veleno,
    )
    righe = log.path.read_text(encoding="utf-8").splitlines()
    assert len(righe) == 1
    assert json.loads(righe[0])["detail"] == veleno


def test_unicode_preservato(log: AuditLog):
    log.log(
        correlation_id=_cid(),
        action=LogAction.AGENT_RESULT,
        outcome=CallOutcome.OK,
        detail="configurazione già conforme — nessun finding",
    )
    assert log.read_all()[0].detail == "configurazione già conforme — nessun finding"


def test_round_trip_record(log: AuditLog):
    scritto = log.log(
        correlation_id=_cid(),
        action=LogAction.TOOL_CALL,
        outcome=CallOutcome.OK,
        agent=OwnerAgent.ECHO_DUMMY,
        tool_id="echo.ping",
        target="lab-kali",
        tier_effective=RiskTier.GIALLO,
        authorized_by=AuthorizedBy.USER,
    )
    assert log.read_all() == (scritto,)


# --------------------------------------------------------------------------- #
# Append-only
# --------------------------------------------------------------------------- #


def test_append_non_tronca(log: AuditLog, tmp_path):
    """Una nuova istanza non deve azzerare un log esistente."""
    log.log(correlation_id=_cid(), action=LogAction.AGENT_INVOKED, outcome=CallOutcome.OK)
    secondo = AuditLog(log.path)
    secondo.log(correlation_id=_cid(), action=LogAction.AGENT_RESULT, outcome=CallOutcome.OK)
    assert len(secondo.read_all()) == 2


def test_writer_non_espone_modifiche(log: AuditLog):
    """Append-only è una proprietà dell'API, non solo della buona volontà."""
    for vietato in ("truncate", "delete", "clear", "rewrite", "update"):
        assert not hasattr(log, vietato)


def test_scritture_concorrenti_non_si_interlacciano(log: AuditLog):
    """O_APPEND: righe corte da più writer non si spezzano a metà."""
    from concurrent.futures import ThreadPoolExecutor

    def scrivi(_: int) -> None:
        AuditLog(log.path).log(
            correlation_id=_cid(),
            action=LogAction.TOOL_CALL,
            outcome=CallOutcome.OK,
            detail="x" * 200,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(scrivi, range(40)))

    righe = log.path.read_text(encoding="utf-8").splitlines()
    assert len(righe) == 40
    assert all(json.loads(r)["detail"] == "x" * 200 for r in righe)


# --------------------------------------------------------------------------- #
# Permessi
# --------------------------------------------------------------------------- #


def test_permessi_restrittivi(log: AuditLog):
    """Target e hostname nel log non devono essere leggibili da altri utenti."""
    log.log(correlation_id=_cid(), action=LogAction.TOOL_CALL, outcome=CallOutcome.OK)
    assert stat.S_IMODE(log.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(log.path.parent.stat().st_mode) == 0o700


def test_chmod_rifiutata_non_impedisce_la_scrittura(tmp_path, monkeypatch):
    """Indurire il log non deve metterlo fuori uso.

    Difetto trovato sul campo: `chattr +a` sul log d'audit fa rifiutare la
    chmod con EPERM anche al proprietario, e il writer la eseguiva a ogni
    costruzione. Risultato: la misura di protezione impediva di scrivere ciò
    che proteggeva, e il server non partiva più.
    """
    import os as _os

    percorso = tmp_path / "audit.jsonl"
    percorso.write_text("", encoding="utf-8")
    _os.chmod(percorso, 0o666)  # permessi diversi: forza il tentativo di chmod

    def chmod_negata(*args, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(_os, "chmod", chmod_negata)

    log = AuditLog(percorso)  # non deve sollevare
    log.log(correlation_id=_cid(), action=LogAction.TOOL_CALL, outcome=CallOutcome.OK)
    assert len(log.read_all()) == 1


def test_chmod_non_tentata_se_i_permessi_sono_giusti(tmp_path, monkeypatch):
    """Sul caso normale la chmod non viene nemmeno chiamata.

    È ciò che rende il writer compatibile con un log append-only: se il file
    ha già i permessi giusti, non c'è niente da imporre.
    """
    import os as _os

    percorso = tmp_path / "audit.jsonl"
    AuditLog(percorso)  # prima costruzione: crea e imposta i permessi

    chiamate: list[str] = []
    originale = _os.chmod

    def spia(path, mode, *args, **kwargs):
        chiamate.append(str(path))
        return originale(path, mode, *args, **kwargs)

    monkeypatch.setattr(_os, "chmod", spia)
    AuditLog(percorso)  # seconda costruzione: nulla da cambiare
    assert chiamate == []


def test_log_append_only_reale(tmp_path):
    """Con `chattr +a` applicato davvero, la scrittura deve funzionare.

    Salta dove `chattr` non è disponibile o il filesystem non lo supporta —
    nella CI capita. Dove gira, è la verifica che conta: il writer continua a
    scrivere su un log che nessuno può più troncare.
    """
    import os as _os
    import subprocess

    percorso = tmp_path / "audit.jsonl"
    AuditLog(percorso).log(
        correlation_id=_cid(), action=LogAction.AGENT_INVOKED, outcome=CallOutcome.OK
    )

    try:
        esito = subprocess.run(
            ["chattr", "+a", str(percorso)], capture_output=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        pytest.skip("chattr non disponibile")
    if esito.returncode != 0:
        pytest.skip("chattr +a non supportato su questo filesystem o privilegi")

    try:
        log = AuditLog(percorso)  # il punto che si rompeva
        log.log(
            correlation_id=_cid(),
            action=LogAction.TOOL_CALL,
            outcome=CallOutcome.OK,
            detail="scritto su log append-only",
        )
        righe = log.read_all()
        assert len(righe) == 2
        assert righe[-1].detail == "scritto su log append-only"
    finally:
        # Senza togliere l'attributo, tmp_path non è cancellabile.
        subprocess.run(["chattr", "-a", str(percorso)], capture_output=True, timeout=10)
        _os.chmod(percorso, 0o600)


def test_crea_directory_mancante(tmp_path):
    destinazione = tmp_path / "a" / "b" / "audit.jsonl"
    AuditLog(destinazione).log(
        correlation_id=_cid(), action=LogAction.AGENT_INVOKED, outcome=CallOutcome.OK
    )
    assert destinazione.exists()


# --------------------------------------------------------------------------- #
# Correlazione con AgentResult
# --------------------------------------------------------------------------- #


def test_log_agent_result_una_riga_piu_una_per_chiamata(log: AuditLog):
    cid = _cid()
    res = AgentResult(
        correlation_id=cid,
        agent=OwnerAgent.ECHO_DUMMY,
        status=AgentStatus.OK,
        summary="Due tool eseguiti.",
        tool_calls=[
            ToolCall(
                tool_id="echo.ping",
                target="lab-kali",
                tier_effective=RiskTier.VERDE,
                authorized_by=AuthorizedBy.POLICY,
                outcome=CallOutcome.OK,
            ),
            ToolCall(
                tool_id="echo.pong",
                tier_effective=RiskTier.GIALLO,
                authorized_by=AuthorizedBy.USER,
                outcome=CallOutcome.OK,
            ),
        ],
    )
    righe = log.log_agent_result(res)

    assert len(righe) == 3
    assert [r.action for r in righe] == [
        LogAction.AGENT_RESULT,
        LogAction.TOOL_CALL,
        LogAction.TOOL_CALL,
    ]
    # Tutta la catena sotto un unico correlation_id: ricostruibile con una query.
    assert {r.correlation_id for r in righe} == {cid}
    assert righe[1].tool_id == "echo.ping"
    assert righe[1].tier_effective is RiskTier.VERDE
    assert righe[2].authorized_by is AuthorizedBy.USER


def test_log_agent_result_needs_confirmation_resta_pending(log: AuditLog):
    """Una conferma non data si legge nel log come 'pending', non come successo."""
    res = AgentResult(
        correlation_id=_cid(),
        agent=OwnerAgent.ECHO_DUMMY,
        status=AgentStatus.NEEDS_CONFIRMATION,
        summary="Richiesta conferma puntuale (tier rosso).",
        tool_calls=[
            ToolCall(
                tool_id="echo.ping",
                tier_effective=RiskTier.ROSSO,
                authorized_by=AuthorizedBy.NONE,
                outcome=CallOutcome.PENDING,
            )
        ],
    )
    righe = log.log_agent_result(res)
    assert righe[0].outcome is CallOutcome.PENDING
    assert righe[1].outcome is CallOutcome.PENDING


def test_log_agent_result_errore_mappato(log: AuditLog):
    res = AgentResult(
        correlation_id=_cid(),
        agent=OwnerAgent.ECHO_DUMMY,
        status=AgentStatus.ERROR,
        summary="Tool non registrato.",
    )
    assert log.log_agent_result(res)[0].outcome is CallOutcome.ERROR


def test_read_all_su_log_inesistente(tmp_path):
    vuoto = AuditLog(tmp_path / "mai-scritto.jsonl")
    vuoto.path.unlink()
    assert vuoto.read_all() == ()
