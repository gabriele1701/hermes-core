"""Test della catena completa (M0 passo 7).

È la definition of done della Milestone 0: orchestratore → agente → gate →
script → log, con **un solo `correlation_id`** dall'invocazione alla riga
finale.

I test segnati ``slow`` avviano processi veri. Durante l'iterazione:
``pytest -m "not slow"``.
"""

from __future__ import annotations

import textwrap
import uuid
from pathlib import Path

import pytest

from agents.orchestrator.orchestrator import (
    AgentEndpoint,
    Invocation,
    MalformedAgentResult,
    Orchestrator,
)
from mcp_server.audit import AuditLog, LogAction
from mcp_server.contracts import AgentResult, AgentStatus, CallOutcome, OwnerAgent
from mcp_server.executor import sha256_file

SCRIPT = "agents/echo_agent/run.py"


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture()
def radice() -> Path:
    """Radice del repo reale: lo script dell'echo agent è quello vero."""
    return Path(__file__).resolve().parent.parent


@pytest.fixture()
def config(tmp_path: Path, radice: Path) -> Path:
    """Config che punta allo script reale, con log in una cartella temporanea."""
    percorso = tmp_path / "hermes.toml"
    percorso.write_text(
        textwrap.dedent(f"""\
            [server]
            agent = "echo_dummy"
            repo_root = "{radice}"
            log_path = "{tmp_path}/audit.jsonl"
            container_available = false

            [vault]
            backend = "stub"
            stub_secrets = ["ssh/lab-kali"]

            [[tool]]
            tool_id = "echo.ping"
            owner_agent = "echo_dummy"
            default_tier = "verde"
            personal_data = false
            requires_container = false
            exec_path = "{SCRIPT}"
            exec_sha256 = "{sha256_file(radice / SCRIPT)}"
            description = "Agente dummy."

            [[tool]]
            tool_id = "echo.rosso"
            owner_agent = "echo_dummy"
            default_tier = "rosso"
            personal_data = false
            requires_container = false
            exec_path = "{SCRIPT}"
            exec_sha256 = "{sha256_file(radice / SCRIPT)}"
            description = "Dummy a tier rosso."
            """),
        encoding="utf-8",
    )
    return percorso


@pytest.fixture()
def audit(tmp_path: Path) -> AuditLog:
    """Lo **stesso** log su cui scrive il processo dell'agente."""
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture()
def endpoint(config: Path, radice: Path) -> AgentEndpoint:
    return AgentEndpoint(
        agent=OwnerAgent.ECHO_DUMMY, config_path=config, cwd=radice
    )


@pytest.fixture()
def orchestratore(audit: AuditLog) -> Orchestrator:
    return Orchestrator(audit)


# --------------------------------------------------------------------------- #
# Lo script dell'echo agent
# --------------------------------------------------------------------------- #


def test_script_echo_senza_dipendenze(radice: Path):
    """Un tool è un eseguibile autonomo, non un modulo del server.

    Il gate esegue gli script senza PYTHONPATH e senza il virtualenv: uno
    script che importasse hermes-core funzionerebbe nei test e fallirebbe in
    esecuzione reale.
    """
    sorgente = (radice / SCRIPT).read_text(encoding="utf-8")
    assert "mcp_server" not in sorgente
    assert "import mcp" not in sorgente


def test_script_echo_emette_json(radice: Path):
    import json
    import subprocess
    import sys

    esito = subprocess.run(
        [sys.executable, str(radice / SCRIPT)],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(esito.stdout)
    assert payload["tool"] == "echo.ping"
    assert payload["findings"] == []


# --------------------------------------------------------------------------- #
# Validazione del risultato
# --------------------------------------------------------------------------- #


def test_risposta_senza_result_rifiutata(orchestratore, endpoint, audit):
    with pytest.raises(MalformedAgentResult, match="result"):
        orchestratore._valida({"qualcosa": "altro"}, uuid.uuid4(), endpoint)
    assert audit.read_all()[-1].outcome is CallOutcome.ERROR


def test_risposta_non_dict_rifiutata(orchestratore, endpoint):
    with pytest.raises(MalformedAgentResult):
        orchestratore._valida(None, uuid.uuid4(), endpoint)


def test_agentresult_non_conforme_rifiutato(orchestratore, endpoint, audit):
    """La risposta attraversa un confine di processo: è input, non verità."""
    with pytest.raises(MalformedAgentResult, match="non conforme"):
        orchestratore._valida(
            {"result": {"status": "ok", "summary": "mancano dei campi"}},
            uuid.uuid4(),
            endpoint,
        )
    assert audit.read_all()[-1].outcome is CallOutcome.ERROR


def test_agente_che_dichiara_altra_identita_rifiutato(orchestratore, endpoint, audit):
    """Un agente non può presentarsi come un altro."""
    cid = uuid.uuid4()
    payload = {
        "result": AgentResult(
            correlation_id=cid,
            agent=OwnerAgent.PENTEST_KALI,
            status=AgentStatus.OK,
            summary="mi dichiaro un altro agente",
        ).model_dump(mode="json")
    }
    with pytest.raises(MalformedAgentResult, match="identità incoerente"):
        orchestratore._valida(payload, cid, endpoint)
    assert "dichiarato" in audit.read_all()[-1].detail


def test_risultato_valido_accettato(orchestratore, endpoint):
    cid = uuid.uuid4()
    payload = {
        "result": AgentResult(
            correlation_id=cid,
            agent=OwnerAgent.ECHO_DUMMY,
            status=AgentStatus.OK,
            summary="tutto bene",
        ).model_dump(mode="json"),
        "output": {"stdout": "ciao", "stderr": "", "returncode": 0},
    }
    inv = orchestratore._valida(payload, cid, endpoint)
    assert isinstance(inv, Invocation)
    assert inv.riuscita is True
    assert inv.stdout == "ciao"


# --------------------------------------------------------------------------- #
# Catena completa
# --------------------------------------------------------------------------- #


@pytest.mark.slow
@pytest.mark.anyio
async def test_catena_completa(orchestratore, endpoint, audit):
    """Definition of done di M0: la catena intera, con esito strutturato."""
    inv = await orchestratore.invoca(endpoint, "echo.ping", target="lab-kali")

    assert inv.riuscita is True
    assert inv.result.agent is OwnerAgent.ECHO_DUMMY
    assert inv.result.tool_calls[0].tool_id == "echo.ping"
    assert inv.result.tool_calls[0].target == "lab-kali"
    assert "catena di esecuzione percorsa correttamente" in inv.stdout


@pytest.mark.slow
@pytest.mark.anyio
async def test_due_catene_collegate_da_entrambi_i_lati(
    orchestratore, endpoint, audit
):
    """Il requisito di M0 cambiato in qualcosa di più difendibile.

    Prima l'orchestratore imponeva il proprio `correlation_id` all'agente, e
    le righe dei due processi finivano sotto un'unica catena. Comodo da
    leggere, ma non difendibile: un client qualunque poteva dichiarare la
    catena di un'altra invocazione e scriverci dentro le proprie righe.

    Ora l'identità di una catena la decide chi scrive le righe, e il
    collegamento è annotato **in entrambe le direzioni** — quindi nessuno dei
    due lati può falsificarlo da solo.
    """
    cid = uuid.uuid4()
    inv = await orchestratore.invoca(endpoint, "echo.ping", correlation_id=cid)

    agente = inv.agent_correlation_id
    assert agente != cid, "l'agente non adotta l'identificativo del client"

    righe = audit.read_all()
    dell_orchestratore = [r for r in righe if r.correlation_id == cid]
    dell_agente = [r for r in righe if r.correlation_id == agente]

    assert dell_orchestratore, "l'orchestratore ha la propria catena"
    assert dell_agente, "l'agente ha la propria catena"

    # Collegamento annotato da entrambi i lati.
    assert any(
        r.peer_correlation_id == str(cid) for r in dell_agente
    ), "l'agente registra la catena dichiarata dal client"
    assert any(
        r.peer_correlation_id == str(agente) for r in dell_orchestratore
    ), "l'orchestratore registra la catena dell'agente"

    # Ciascuna catena è internamente coerente.
    assert {r.agent for r in dell_orchestratore} == {OwnerAgent.ORCHESTRATOR}
    azioni_agente = [r.action for r in dell_agente]
    assert LogAction.AGENT_INVOKED in azioni_agente
    assert LogAction.TOOL_CALL in azioni_agente
    assert LogAction.AGENT_RESULT in azioni_agente


@pytest.mark.slow
@pytest.mark.anyio
async def test_invocazione_ricostruibile_seguendo_il_collegamento(
    orchestratore, endpoint, audit
):
    """Ricostruire resta possibile: in due passi invece di uno.

    Si parte dalla catena dell'orchestratore, si legge il collegamento, e si
    arriva alle righe dell'agente. È l'operazione che un operatore fa in
    audit, e deve restare fattibile con un grep.
    """
    cid = uuid.uuid4()
    await orchestratore.invoca(endpoint, "echo.ping", target="lab-kali", correlation_id=cid)

    righe = audit.read_all()
    partenza = [r for r in righe if r.correlation_id == cid]
    collegamenti = {r.peer_correlation_id for r in partenza if r.peer_correlation_id}
    assert len(collegamenti) == 1, "un solo collegamento da seguire"

    # Estratto prima della comprehension: dentro, `pop()` verrebbe chiamato a
    # ogni iterazione e svuoterebbe l'insieme al primo giro.
    catena_agente = collegamenti.pop()
    arrivo = [r for r in righe if str(r.correlation_id) == catena_agente]
    esecuzioni = [r for r in arrivo if r.action is LogAction.TOOL_CALL]
    assert esecuzioni and esecuzioni[0].tool_id == "echo.ping"
    assert esecuzioni[0].target == "lab-kali"


@pytest.mark.slow
@pytest.mark.anyio
async def test_due_processi_scrivono_lo_stesso_log(orchestratore, endpoint, audit):
    """Il log append-only del passo 2 regge due scrittori senza lock."""
    await orchestratore.invoca(endpoint, "echo.ping")

    righe = audit.read_all()  # rilegge e valida: nessuna riga spezzata
    agenti = {r.agent for r in righe if r.agent is not None}
    assert OwnerAgent.ORCHESTRATOR in agenti
    assert OwnerAgent.ECHO_DUMMY in agenti


@pytest.mark.slow
@pytest.mark.anyio
async def test_elenco_tool_via_orchestratore(orchestratore, endpoint):
    tool = await orchestratore.elenca_tool(endpoint)
    assert {t["tool_id"] for t in tool} == {"echo.ping", "echo.rosso"}


@pytest.mark.slow
@pytest.mark.anyio
async def test_tool_rosso_sospeso_lungo_la_catena(orchestratore, endpoint, audit):
    """La sospensione arriva fino all'orchestratore come stato, non come errore."""
    cid = uuid.uuid4()
    inv = await orchestratore.invoca(endpoint, "echo.rosso", correlation_id=cid)

    assert inv.in_attesa_di_conferma is True
    assert inv.riuscita is False
    assert inv.result.tool_calls[0].outcome is CallOutcome.PENDING
    assert inv.output is None

    finale = [
        r
        for r in audit.read_all()
        if r.correlation_id == cid and r.action is LogAction.AGENT_RESULT
    ][-1]
    assert finale.outcome is CallOutcome.PENDING


@pytest.mark.slow
@pytest.mark.anyio
async def test_tool_inesistente_non_rompe_la_catena(orchestratore, endpoint):
    inv = await orchestratore.invoca(endpoint, "mai.registrato")
    assert inv.result.status is AgentStatus.ERROR
    assert inv.result.tool_calls == ()


@pytest.mark.slow
@pytest.mark.anyio
async def test_script_manomesso_fermato_lungo_la_catena(
    orchestratore, endpoint, tmp_path, radice
):
    """L'integrità regge anche a valle: lo script giusto, l'hash sbagliato."""
    config = tmp_path / "hermes-sha-errato.toml"
    config.write_text(
        textwrap.dedent(f"""\
            [server]
            agent = "echo_dummy"
            repo_root = "{radice}"
            log_path = "{tmp_path}/audit.jsonl"

            [[tool]]
            tool_id = "echo.ping"
            owner_agent = "echo_dummy"
            default_tier = "verde"
            personal_data = false
            requires_container = false
            exec_path = "{SCRIPT}"
            exec_sha256 = "{'0' * 64}"
            description = "Hash non corrispondente."
            """),
        encoding="utf-8",
    )
    endpoint_rotto = AgentEndpoint(
        agent=OwnerAgent.ECHO_DUMMY, config_path=config, cwd=radice
    )
    inv = await orchestratore.invoca(endpoint_rotto, "echo.ping")

    assert inv.result.status is AgentStatus.ERROR
    assert inv.result.tool_calls[0].outcome is CallOutcome.DENIED
