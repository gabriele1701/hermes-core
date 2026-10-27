"""Test dello store degli innalzamenti di tier (patch di sicurezza, passo 6a).

L'insieme dei test insiste su quattro proprietà, nell'ordine in cui
importano:

1. un innalzamento sopravvive alla connessione;
2. nessuna fonte può **abbassare** un tier, nemmeno un file manomesso;
3. il file non cresce: una riga per incremento reale, non per richiesta;
4. illeggibile non è vuoto — un file che non si apre non diventa «nessun
   innalzamento registrato».
"""

from __future__ import annotations

import json
import os
import uuid

import pytest

from mcp_server.audit import AuditLog, LogAction
from mcp_server.contracts import CallOutcome, OwnerAgent, RiskTier, ToolSpec
from mcp_server.overrides import (
    NOME_FILE,
    OverrideScope,
    OverrideStore,
    OverrideStoreError,
)
from mcp_server.registry import ToolRegistry

SHA = "a" * 64


def _spec(**override) -> ToolSpec:
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
    return ToolSpec(**(base | override))


@pytest.fixture()
def audit(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture()
def store(tmp_path) -> OverrideStore:
    return OverrideStore.in_directory(tmp_path / "stato")


# --------------------------------------------------------------------------- #
# Lo store da solo
# --------------------------------------------------------------------------- #


def test_costruttore_non_tocca_il_filesystem(tmp_path):
    """Costruire lo store non deve poter impedire l'avvio del server.

    Directory e file nascono alla prima scrittura: un componente che il server
    costruisce all'avvio non deve sollevare per un percorso non ancora creato.
    """
    store = OverrideStore.in_directory(tmp_path / "mai" / "creata")
    assert not (tmp_path / "mai").exists()
    assert store.carica().tiers == {}


def test_nome_file_convenzionale(tmp_path):
    assert OverrideStore.in_directory(tmp_path).path.name == NOME_FILE


def test_registra_e_rilegge(store: OverrideStore):
    store.registra("echo.ping", RiskTier.ROSSO, agent=OwnerAgent.ECHO_DUMMY)
    esito = store.carica()
    assert esito.tiers == {"echo.ping": RiskTier.ROSSO}
    assert esito.righe == 1
    assert esito.scartate == 0


def test_tiene_il_massimo_non_l_ultimo(store: OverrideStore):
    """Dello store importa il massimo per tool, non l'ordine delle righe.

    Serve perché una riga più bassa scritta dopo — da una versione futura, da
    un merge, da una manomissione — non deve declassare nulla.
    """
    store.registra("echo.ping", RiskTier.ROSSO)
    store.registra("echo.ping", RiskTier.GIALLO)
    assert store.carica().tiers["echo.ping"] is RiskTier.ROSSO


def test_permessi_restrittivi(store: OverrideStore):
    store.registra("echo.ping", RiskTier.GIALLO)
    assert os.stat(store.path).st_mode & 0o077 == 0
    assert os.stat(store.path.parent).st_mode & 0o077 == 0


def test_riga_malformata_saltata_e_contata(tmp_path):
    """Un file corrotto a metà non deve impedire l'avvio.

    Ma le righe scartate vanno **contate**: ciascuna potrebbe essere un
    innalzamento perduto, e un silenzio qui sarebbe un declassamento
    invisibile.
    """
    percorso = tmp_path / NOME_FILE
    percorso.write_text(
        "\n".join(
            [
                json.dumps({"tool_id": "a.uno", "tier": "rosso"}),
                "{non è json",
                json.dumps({"tool_id": "b.due", "tier": "viola"}),  # tier inventato
                json.dumps({"tier": "rosso"}),  # senza tool_id
                json.dumps({"tool_id": "", "tier": "rosso"}),  # tool_id vuoto
                json.dumps({"tool_id": "c.tre", "tier": "giallo"}),
                "",
            ]
        ),
        encoding="utf-8",
    )
    esito = OverrideStore(percorso).carica()
    assert esito.tiers == {"a.uno": RiskTier.ROSSO, "c.tre": RiskTier.GIALLO}
    assert esito.righe == 6
    assert esito.scartate == 4


def test_file_illeggibile_non_e_file_vuoto(tmp_path):
    """Illeggibile e assente non possono avere la stessa conseguenza.

    Assente significa «nessun innalzamento registrato». Illeggibile significa
    «non so quali innalzamenti ci sono», e trattarlo come il primo vorrebbe
    dire applicare tier più bassi di quelli registrati perché un file non si
    apriva.

    Il guasto è provocato con una **directory al posto del file** invece che
    con ``chmod 000``: i permessi non fermano root, e un test che si salta
    silenziosamente in CI o in un container non difende nulla. La clausola
    ``except OSError`` esercitata è la stessa.
    """
    percorso = tmp_path / NOME_FILE
    percorso.mkdir()
    with pytest.raises(OverrideStoreError, match="non leggibile"):
        OverrideStore(percorso).carica()


def test_scrittura_fallita_solleva_oserror(tmp_path):
    """Lo store non inghiotte un guasto di scrittura: lo fa risalire.

    Anche qui il guasto è di *forma* e non di permessi, per girare anche da
    root: la directory di stato è in realtà un file regolare.
    """
    finta_directory = tmp_path / "stato"
    finta_directory.write_text("non sono una directory\n", encoding="utf-8")
    with pytest.raises(OSError):
        OverrideStore.in_directory(finta_directory).registra(
            "echo.ping", RiskTier.ROSSO
        )


# --------------------------------------------------------------------------- #
# Lo store visto dal registro
# --------------------------------------------------------------------------- #


def test_innalzamento_sopravvive_alla_connessione(audit: AuditLog, store: OverrideStore):
    """È la ragione d'essere del passo: l'host riavvia il processo.

    Il secondo registro simula la connessione successiva: spec identica,
    processo nuovo, nessuno stato in memoria.
    """
    primo = ToolRegistry(audit, store=store)
    primo.register(_spec())
    primo.set_override("echo.ping", RiskTier.ROSSO)

    secondo = ToolRegistry(audit, store=store)
    secondo.register(_spec())
    assert secondo.effective_tier("echo.ping") is RiskTier.ROSSO
    assert secondo.override_scope("echo.ping") is OverrideScope.PERSISTENT


def test_senza_store_resta_di_sessione_e_lo_dichiara(audit: AuditLog):
    reg = ToolRegistry(audit)
    reg.register(_spec())
    reg.set_override("echo.ping", RiskTier.ROSSO)
    assert reg.override_scope("echo.ping") is OverrideScope.SESSION


def test_nessun_override_nessuno_scope(audit: AuditLog, store: OverrideStore):
    reg = ToolRegistry(audit, store=store)
    reg.register(_spec())
    assert reg.override_scope("echo.ping") is OverrideScope.NONE


def test_una_riga_per_incremento_non_per_richiesta(audit: AuditLog, store: OverrideStore):
    """Il tetto strutturale dello store, che è il motivo per cui non va ruotato.

    Mille richieste di 'rosso' producono una riga, non mille: si scrive solo
    quando il tier **sale davvero**. Le altre 999 restano nel log d'audit,
    dove è giusto che si vedano.
    """
    reg = ToolRegistry(audit, store=store)
    reg.register(_spec())
    for _ in range(1000):
        reg.set_override("echo.ping", RiskTier.ROSSO)

    assert store.path.read_text(encoding="utf-8").count("\n") == 1
    richieste = [
        r for r in audit.read_all() if r.action is LogAction.OVERRIDE_SET
    ]
    assert len(richieste) == 1000


def test_tetto_di_due_righe_per_tool(audit: AuditLog, store: OverrideStore):
    """Un tier può salire al massimo due volte: verde -> giallo -> rosso."""
    reg = ToolRegistry(audit, store=store)
    reg.register(_spec())
    for tier in (RiskTier.GIALLO, RiskTier.GIALLO, RiskTier.ROSSO, RiskTier.ROSSO):
        reg.set_override("echo.ping", tier)
    assert store.path.read_text(encoding="utf-8").count("\n") == 2


def test_scrittura_fallita_alza_comunque_ma_lo_dichiara(
    audit: AuditLog, tmp_path, monkeypatch
):
    """Un guasto di I/O non deve lasciare il tool al tier più basso.

    Chi chiede di trattare un tool come più rischioso ottiene il tier alzato
    in ogni caso; ciò che non si può fare è **tacere** che non durerà.
    """
    store = OverrideStore.in_directory(tmp_path / "stato")

    def rifiuta(*_args, **_kwargs):
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr(OverrideStore, "registra", rifiuta)
    reg = ToolRegistry(audit, store=store)
    reg.register(_spec())
    reg.set_override("echo.ping", RiskTier.ROSSO)

    assert reg.effective_tier("echo.ping") is RiskTier.ROSSO
    assert reg.override_scope("echo.ping") is OverrideScope.SESSION

    righe = [
        r for r in audit.read_all() if r.action is LogAction.OVERRIDE_NOT_PERSISTED
    ]
    assert len(righe) == 1
    assert righe[0].outcome is CallOutcome.ERROR
    assert "Read-only file system" in righe[0].detail


def test_store_illeggibile_impedisce_l_avvio_del_registro(audit: AuditLog, tmp_path):
    """Fail-closed: meglio un server che non parte di uno che declassa."""
    percorso = tmp_path / NOME_FILE
    percorso.mkdir()
    with pytest.raises(OverrideStoreError):
        ToolRegistry(audit, store=OverrideStore(percorso))


def test_caricamento_registrato_nel_log(audit: AuditLog, store: OverrideStore):
    store.registra("echo.ping", RiskTier.ROSSO)
    ToolRegistry(audit, store=store)
    righe = [
        r for r in audit.read_all() if r.action is LogAction.OVERRIDE_STORE_LOADED
    ]
    assert len(righe) == 1
    assert righe[0].outcome is CallOutcome.OK
    assert "1 righe" in righe[0].detail


def test_righe_scartate_segnalate_nel_log(audit: AuditLog, tmp_path):
    """Un innalzamento perduto deve essere visibile a chi legge il log."""
    percorso = tmp_path / NOME_FILE
    percorso.write_text("{rotta\n", encoding="utf-8")
    ToolRegistry(audit, store=OverrideStore(percorso))
    riga = [
        r for r in audit.read_all() if r.action is LogAction.OVERRIDE_STORE_LOADED
    ][0]
    assert riga.outcome is CallOutcome.ERROR
    assert "1 righe illeggibili" in riga.detail


def test_riga_contiene_attribuzione_e_catena(store: OverrideStore):
    """Chi ha chiesto l'innalzamento, e in quale catena: serve in audit."""
    correlazione = uuid.uuid4()
    store.registra(
        "echo.ping",
        RiskTier.ROSSO,
        agent=OwnerAgent.PENTEST_KALI,
        correlation_id=correlazione,
    )
    voce = json.loads(store.path.read_text(encoding="utf-8").strip())
    assert voce["agent"] == OwnerAgent.PENTEST_KALI.value
    assert voce["correlation_id"] == str(correlazione)
    assert voce["tier"] == RiskTier.ROSSO.value
    assert voce["ts"].endswith("+00:00")


def test_declassamento_rifiutato_non_scrive(audit: AuditLog, store: OverrideStore):
    from mcp_server.registry import OverrideRefused

    reg = ToolRegistry(audit, store=store)
    reg.register(_spec(default_tier=RiskTier.ROSSO))
    with pytest.raises(OverrideRefused):
        reg.set_override("echo.ping", RiskTier.VERDE)
    assert not store.path.exists()


def test_store_append_only_reale(tmp_path):
    """Con `chattr +a` applicato davvero, lo store deve restare scrivibile.

    Stessa verifica del log d'audit, e per lo stesso difetto già trovato sul
    campo: un file append-only rifiuta la `chmod` anche al proprietario, e un
    writer che insistesse si metterebbe fuori uso proprio irrigidendo ciò che
    protegge.

    Salta dove `chattr` non è disponibile o il filesystem non lo supporta.
    """
    import subprocess

    store = OverrideStore(tmp_path / NOME_FILE)
    store.registra("echo.ping", RiskTier.GIALLO)

    try:
        esito = subprocess.run(
            ["chattr", "+a", str(store.path)], capture_output=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        pytest.skip("chattr non disponibile")
    if esito.returncode != 0:
        pytest.skip("chattr +a non supportato su questo filesystem o privilegi")

    try:
        store.registra("echo.ping", RiskTier.ROSSO)
        assert store.carica().tiers["echo.ping"] is RiskTier.ROSSO
    finally:
        subprocess.run(["chattr", "-a", str(store.path)], capture_output=True, timeout=10)
        os.chmod(store.path, 0o600)


def test_nessuna_api_di_rimozione(store: OverrideStore):
    """Una rimozione comoda sarebbe un declassamento con un bel nome.

    Il test fissa un'assenza deliberata: una volta che un metodo del genere
    esiste, finisce per essere chiamato da qualcosa di automatico. Il
    declassamento resta una procedura manuale e privilegiata, documentata in
    ``docs/setup-vm-hermes.md``.
    """
    vietati = {"rimuovi", "remove", "cancella", "delete", "abbassa", "reset"}
    assert vietati.isdisjoint(dir(store))


def test_nota_persistente_dice_che_non_si_torna_indietro(audit: AuditLog, store):
    """Chi alza un tier deve sapere subito che non lo annulla da lì.

    È la valvola di sfogo che la persistenza ha tolto: prima un innalzamento
    sbagliato si curava riconnettendosi.
    """
    from mcp_server.server import NOTE_DURATA

    nota = NOTE_DURATA[OverrideScope.PERSISTENT]
    assert "non è annullabile da questa interfaccia" in nota
    assert "amministratore" in nota
