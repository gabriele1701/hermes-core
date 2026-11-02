"""Test del gate di esecuzione (M0 passo 6a).

Chiude il debito ALTA su ``exec_sha256``: lo SHA dichiarato viene
effettivamente verificato, e **a ogni esecuzione**. I test insistono sui
modi in cui un'esecuzione deve essere negata, perché un gate si giudica da
cosa ferma, non da cosa lascia passare.
"""

from __future__ import annotations

import subprocess
import time
import uuid
from pathlib import Path

import pytest

from mcp_server.audit import AuditLog, LogAction
from mcp_server.contracts import AuthorizedBy, CallOutcome, OwnerAgent, RiskTier, ToolSpec
from mcp_server.config import TOOL_PYTHON_DEFAULT
from mcp_server.executor import (
    ConcurrencyLimitReached,
    ConfirmationRequired,
    ContainerUnavailable,
    IntegrityMismatch,
    RunResult,
    SharedSlotsUnusable,
    SubprocessRunner,
    ToolExecutor,
    ambiente_minimo,
    risolvi_script,
    sha256_file,
)
from mcp_server.registry import InvocationRefused, ToolNotRegistered, ToolRegistry

SCRIPT = "tools/echo.py"
SORGENTE = "import sys\nprint('ok')\nsys.exit(0)\n"


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    (tmp_path / "tools").mkdir()
    (tmp_path / SCRIPT).write_text(SORGENTE, encoding="utf-8")
    return tmp_path


@pytest.fixture()
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "logs" / "audit.jsonl")


@pytest.fixture()
def registry(audit: AuditLog) -> ToolRegistry:
    return ToolRegistry(audit)


class RunnerFinto:
    """Runner che registra come è stato invocato, senza eseguire nulla."""

    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.chiamate: list[dict] = []

    def run(self, argv, *, cwd, env, timeout) -> RunResult:
        self.chiamate.append({"argv": argv, "cwd": cwd, "env": env, "timeout": timeout})
        return RunResult(returncode=self.returncode, stdout="ok", stderr="")


def _spec(repo: Path, **override) -> ToolSpec:
    base = {
        "tool_id": "echo.ping",
        "owner_agent": OwnerAgent.ECHO_DUMMY,
        "default_tier": RiskTier.VERDE,
        "personal_data": False,
        "requires_container": False,
        "exec_path": SCRIPT,
        "exec_sha256": sha256_file(repo / SCRIPT),
        "description": "Tool dummy.",
    }
    return ToolSpec(**(base | override))


def _executor(registry, audit, repo, **kw) -> ToolExecutor:
    kw.setdefault("runner", RunnerFinto())
    return ToolExecutor(registry, audit, repo_root=repo, **kw)


def _negati(audit: AuditLog):
    return [r for r in audit.read_all() if r.outcome is CallOutcome.DENIED]


# --------------------------------------------------------------------------- #
# Hash e confinamento
# --------------------------------------------------------------------------- #


def test_sha256_file(repo: Path):
    import hashlib

    atteso = hashlib.sha256(SORGENTE.encode()).hexdigest()
    assert sha256_file(repo / SCRIPT) == atteso


def test_risolvi_script_dentro_il_repo(repo: Path):
    assert risolvi_script(repo, SCRIPT) == (repo / SCRIPT).resolve()


def test_symlink_fuori_dal_repo_rifiutato(repo: Path, tmp_path: Path):
    """Il contratto valida la stringa; qui si guarda dove il filesystem va.

    Un symlink dentro il repo che punta fuori passa la validazione sintattica
    di exec_path: lo ferma solo la risoluzione del percorso.
    """
    esterno = tmp_path.parent / "esterno.py"
    esterno.write_text("print('fuori')", encoding="utf-8")
    (repo / "tools" / "evaso.py").symlink_to(esterno)

    with pytest.raises(IntegrityMismatch, match="esce dalla radice"):
        risolvi_script(repo, "tools/evaso.py")


def test_script_assente_rifiutato(repo: Path):
    with pytest.raises(IntegrityMismatch, match="assente"):
        risolvi_script(repo, "tools/mai-esistito.py")


def test_directory_non_e_uno_script(repo: Path):
    with pytest.raises(IntegrityMismatch):
        risolvi_script(repo, "tools")


# --------------------------------------------------------------------------- #
# Integrità verificata a ogni esecuzione
# --------------------------------------------------------------------------- #


def test_esecuzione_con_integrita_valida(repo, registry, audit):
    registry.register(_spec(repo))
    ex = _executor(registry, audit, repo)
    call, esito = ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())
    assert call.outcome is CallOutcome.OK
    assert call.authorized_by is AuthorizedBy.POLICY
    assert esito.returncode == 0


def test_script_modificato_dopo_la_registrazione_negato(repo, registry, audit):
    """Il cuore del debito ALTA: senza questo, il pinning è un commento."""
    registry.register(_spec(repo))
    ex = _executor(registry, audit, repo)

    (repo / SCRIPT).write_text("print('manomesso')\n", encoding="utf-8")

    with pytest.raises(IntegrityMismatch):
        ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())
    assert "integrità fallita" in _negati(audit)[-1].detail


def test_integrita_verificata_a_ogni_esecuzione_non_solo_la_prima(repo, registry, audit):
    """Un controllo solo all'avvio lascerebbe aperta la finestra successiva."""
    registry.register(_spec(repo))
    runner = RunnerFinto()
    ex = _executor(registry, audit, repo, runner=runner)
    cid = uuid.uuid4()

    ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=cid)
    (repo / SCRIPT).write_text("print('manomesso dopo la prima')\n", encoding="utf-8")
    with pytest.raises(IntegrityMismatch):
        ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=cid)

    assert len(runner.chiamate) == 1  # la seconda non è mai partita


def test_sha_dichiarato_errato_negato(repo, registry, audit):
    registry.register(_spec(repo, exec_sha256="f" * 64))
    ex = _executor(registry, audit, repo)
    with pytest.raises(IntegrityMismatch):
        ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())


def test_script_mancante_negato_e_loggato(repo, registry, audit):
    registry.register(_spec(repo))
    (repo / SCRIPT).unlink()
    ex = _executor(registry, audit, repo)
    with pytest.raises(IntegrityMismatch):
        ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())
    assert _negati(audit)


# --------------------------------------------------------------------------- #
# Isolamento: mai degradare verso l'host
# --------------------------------------------------------------------------- #


def test_container_richiesto_e_assente_nega(repo, registry, audit):
    """La degradazione silenziosa verso l'host è il guasto da impedire."""
    registry.register(_spec(repo, requires_container=True))
    runner = RunnerFinto()
    ex = _executor(registry, audit, repo, container_available=False, runner=runner)

    with pytest.raises(ContainerUnavailable):
        ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())

    assert runner.chiamate == []
    assert "container isolato" in _negati(audit)[-1].detail


def test_container_richiesto_e_presente_procede(repo, registry, audit):
    registry.register(_spec(repo, requires_container=True))
    ex = _executor(registry, audit, repo, container_available=True)
    call, _ = ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())
    assert call.outcome is CallOutcome.OK


def test_container_non_richiesto_indifferente(repo, registry, audit):
    registry.register(_spec(repo, requires_container=False))
    ex = _executor(registry, audit, repo, container_available=False)
    call, _ = ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())
    assert call.outcome is CallOutcome.OK


# --------------------------------------------------------------------------- #
# Autorizzazione
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("tier", [RiskTier.GIALLO, RiskTier.ROSSO])
def test_conferma_richiesta_sospende(repo, registry, audit, tier):
    registry.register(_spec(repo, default_tier=tier))
    runner = RunnerFinto()
    ex = _executor(registry, audit, repo, runner=runner)

    with pytest.raises(ConfirmationRequired):
        ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())

    assert runner.chiamate == []
    riga = audit.read_all()[-1]
    assert riga.outcome is CallOutcome.PENDING
    assert riga.authorized_by is AuthorizedBy.NONE


def test_conferma_fornita_esegue(repo, registry, audit):
    registry.register(_spec(repo, default_tier=RiskTier.ROSSO))
    ex = _executor(registry, audit, repo)
    call, _ = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4(), confirmed=True
    )
    assert call.outcome is CallOutcome.OK
    assert call.authorized_by is AuthorizedBy.USER


def test_dati_personali_richiedono_conferma_anche_su_verde(repo, registry, audit):
    """I due assi restano indipendenti fin dentro il gate."""
    registry.register(_spec(repo, default_tier=RiskTier.VERDE, personal_data=True))
    ex = _executor(registry, audit, repo)
    with pytest.raises(ConfirmationRequired):
        ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())


def test_override_rende_necessaria_la_conferma(repo, registry, audit):
    """Il gate segue il tier effettivo, non il dichiarato."""
    registry.register(_spec(repo, default_tier=RiskTier.VERDE))
    ex = _executor(registry, audit, repo)
    ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())

    registry.set_override("echo.ping", RiskTier.ROSSO)
    with pytest.raises(ConfirmationRequired):
        ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())


def test_integrita_precede_autorizzazione(repo, registry, audit):
    """Non si chiede di autorizzare uno script la cui identità non è verificata."""
    registry.register(_spec(repo, default_tier=RiskTier.ROSSO))
    (repo / SCRIPT).write_text("print('manomesso')\n", encoding="utf-8")
    ex = _executor(registry, audit, repo)

    with pytest.raises(IntegrityMismatch):
        ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())

    assert not [r for r in audit.read_all() if r.outcome is CallOutcome.PENDING]


# --------------------------------------------------------------------------- #
# Controlli ereditati dal registro
# --------------------------------------------------------------------------- #


def test_tool_sconosciuto_negato(repo, registry, audit):
    ex = _executor(registry, audit, repo)
    with pytest.raises(ToolNotRegistered):
        ex.execute("mai.registrato", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())


def test_agente_sbagliato_negato(repo, registry, audit):
    registry.register(_spec(repo, owner_agent=OwnerAgent.VULN_ASSESSMENT))
    runner = RunnerFinto()
    ex = _executor(registry, audit, repo, runner=runner)
    with pytest.raises(InvocationRefused):
        ex.execute("echo.ping", OwnerAgent.PENTEST_KALI, correlation_id=uuid.uuid4())
    assert runner.chiamate == []


# --------------------------------------------------------------------------- #
# Minimo privilegio nell'esecuzione
# --------------------------------------------------------------------------- #


def test_ambiente_e_una_lista_bianca(monkeypatch):
    """L'ambiente del server può contenere credenziali: non va ereditato."""
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "non-deve-passare")
    env = ambiente_minimo()
    assert env["PATH"] == "/usr/bin"
    assert "AWS_SECRET_ACCESS_KEY" not in env


def test_tool_riceve_ambiente_ridotto(repo, registry, audit, monkeypatch):
    monkeypatch.setenv("TOKEN_SEGRETO", "non-deve-passare")
    registry.register(_spec(repo))
    runner = RunnerFinto()
    _executor(registry, audit, repo, runner=runner).execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
    )
    assert "TOKEN_SEGRETO" not in runner.chiamate[0]["env"]


def test_esecuzione_senza_shell(repo, registry, audit):
    """argv esplicito: nessuna stringa interpretata da una shell."""
    registry.register(_spec(repo))
    runner = RunnerFinto()
    _executor(registry, audit, repo, runner=runner).execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
    )
    argv = runner.chiamate[0]["argv"]
    assert isinstance(argv, list)
    assert argv[-1].endswith("echo.py")


# --------------------------------------------------------------------------- #
# L'interprete è deciso, non ereditato
# --------------------------------------------------------------------------- #


def test_interprete_assoluto_e_isolato_per_default(repo, registry, audit):
    """Mai `python3` dal PATH: quale codice gira è una decisione, non un caso."""
    registry.register(_spec(repo))
    runner = RunnerFinto()
    _executor(registry, audit, repo, runner=runner).execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
    )
    argv = runner.chiamate[0]["argv"]
    assert Path(argv[0]).is_absolute(), "l'interprete non va risolto dal PATH"
    assert argv[0] == str(TOOL_PYTHON_DEFAULT)
    assert "-I" in argv and "-S" in argv


def test_interprete_configurabile(repo, registry, audit):
    registry.register(_spec(repo))
    runner = RunnerFinto()
    ex = ToolExecutor(
        registry,
        audit,
        repo_root=repo,
        runner=runner,
        tool_python="/usr/bin/python3.13",
        tool_python_flags=("-I",),
    )
    ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())
    argv = runner.chiamate[0]["argv"]
    assert argv[0] == "/usr/bin/python3.13"
    assert argv[1:-1] == ["-I"]
    assert ex.tool_python == Path("/usr/bin/python3.13")
    assert ex.tool_python_flags == ("-I",)


def test_modulo_omonimo_non_sostituisce_la_stdlib(repo, registry, audit):
    """Il vettore confermato dal security review: `json.py` accanto allo script.

    La directory dello script era in testa a `sys.path`, quindi un modulo
    omonimo rimpiazzava la libreria standard — con lo SHA dello script
    invariato e la verifica d'integrità superata. `-I` esclude quella
    directory da `sys.path`.
    """
    (repo / SCRIPT).write_text(
        "import json\nprint(json.dumps({'x': 1}))\n", encoding="utf-8"
    )
    (repo / "tools" / "json.py").write_text(
        "def dumps(*a, **k):\n    return 'SOSTITUITA'\n", encoding="utf-8"
    )
    registry.register(_spec(repo))
    ex = ToolExecutor(registry, audit, repo_root=repo, runner=SubprocessRunner())

    call, esito = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
    )
    assert call.outcome is CallOutcome.OK
    assert "SOSTITUITA" not in esito.stdout
    assert '{"x": 1}' in esito.stdout


def test_user_site_escluso(repo, registry, audit):
    """`-I` esclude lo user site, dove l'utente di servizio può scrivere.

    È la via con cui un tool compromesso otterrebbe esecuzione in ogni tool
    futuro — un `.pth` eseguito prima dello script — senza toccare nessuno
    SHA.
    """
    (repo / SCRIPT).write_text(
        "import sys, pathlib\n"
        "print('isolated', sys.flags.isolated)\n"
        "print('no_site', sys.flags.no_site)\n"
        "dirscript = str(pathlib.Path(__file__).resolve().parent)\n"
        "print('dir_script_in_path', dirscript in [str(p) for p in sys.path])\n"
        "print('user_site_in_path', any('.local' in str(p) for p in sys.path))\n",
        encoding="utf-8",
    )
    registry.register(_spec(repo))
    ex = ToolExecutor(registry, audit, repo_root=repo, runner=SubprocessRunner())
    _, esito = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
    )
    # Con -S il modulo `site` non viene mai inizializzato: più forte di
    # "user site disattivato", perché non c'è nemmeno la fase in cui i .pth
    # verrebbero letti.
    assert "isolated 1" in esito.stdout
    assert "no_site 1" in esito.stdout
    assert "dir_script_in_path False" in esito.stdout
    assert "user_site_in_path False" in esito.stdout


def test_echo_agent_reale_gira_isolato(registry, audit):
    """Il tool che consegniamo deve funzionare coi flag più stretti.

    Verifica il vincolo dichiarato in `agents/echo_agent/run.py`: un tool è un
    eseguibile autonomo, che usa solo la libreria standard.
    """
    import json

    radice = Path(__file__).resolve().parent.parent
    reale = "agents/echo_agent/run.py"
    registry.register(
        ToolSpec(
            tool_id="echo.ping",
            owner_agent=OwnerAgent.ECHO_DUMMY,
            default_tier=RiskTier.VERDE,
            personal_data=False,
            requires_container=False,
            exec_path=reale,
            exec_sha256=sha256_file(radice / reale),
            description="Echo agent reale.",
        )
    )
    ex = ToolExecutor(registry, audit, repo_root=radice, runner=SubprocessRunner())
    call, esito = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
    )
    assert call.outcome is CallOutcome.OK
    assert json.loads(esito.stdout)["tool"] == "echo.ping"


def test_timeout_propagato(repo, registry, audit):
    registry.register(_spec(repo))
    runner = RunnerFinto()
    _executor(registry, audit, repo, runner=runner).execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4(), timeout=7
    )
    assert runner.chiamate[0]["timeout"] == 7


def test_timeout_scaduto_e_errore_non_successo(repo, registry, audit):
    class RunnerLento:
        def run(self, argv, *, cwd, env, timeout):
            raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)

    registry.register(_spec(repo))
    ex = _executor(registry, audit, repo, runner=RunnerLento())
    call, esito = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4(), timeout=1
    )
    assert call.outcome is CallOutcome.ERROR
    assert esito.returncode == -1


def test_exit_non_zero_e_errore(repo, registry, audit):
    registry.register(_spec(repo))
    ex = _executor(registry, audit, repo, runner=RunnerFinto(returncode=3))
    call, _ = ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())
    assert call.outcome is CallOutcome.ERROR
    assert "exit=3" in call.detail


# --------------------------------------------------------------------------- #
# Nessuna esecuzione senza traccia
# --------------------------------------------------------------------------- #


def test_output_non_utf8_resta_tracciato(repo, registry, audit):
    """Il caso del security review: un byte fuori posto cancellava la riga.

    Lo script produce un effetto osservabile e poi scrive byte non
    decodificabili. Con `text=True` la decodifica strict sollevava
    UnicodeDecodeError **dopo** l'esecuzione: lo script aveva agito, ma nel
    log non c'era alcuna `tool_call`. Non serve un attaccante — basta un
    banner binario da un host scansionato.
    """
    (repo / SCRIPT).write_text(
        "import sys, pathlib\n"
        "pathlib.Path(__file__).parent.joinpath('MARKER').write_text('x')\n"
        "sys.stdout.buffer.write(b'banner \\xff\\xfe')\n",
        encoding="utf-8",
    )
    registry.register(_spec(repo))
    ex = ToolExecutor(registry, audit, repo_root=repo, runner=SubprocessRunner())

    call, esito = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
    )

    assert (repo / "tools" / "MARKER").exists(), "lo script deve avere agito"
    tracciate = [r for r in audit.read_all() if r.action is LogAction.TOOL_CALL]
    assert len(tracciate) == 1, "l'esecuzione deve lasciare esattamente una riga"
    assert call.outcome is CallOutcome.OK
    assert "�" in esito.stdout, "i byte invalidi diventano sostituzioni"
    assert "banner" in esito.stdout


def test_decodifica_tollerante_su_stderr(repo, registry, audit):
    (repo / SCRIPT).write_text(
        "import sys\nsys.stderr.buffer.write(b'\\xff\\xfe')\nsys.exit(0)\n",
        encoding="utf-8",
    )
    registry.register(_spec(repo))
    ex = ToolExecutor(registry, audit, repo_root=repo, runner=SubprocessRunner())
    call, esito = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
    )
    assert call.outcome is CallOutcome.OK
    assert "�" in esito.stderr


def test_eccezione_del_runner_dopo_lo_spawn_resta_tracciata(repo, registry, audit):
    """Dopo lo spawn il processo può essere già partito: niente deve sfuggire."""

    class RunnerGuasto:
        def run(self, argv, *, cwd, env, timeout):
            raise RuntimeError("guasto a metà esecuzione")

    registry.register(_spec(repo))
    ex = _executor(registry, audit, repo, runner=RunnerGuasto())

    call, esito = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
    )
    assert call.outcome is CallOutcome.ERROR
    assert "RuntimeError" in call.detail
    assert esito.returncode == -1
    assert [r.action for r in audit.read_all()].count(LogAction.TOOL_CALL) == 1


def test_interprete_mancante_resta_tracciato(repo, registry, audit):
    """FileNotFoundError sull'interprete non deve risalire come eccezione."""

    class RunnerSenzaInterprete:
        def run(self, argv, *, cwd, env, timeout):
            raise FileNotFoundError(2, "No such file or directory", argv[0])

    registry.register(_spec(repo))
    ex = _executor(registry, audit, repo, runner=RunnerSenzaInterprete())
    call, _ = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
    )
    assert call.outcome is CallOutcome.ERROR
    assert "FileNotFoundError" in call.detail


def test_interruzione_lascia_la_riga_prima_di_risalire(repo, registry, audit):
    """Un KeyboardInterrupt viene ri-sollevato, ma solo dopo aver tracciato."""

    class RunnerInterrotto:
        def run(self, argv, *, cwd, env, timeout):
            raise KeyboardInterrupt

    registry.register(_spec(repo))
    ex = _executor(registry, audit, repo, runner=RunnerInterrotto())

    with pytest.raises(KeyboardInterrupt):
        ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())

    tracciate = [r for r in audit.read_all() if r.action is LogAction.TOOL_CALL]
    assert len(tracciate) == 1
    assert tracciate[0].outcome is CallOutcome.ERROR


def test_errori_del_gate_non_producono_righe_di_esecuzione(repo, registry, audit):
    """Chi non supera il gate non ha eseguito: la sua riga è `denied`, non `error`.

    Serve a non confondere le due cose: 'negato prima di partire' e 'partito e
    andato male' sono stati diversi, e il log deve distinguerli.
    """
    registry.register(_spec(repo, exec_sha256="f" * 64))
    runner = RunnerFinto()
    ex = _executor(registry, audit, repo, runner=runner)

    with pytest.raises(IntegrityMismatch):
        ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())

    assert runner.chiamate == []
    righe = [r for r in audit.read_all() if r.action is LogAction.TOOL_CALL]
    assert [r.outcome for r in righe] == [CallOutcome.DENIED]


# --------------------------------------------------------------------------- #
# Contenimento dei processi
# --------------------------------------------------------------------------- #


def test_stdin_del_tool_e_devnull(repo, registry, audit):
    """Su stdio, lo stdin del server è il canale MCP: il tool non deve vederlo.

    Trovato verificando il report: un figlio che eredita fd 0 può leggere — e
    quindi *consumare* — i byte che l'host sta inviando. Verificato prima
    della correzione: il tool riceveva
    `{"jsonrpc":"2.0","id":1,"method":"initia…`.

    Conseguenze: il server perde input e la sessione si corrompe, e il tool
    vede ciò che il client manda, che con l'elicitation comprenderà le
    risposte dell'utente alle richieste di conferma.
    """
    (repo / SCRIPT).write_text(
        "import sys\nprint('letto da stdin:', repr(sys.stdin.read()))\n",
        encoding="utf-8",
    )
    registry.register(_spec(repo))
    ex = ToolExecutor(registry, audit, repo_root=repo, runner=SubprocessRunner())
    _, esito = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
    )
    assert "letto da stdin: ''" in esito.stdout


def test_discendenza_terminata_al_timeout(repo, registry, audit):
    """Il report lo ha confermato: `subprocess` uccideva solo il figlio diretto.

    Un tool che ha lanciato qualcosa a sua volta — nmap dentro uno script —
    lasciava quel qualcosa vivo e adottato da init, mentre il log dichiarava
    l'esecuzione terminata. Una scansione «conclusa» che continua a girare è
    peggio di un errore, perché nessuno la sta più guardando.
    """
    import subprocess as sp

    marcatore = f"hermes-orfano-{uuid.uuid4().hex[:8]}"
    (repo / SCRIPT).write_text(
        "import subprocess, time, sys\n"
        f"subprocess.Popen(['sleep', '47'], stdout=subprocess.DEVNULL)\n"
        f"sys.stderr.write({marcatore!r})\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    registry.register(_spec(repo))
    ex = ToolExecutor(registry, audit, repo_root=repo, runner=SubprocessRunner())

    call, _ = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4(), timeout=2
    )
    assert call.outcome is CallOutcome.ERROR
    assert "timeout" in call.detail

    time.sleep(0.5)
    vivi = sp.run(["pgrep", "-f", "sleep 47"], capture_output=True, text=True)
    try:
        assert vivi.stdout.strip() == "", f"processi orfani: {vivi.stdout!r}"
    finally:
        sp.run(["pkill", "-f", "sleep 47"], capture_output=True)


def test_output_troncato_e_dichiarato(repo, registry, audit):
    """Un output troncato in silenzio fa trarre conclusioni sbagliate."""
    (repo / SCRIPT).write_text(
        "import sys\nsys.stdout.write('A' * 50000)\n", encoding="utf-8"
    )
    registry.register(_spec(repo))
    ex = ToolExecutor(
        registry,
        audit,
        repo_root=repo,
        runner=SubprocessRunner(max_output_bytes=1024),
        max_output_bytes=1024,
    )
    call, esito = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
    )
    assert len(esito.stdout) == 1024
    assert esito.truncated is True
    assert "troncato" in call.detail
    riga = [r for r in audit.read_all() if r.action is LogAction.TOOL_CALL][-1]
    assert "troncato" in riga.detail


def test_output_sotto_il_tetto_non_e_troncato(repo, registry, audit):
    registry.register(_spec(repo))
    ex = ToolExecutor(registry, audit, repo_root=repo, runner=SubprocessRunner())
    _, esito = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
    )
    assert esito.truncated is False


def test_limite_di_concorrenza_rifiuta_e_traccia(repo, registry, audit):
    """Un modello in ciclo deve ricevere un rifiuto, non saturare il server."""
    import threading

    (repo / SCRIPT).write_text("import time\ntime.sleep(3)\n", encoding="utf-8")
    registry.register(_spec(repo))
    ex = ToolExecutor(
        registry,
        audit,
        repo_root=repo,
        runner=SubprocessRunner(),
        max_concurrent=1,
    )

    partito = threading.Event()
    esiti: list[str] = []

    def occupa():
        partito.set()
        try:
            ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4(), timeout=5)
            esiti.append("primo-ok")
        except Exception as err:  # pragma: no cover
            esiti.append(f"primo-{type(err).__name__}")

    t = threading.Thread(target=occupa, daemon=True)
    t.start()
    partito.wait(timeout=5)
    time.sleep(0.4)  # il primo ha preso il posto

    with pytest.raises(ConcurrencyLimitReached):
        ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())

    negate = [
        r
        for r in audit.read_all()
        if r.action is LogAction.TOOL_CALL and r.outcome is CallOutcome.DENIED
    ]
    assert negate and "contemporanee" in negate[-1].detail
    t.join(timeout=10)


def test_il_posto_viene_restituito_dopo_l_esecuzione(repo, registry, audit):
    """Senza release il server si bloccherebbe dopo N invocazioni."""
    registry.register(_spec(repo))
    ex = ToolExecutor(
        registry, audit, repo_root=repo, runner=SubprocessRunner(), max_concurrent=1
    )
    for _ in range(4):
        call, _ = ex.execute(
            "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
        )
        assert call.outcome is CallOutcome.OK


def test_il_posto_viene_restituito_anche_dopo_un_errore(repo, registry, audit):
    class RunnerGuasto:
        def run(self, argv, *, cwd, env, timeout):
            raise RuntimeError("guasto")

    registry.register(_spec(repo))
    ex = _executor(registry, audit, repo, runner=RunnerGuasto(), max_concurrent=1)
    for _ in range(3):
        call, _ = ex.execute(
            "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
        )
        assert call.outcome is CallOutcome.ERROR


def test_limiti_introspezionabili(repo, registry, audit):
    ex = ToolExecutor(
        registry,
        audit,
        repo_root=repo,
        max_output_bytes=2048,
        max_concurrent=3,
    )
    assert ex.max_output_bytes == 2048
    assert ex.max_concurrent == 3


# --------------------------------------------------------------------------- #
# Tracciamento
# --------------------------------------------------------------------------- #


def test_toolcall_pronta_per_agentresult(repo, registry, audit):
    registry.register(_spec(repo))
    ex = _executor(registry, audit, repo)
    cid = uuid.uuid4()
    call, _ = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=cid, target="lab-kali"
    )
    assert call.tool_id == "echo.ping"
    assert call.target == "lab-kali"
    assert call.tier_effective is RiskTier.VERDE


def test_ogni_decisione_sotto_il_correlation_id(repo, registry, audit):
    registry.register(_spec(repo))
    cid = uuid.uuid4()
    _executor(registry, audit, repo).execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=cid
    )
    esecuzione = [r for r in audit.read_all() if r.action is LogAction.TOOL_CALL]
    assert esecuzione and all(r.correlation_id == cid for r in esecuzione)


# --------------------------------------------------------------------------- #
# Runner reale
# --------------------------------------------------------------------------- #


def test_runner_reale_esegue_davvero(repo, registry, audit):
    """Un passaggio end-to-end col subprocess vero, non col finto."""
    registry.register(_spec(repo))
    ex = ToolExecutor(registry, audit, repo_root=repo, runner=SubprocessRunner())
    call, esito = ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())
    assert call.outcome is CallOutcome.OK
    assert esito.stdout.strip() == "ok"


# --------------------------------------------------------------------------- #
# Posti condivisi fra processi (patch di sicurezza, passo 6b)
# --------------------------------------------------------------------------- #


def test_posto_occupato_da_un_altro_processo_rifiuta(repo, registry, audit, tmp_path):
    """Il limite ora vale anche fra le connessioni, non solo nel processo.

    Il posto viene occupato da un processo **vero**, perché è esattamente ciò
    che il semaforo in memoria non poteva vedere.
    """
    import subprocess as sp
    import sys as _sys

    from mcp_server.slots import SlotPool

    pool = SlotPool(tmp_path / "slots", 1)
    pool.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    occupante = sp.Popen(
        [
            _sys.executable,
            "-c",
            "import fcntl,os,sys,time\n"
            "fd=os.open(sys.argv[1], os.O_RDWR|os.O_CREAT, 0o600)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\n"
            "sys.stdout.write('preso\\n'); sys.stdout.flush()\n"
            "time.sleep(300)\n",
            str(pool.percorso(0)),
        ],
        stdout=sp.PIPE,
        text=True,
    )
    assert occupante.stdout.readline().strip() == "preso"

    try:
        registry.register(_spec(repo))
        ex = ToolExecutor(
            registry,
            audit,
            repo_root=repo,
            runner=RunnerFinto(),
            max_concurrent=1,
            slots=pool,
        )
        assert ex.concorrenza_condivisa is True
        # Il messaggio dell'eccezione è quello che arriva al modello, e deve
        # dire che qui riprovare ha senso — all'opposto dei posti rotti.
        with pytest.raises(ConcurrencyLimitReached, match="Riprovare ha senso"):
            ex.execute(
                "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
            )
    finally:
        occupante.kill()
        occupante.wait(timeout=10)

    negate = [
        r
        for r in audit.read_all()
        if r.outcome is CallOutcome.DENIED and "connessioni dell'agente" in r.detail
    ]
    assert len(negate) == 1


def test_rifiuto_condiviso_restituisce_il_posto_di_processo(
    repo, registry, audit, tmp_path
):
    """Il semaforo va rilasciato anche quando a negare è il lock condiviso.

    Senza, ogni rifiuto consumerebbe un posto in memoria per sempre: dopo N
    rifiuti il processo non eseguirebbe più nulla, cioè un controllo che si
    auto-esaurisce.
    """
    from mcp_server.slots import SlotPool

    pool = SlotPool(tmp_path / "slots", 1)
    registry.register(_spec(repo))
    ex = ToolExecutor(
        registry,
        audit,
        repo_root=repo,
        runner=RunnerFinto(),
        max_concurrent=1,
        slots=pool,
    )

    with pool.acquire():
        for _ in range(3):
            with pytest.raises(ConcurrencyLimitReached):
                ex.execute(
                    "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
                )

    # Liberato il posto condiviso, il processo deve poter ancora eseguire.
    call, _ = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
    )
    assert call.outcome is CallOutcome.OK


def test_pool_inutilizzabile_nega_e_non_esegue(repo, registry, audit, tmp_path):
    """Posti configurati e rotti: si rifiuta, non si degrada.

    Degradare avrebbe fatto girare il tool oltre il tetto che la
    configurazione dichiara, e l'avrebbe fatto proprio quando la macchina ha
    già un guasto — con una risposta che non dà a nessuno motivo di
    sospettarlo. Il rifiuto è una riga del gate come le altre, correlata
    all'invocazione: la prova che non basta che l'evento sia registrato, deve
    essere anche ricollegabile.
    """
    from mcp_server.slots import SlotPool

    blocco = tmp_path / "slots"
    blocco.write_text("non sono una directory\n", encoding="utf-8")

    registry.register(_spec(repo))
    runner = RunnerFinto()
    correlation_id = uuid.uuid4()
    ex = ToolExecutor(
        registry,
        audit,
        repo_root=repo,
        runner=runner,
        max_concurrent=1,
        slots=SlotPool(blocco, 1),
    )
    with pytest.raises(SharedSlotsUnusable) as sollevata:
        ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=correlation_id)

    # Il messaggio dell'eccezione è ciò che legge il modello: la frase che gli
    # impedisce di riprovare in ciclo deve stare lì, non solo nel log.
    assert "non eseguita" in str(sollevata.value)
    assert "Riprovare non cambia l'esito" in str(sollevata.value)

    # Nulla è partito: è la differenza fra un rifiuto e un degrado.
    assert runner.chiamate == []

    righe = [
        r
        for r in audit.read_all()
        if r.action is LogAction.TOOL_CALL and r.outcome is CallOutcome.DENIED
    ]
    assert len(righe) == 1
    assert righe[0].correlation_id == correlation_id
    assert righe[0].tool_id == "echo.ping"
    assert righe[0].agent is OwnerAgent.ECHO_DUMMY
    assert "non eseguita" in righe[0].detail
    assert "Riprovare non cambia l'esito" in righe[0].detail

    # Il posto in memoria è tornato: un rifiuto non deve consumare capacità.
    assert ex._posti.acquire(blocking=False) is True
    ex._posti.release()


def test_senza_pool_resta_il_limite_di_processo(repo, registry, audit):
    ex = ToolExecutor(registry, audit, repo_root=repo, runner=RunnerFinto())
    assert ex.concorrenza_condivisa is False


def test_guasto_imprevisto_nel_pool_non_perde_il_posto_in_memoria(
    repo, registry, audit, monkeypatch
):
    """Un semaforo perso riduce la capacità del processo per sempre.

    È lo stesso controllo-che-si-auto-esaurisce per cui i posti condivisi sono
    lock e non contatori: vale anche per il semaforo in memoria, e un'eccezione
    inattesa nel codice dei posti non deve provocarlo.
    """
    from mcp_server.slots import SlotPool

    registry.register(_spec(repo))
    pool = SlotPool(repo / "slots", 1)
    ex = ToolExecutor(
        registry,
        audit,
        repo_root=repo,
        runner=RunnerFinto(),
        max_concurrent=1,
        slots=pool,
    )

    def esplode():
        raise RuntimeError("guasto inatteso nel pool")

    monkeypatch.setattr(ex, "_prendi_posto_condiviso", esplode)
    for _ in range(3):
        with pytest.raises(RuntimeError):
            ex.execute(
                "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
            )

    # Il processo deve avere ancora il suo posto: senza il rilascio, al
    # secondo tentativo il semaforo sarebbe gia' esaurito.
    monkeypatch.undo()
    call, _ = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4()
    )
    assert call.outcome is CallOutcome.OK
