"""Test del preflight (M0 passo 8).

Un diagnostico che dice sempre «ok» è peggio che inutile: dà fiducia
ingiustificata. I test verificano soprattutto che i guasti vengano
**rilevati**, e che il rimedio suggerito sia utilizzabile.
"""

from __future__ import annotations

import importlib.metadata
import io
import os
import shutil
import sys
import textwrap
from pathlib import Path

import pytest

from mcp_server.doctor import NOME_LOCKFILE, Esito, esegui, main, stampa
from mcp_server.executor import sha256_file

#: Tutto il modulo è integrazione: ogni controllo che arriva all'handshake
#: avvia un processo. Marcato a livello di modulo invece che test per test,
#: perché è la natura del componente e non una proprietà dei singoli casi.
pytestmark = pytest.mark.slow

SCRIPT = "agents/echo_agent/run.py"


@pytest.fixture()
def radice() -> Path:
    return Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def dipendenze_conformi(request, monkeypatch):
    """Isola i test dallo stato delle dipendenze installate.

    Difetto trovato l'11 novembre eseguendo la suite sulla VM: il `.venv`
    del dispiegamento era stato creato prima del lockfile e aveva nove
    pacchetti a versioni più vecchie. Il controllo lo ha riportato — ed era
    **corretto** — ma i test che usano la radice vera del repo leggono quel
    lock, quindi **nove test** su configurazione, store, perimetro e wrapper
    sono diventati rossi per una ragione che non ha nulla a che vedere con
    ciò che verificano.

    Il precedente è lo stesso del 4 novembre con «scrivibilità del codice»:
    un fatto dell'ambiente che fa cadere test su altri argomenti. Lì la
    risposta fu correggere il controllo, perché non sapeva rispondere. Qui
    il controllo sa rispondere e dice il vero: è la **suite** a essere
    accoppiata a uno stato che non dichiara.

    Quindi le dipendenze installate diventano, per default, esattamente
    quelle che il lock fissa: il controllo resta nel referto, ma non è più
    una terza variabile nei test di altri. I casi il cui soggetto *è*
    l'ambiente vero si marcano `dipendenze_reali` e vedono la macchina come
    è. Una deriva reale fa cadere **un** test che la nomina, invece di nove
    che la nascondono.
    """
    if request.node.get_closest_marker("dipendenze_reali"):
        return

    from mcp_server import doctor as mod

    lock = Path(__file__).resolve().parent.parent / NOME_LOCKFILE
    try:
        pin = mod.leggi_lockfile(lock.read_text(encoding="utf-8"))
    except OSError:  # pragma: no cover - il lock è versionato
        pin = {}
    monkeypatch.setattr(mod, "_installate", lambda: dict(pin))


def scrivi_config(
    tmp_path: Path,
    radice: Path,
    *,
    tier: str = "verde",
    sha: str | None = None,
    exec_path: str = SCRIPT,
    personal_data: bool = False,
    requires_container: bool = False,
    backend: str = "stub",
    senza_tool: bool = False,
    agent: str = "echo_dummy",
    state_dir: Path | str | None = None,
    scope_file: Path | str | None = None,
    target_kind: str | None = None,
    tool_runner: Path | str | None = None,
    repo_root: Path | None = None,
) -> Path:
    riga_stato = f'state_dir = "{state_dir}"\n' if state_dir is not None else ""
    if scope_file is not None:
        riga_stato += f'scope_file = "{scope_file}"\n'
    if tool_runner is not None:
        riga_stato += f'tool_runner = "{tool_runner}"\n'
    riga_bersaglio = (
        f'target_kind = "{target_kind}"\n            '
        if target_kind is not None
        else ""
    )
    radice_cfg = repo_root if repo_root is not None else radice
    sha = sha if sha is not None else sha256_file(radice / SCRIPT)
    blocco_tool = (
        ""
        if senza_tool
        else textwrap.dedent(f"""
            [[tool]]
            tool_id = "echo.ping"
            owner_agent = "{agent}"
            default_tier = "{tier}"
            personal_data = {str(personal_data).lower()}
            requires_container = {str(requires_container).lower()}
            exec_path = "{exec_path}"
            exec_sha256 = "{sha}"
            {riga_bersaglio}description = "Agente dummy."
            """)
    )
    percorso = tmp_path / "hermes.toml"
    percorso.write_text(
        textwrap.dedent(f"""\
            [server]
            agent = "{agent}"
            repo_root = "{radice_cfg}"
            log_path = "{tmp_path}/audit.jsonl"
            container_available = false

            {riga_stato}
            [vault]
            backend = "{backend}"
            stub_secrets = ["ssh/lab-kali"]
            """)
        + blocco_tool,
        encoding="utf-8",
    )
    return percorso


def _controllo(referto, prefisso: str):
    trovati = [c for c in referto.controlli if c.nome.startswith(prefisso)]
    assert trovati, f"nessun controllo che inizi per {prefisso!r}"
    return trovati[0]


# --------------------------------------------------------------------------- #
# Config pronta
# --------------------------------------------------------------------------- #


def test_config_valida_e_pronta(tmp_path: Path, radice: Path):
    referto = esegui(scrivi_config(tmp_path, radice))
    assert referto.pronto is True
    assert referto.errori == []
    assert _controllo(referto, "configurazione").esito is Esito.OK
    assert _controllo(referto, "tool echo.ping").esito is Esito.OK


def test_handshake_e_stdout_pulito(tmp_path: Path, radice: Path):
    """La causa più comune di fallimento con un host MCP."""
    referto = esegui(scrivi_config(tmp_path, radice))
    assert _controllo(referto, "stdout pulito").esito is Esito.OK
    avvio = _controllo(referto, "avvio su stdio")
    assert avvio.esito is Esito.OK
    assert "hermes-core" in avvio.messaggio


# --------------------------------------------------------------------------- #
# Scrivibilità del codice: il controllo deve sapere quando non può rispondere
# --------------------------------------------------------------------------- #


def test_scrivibilita_non_applicabile_per_il_proprietario(tmp_path: Path, radice: Path):
    """Difetto trovato eseguendo la suite sulla VM.

    Il controllo segnalava ERRORE anche quando lo lanciava il proprietario del
    repo — per il quale la risposta è nota in anticipo, dato che potrebbe
    comunque cambiarsi i permessi da sé. Risultato: referto «NON PRONTO» e
    quattro test rotti, senza che nulla fosse realmente mal configurato.

    Un controllo che non sa rispondere deve dirlo, non rispondere male.
    """
    import os

    referto = esegui(scrivi_config(tmp_path, radice))
    c = _controllo(referto, "scrivibilità del codice")

    assert c.esito is Esito.AVVISO
    assert "non è applicabile" in c.messaggio
    assert "sudo -u" in c.rimedio
    assert referto.pronto is True, "un controllo inapplicabile non blocca il referto"

    if os.geteuid() == 0:
        assert "root" in c.messaggio
    else:
        assert "proprietario" in c.messaggio


def test_scrivibilita_segnalata_per_l_utente_di_servizio(
    tmp_path: Path, radice: Path, monkeypatch
):
    """Con l'utente di servizio invece il controllo è significativo, e blocca."""
    import os

    import mcp_server.doctor as doctor

    # Simula un utente che non è né root né il proprietario del repo.
    # Si falsifica SOLO la risposta sulla scrittura: `os.access` serve anche a
    # validare l'eseguibilità dell'interprete, e sostituirla del tutto farebbe
    # fallire il caricamento della configurazione prima di arrivare al
    # controllo che ci interessa.
    reale = os.access
    monkeypatch.setattr(os, "geteuid", lambda: 4242)
    monkeypatch.setattr(
        doctor.os,
        "access",
        lambda percorso, modo, **k: True if modo == os.W_OK else reale(percorso, modo),
    )

    referto = esegui(scrivi_config(tmp_path, radice))
    c = _controllo(referto, "scrivibilità del codice")

    assert c.esito is Esito.ERRORE
    assert "utente di servizio" in c.messaggio
    assert "setfacl" in c.rimedio
    assert referto.pronto is False


def test_scrivibilita_ok_quando_nulla_e_scrivibile(
    tmp_path: Path, radice: Path, monkeypatch
):
    import os

    import mcp_server.doctor as doctor

    reale = os.access
    monkeypatch.setattr(os, "geteuid", lambda: 4242)
    monkeypatch.setattr(
        doctor.os,
        "access",
        lambda percorso, modo, **k: False if modo == os.W_OK else reale(percorso, modo),
    )

    c = _controllo(esegui(scrivi_config(tmp_path, radice)), "scrivibilità del codice")
    assert c.esito is Esito.OK
    assert "nessuno scrivibile" in c.messaggio


# --------------------------------------------------------------------------- #
# Interprete dei tool
# --------------------------------------------------------------------------- #


def test_interprete_verificato(tmp_path: Path, radice: Path):
    referto = esegui(scrivi_config(tmp_path, radice))
    c = _controllo(referto, "interprete dei tool")
    assert c.esito is Esito.OK
    assert "/usr/bin/python3" in c.messaggio
    assert "-I -S" in c.messaggio


def test_isolamento_confermato(tmp_path: Path, radice: Path):
    c = _controllo(esegui(scrivi_config(tmp_path, radice)), "isolamento dei tool")
    assert c.esito is Esito.OK


def test_isolamento_mancante_segnalato(tmp_path: Path, radice: Path):
    """Chi allenta i flag deve vederselo dire dal preflight."""
    percorso = scrivi_config(tmp_path, radice)
    testo = percorso.read_text(encoding="utf-8").replace(
        "container_available = false",
        'container_available = false\ntool_python_flags = ["-I"]',
    )
    percorso.write_text(testo, encoding="utf-8")

    c = _controllo(esegui(percorso), "isolamento dei tool")
    assert c.esito is Esito.AVVISO
    assert "-S" in c.messaggio


def test_interprete_dentro_il_repo_rilevato(tmp_path: Path, radice: Path):
    """L'interprete non è coperto dallo SHA: dentro il repo è un errore."""
    finto = tmp_path / "python-nel-repo"
    finto.write_text("#!/bin/sh\nexec /usr/bin/python3 \"$@\"\n", encoding="utf-8")
    finto.chmod(0o755)
    percorso = scrivi_config(tmp_path, radice)
    testo = percorso.read_text(encoding="utf-8").replace(
        f'repo_root = "{radice}"', f'repo_root = "{tmp_path}"'
    ).replace(
        "container_available = false",
        f'container_available = false\ntool_python = "{finto}"',
    )
    percorso.write_text(testo, encoding="utf-8")

    referto = esegui(percorso)
    c = _controllo(referto, "interprete fuori dal repo")
    assert c.esito is Esito.ERRORE
    assert referto.pronto is False


def test_interprete_scrivibile_da_altri_rilevato(tmp_path: Path, radice: Path):
    finto = tmp_path / "python-permissivo"
    finto.write_text("#!/bin/sh\nexec /usr/bin/python3 \"$@\"\n", encoding="utf-8")
    finto.chmod(0o777)
    percorso = scrivi_config(tmp_path, radice)
    testo = percorso.read_text(encoding="utf-8").replace(
        "container_available = false",
        f'container_available = false\ntool_python = "{finto}"',
    )
    percorso.write_text(testo, encoding="utf-8")

    referto = esegui(percorso)
    c = _controllo(referto, "permessi dell'interprete")
    assert c.esito is Esito.ERRORE
    assert "chmod go-w" in c.rimedio


def test_flag_che_impediscono_l_avvio_rilevati(tmp_path: Path, radice: Path):
    percorso = scrivi_config(tmp_path, radice)
    testo = percorso.read_text(encoding="utf-8").replace(
        "container_available = false",
        'container_available = false\ntool_python_flags = ["--flag-inventato"]',
    )
    percorso.write_text(testo, encoding="utf-8")

    c = _controllo(esegui(percorso), "interprete dei tool")
    assert c.esito is Esito.ERRORE


# --------------------------------------------------------------------------- #
# Guasti rilevati
# --------------------------------------------------------------------------- #


def test_config_assente(tmp_path: Path):
    referto = esegui(tmp_path / "mai-esistita.toml")
    assert referto.pronto is False
    assert _controllo(referto, "configurazione").esito is Esito.ERRORE


def test_config_malformata(tmp_path: Path):
    percorso = tmp_path / "rotta.toml"
    percorso.write_text("[server\n", encoding="utf-8")
    assert esegui(percorso).pronto is False


def test_sha_non_corrispondente_rilevato_col_rimedio(tmp_path: Path, radice: Path):
    """Il rimedio deve contenere l'hash corretto, pronto da incollare."""
    referto = esegui(scrivi_config(tmp_path, radice, sha="0" * 64))
    assert referto.pronto is False

    c = _controllo(referto, "tool echo.ping")
    assert c.esito is Esito.ERRORE
    assert "SHA non corrisponde" in c.messaggio
    assert sha256_file(radice / SCRIPT) in c.rimedio


def test_script_inesistente_rilevato(tmp_path: Path, radice: Path):
    referto = esegui(
        scrivi_config(tmp_path, radice, exec_path="agents/mai-esistito.py", sha="0" * 64)
    )
    assert referto.pronto is False
    assert "non utilizzabile" in _controllo(referto, "tool echo.ping").messaggio


def test_tool_non_conforme_rilevato(tmp_path: Path, radice: Path):
    """Senza tier il server non partirebbe: il preflight lo dice prima."""
    percorso = scrivi_config(tmp_path, radice)
    testo = percorso.read_text(encoding="utf-8").replace(
        'default_tier = "verde"\n', ""
    )
    percorso.write_text(testo, encoding="utf-8")

    referto = esegui(percorso)
    assert referto.pronto is False
    assert "non conforme" in _controllo(referto, "tool echo.ping").messaggio


def test_backend_vault_non_collegato_rilevato(tmp_path: Path, radice: Path):
    referto = esegui(scrivi_config(tmp_path, radice, backend="pass"))
    assert referto.pronto is False
    assert _controllo(referto, "vault").esito is Esito.ERRORE


def test_repo_root_inesistente(tmp_path: Path):
    percorso = tmp_path / "hermes.toml"
    percorso.write_text(
        '[server]\nagent = "echo_dummy"\nrepo_root = "/non/esiste/affatto"\n',
        encoding="utf-8",
    )
    assert esegui(percorso).pronto is False


# --------------------------------------------------------------------------- #
# Avvisi
# --------------------------------------------------------------------------- #


def test_tool_che_richiede_conferma_segnalato(tmp_path: Path, radice: Path):
    """Non è un errore, ma va saputo prima di chiedersi perché non parte."""
    referto = esegui(scrivi_config(tmp_path, radice, tier="rosso"))
    assert referto.pronto is True
    c = _controllo(referto, "tool echo.ping · eseguibilità")
    assert c.esito is Esito.AVVISO
    assert "needs_confirmation" in c.messaggio


def test_dati_personali_segnalati_anche_su_verde(tmp_path: Path, radice: Path):
    referto = esegui(scrivi_config(tmp_path, radice, personal_data=True))
    c = _controllo(referto, "tool echo.ping · eseguibilità")
    assert "dati personali" in c.messaggio


def test_container_richiesto_e_assente_segnalato(tmp_path: Path, radice: Path):
    referto = esegui(scrivi_config(tmp_path, radice, requires_container=True))
    c = _controllo(referto, "container")
    assert c.esito is Esito.AVVISO
    assert "negati" in c.messaggio


def test_vault_stub_segnalato(tmp_path: Path, radice: Path):
    c = _controllo(esegui(scrivi_config(tmp_path, radice)), "vault")
    assert c.esito is Esito.AVVISO
    assert "nessuna credenziale reale" in c.messaggio


def test_log_append_only_segnalato(tmp_path: Path, radice: Path):
    c = _controllo(esegui(scrivi_config(tmp_path, radice)), "log append-only")
    assert c.esito is Esito.AVVISO
    assert "chattr +a" in c.rimedio


def test_nessun_tool_segnalato(tmp_path: Path, radice: Path):
    referto = esegui(scrivi_config(tmp_path, radice, senza_tool=True))
    c = _controllo(referto, "tool")
    assert c.esito is Esito.AVVISO
    assert "non espone nulla" in c.messaggio


# --------------------------------------------------------------------------- #
# Referto e codice d'uscita
# --------------------------------------------------------------------------- #


def test_stampa_dice_pronto(tmp_path: Path, radice: Path):
    buf = io.StringIO()
    stampa(esegui(scrivi_config(tmp_path, radice)), buf)
    testo = buf.getvalue()
    assert "PRONTO" in testo
    assert "lato Hermes" in testo


def test_stampa_dice_non_pronto(tmp_path: Path, radice: Path):
    buf = io.StringIO()
    stampa(esegui(scrivi_config(tmp_path, radice, sha="0" * 64)), buf)
    assert "NON PRONTO" in buf.getvalue()


def test_exit_code_zero_se_pronto(tmp_path: Path, radice: Path, capsys):
    assert main([str(scrivi_config(tmp_path, radice))]) == 0


def test_exit_code_uno_se_errori(tmp_path: Path, radice: Path, capsys):
    assert main([str(scrivi_config(tmp_path, radice, sha="0" * 64))]) == 1


# --------------------------------------------------------------------------- #
# Diagnosi dallo stderr del server
# --------------------------------------------------------------------------- #


def test_errore_da_stderr_salta_la_riga_traceback():
    """La prima riga di un traceback non informa di nulla: serve l'ultima.

    Difetto trovato sul campo: il preflight riportava «Traceback (most recent
    call last):» come causa, che è esattamente l'unica riga inutile.
    """
    from mcp_server.doctor import _errore_da_stderr

    stderr = (
        "Traceback (most recent call last):\n"
        '  File "/opt/hermes-core/mcp_server/audit.py", line 240, in _prepara\n'
        "    self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)\n"
        "PermissionError: [Errno 13] Permission denied: "
        "'/opt/hermes-core/config/var'\n"
    )
    causa = _errore_da_stderr(stderr)
    assert causa.startswith("PermissionError")
    assert "/opt/hermes-core/config/var" in causa
    assert "Traceback" not in causa


def test_errore_da_stderr_scarta_i_marcatori_di_posizione():
    """Le righe '~~~^^^' di Python 3.11+ sono rumore, non contesto."""
    from mcp_server.doctor import _errore_da_stderr

    stderr = (
        "Traceback (most recent call last):\n"
        '  File "x.py", line 1, in <module>\n'
        "    qualcosa.di_sbagliato()\n"
        "    ~~~~~~~~^^^^^^^^^^^^^^\n"
        "ValueError: messaggio utile\n"
    )
    causa = _errore_da_stderr(stderr)
    assert "ValueError: messaggio utile" in causa
    assert "^" not in causa
    assert "~" not in causa


def test_errore_da_stderr_riga_singola():
    from mcp_server.doctor import _errore_da_stderr

    assert _errore_da_stderr("errore secco\n") == "errore secco"


def test_errore_da_stderr_vuoto():
    from mcp_server.doctor import _errore_da_stderr

    assert _errore_da_stderr("") == ""
    assert _errore_da_stderr("   \n\n") == ""


def test_log_path_relativo_spiegato_nel_rimedio(tmp_path: Path, radice: Path):
    """Il caso che si è presentato davvero: slash iniziale dimenticato.

    Un log_path relativo viene risolto rispetto alla cartella della config,
    quindi finisce dentro il repo — che in produzione è in sola lettura.
    """
    percorso = scrivi_config(tmp_path, radice)
    testo = percorso.read_text(encoding="utf-8").replace(
        f'log_path = "{tmp_path}/audit.jsonl"', 'log_path = "var/log/hermes/audit.jsonl"'
    )
    percorso.write_text(testo, encoding="utf-8")
    # Rende impossibile creare la directory: 'var' esiste come file.
    (tmp_path / "var").touch()

    referto = esegui(percorso)
    c = _controllo(referto, "log d'audit")
    assert c.esito is Esito.ERRORE
    assert "relativo" in c.rimedio
    assert "Percorso risolto" in c.rimedio


# --------------------------------------------------------------------------- #
# Wrapper di avvio
# --------------------------------------------------------------------------- #


def test_wrapper_eseguibile(radice: Path):
    import os

    wrapper = radice / "bin" / "hermes-core-server"
    assert wrapper.is_file()
    assert os.access(wrapper, os.X_OK), "il wrapper deve avere il bit di esecuzione"


def test_wrapper_non_scrive_su_stdout(radice: Path):
    """Su stdio, stdout appartiene al protocollo: anche gli errori vanno su stderr."""
    sorgente = (radice / "bin" / "hermes-core-server").read_text(encoding="utf-8")
    righe_echo = [
        r.strip()
        for r in sorgente.splitlines()
        if r.strip().startswith("echo") and ">&2" not in r
    ]
    assert righe_echo == []


def test_wrapper_segnala_venv_assente(radice: Path, tmp_path: Path):
    """L'host mostra poco di un avvio fallito: il messaggio deve bastare."""
    import os
    import subprocess

    ambiente = dict(os.environ, HERMES_VENV=str(tmp_path / "venv-inesistente"))
    esito = subprocess.run(
        [str(radice / "bin" / "hermes-core-server")],
        capture_output=True,
        text=True,
        timeout=60,
        env=ambiente,
    )
    assert esito.returncode == 1
    assert esito.stdout == "", "su stdio, stdout appartiene al protocollo"
    assert "virtualenv assente" in esito.stderr
    assert "HERMES_VENV" in esito.stderr


def test_wrapper_segnala_package_non_importabile(radice: Path, tmp_path: Path):
    """Il caso reale: un PermissionError dentro importlib non dice cosa fare.

    Si riproduce con un progetto finto che ha il venv ma non il package.
    """
    import os
    import shutil
    import subprocess

    finto = tmp_path / "progetto"
    (finto / "bin").mkdir(parents=True)
    (finto / "config").mkdir()
    (finto / ".venv" / "bin").mkdir(parents=True)
    shutil.copy(radice / "bin" / "hermes-core-server", finto / "bin")
    (finto / ".venv" / "bin" / "python").symlink_to(
        Path(sys.executable).resolve()
    )
    (finto / "config" / "hermes.toml").write_text(
        '[server]\nagent = "echo_dummy"\nrepo_root = "."\n', encoding="utf-8"
    )

    esito = subprocess.run(
        [str(finto / "bin" / "hermes-core-server")],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(tmp_path),
    )
    assert esito.returncode == 1
    assert esito.stdout == ""
    assert "non è importabile" in esito.stderr
    assert "setfacl" in esito.stderr, "il rimedio deve indicare le ACL"


def test_wrapper_segnala_config_assente(radice: Path, tmp_path: Path):
    import subprocess

    esito = subprocess.run(
        [str(radice / "bin" / "hermes-core-server"), str(tmp_path / "assente.toml")],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert esito.returncode == 1
    assert esito.stdout == ""
    assert "configurazione assente" in esito.stderr
    # Percorsi assoluti nel rimedio: un comando copiabile vale piu' di uno
    # relativo a una directory che l'operatore potrebbe non avere.
    assert "hermes.example.toml" in esito.stderr
    assert "/opt" in esito.stderr or str(radice) in esito.stderr


# --------------------------------------------------------------------------- #
# Store degli override: due esiti negativi diversi per due cose diverse
# --------------------------------------------------------------------------- #


def test_store_non_configurato_e_avviso_non_errore(tmp_path: Path, radice: Path):
    """Manca una proprietà, non un pezzo: il server funziona e lo dichiara."""
    referto = esegui(scrivi_config(tmp_path, radice))
    controllo = _controllo(referto, "store degli override")
    assert controllo.esito is Esito.AVVISO
    assert referto.pronto is True
    assert "state_dir" in controllo.messaggio
    assert "install -d" in controllo.rimedio


def test_store_configurato_e_scrivibile(tmp_path: Path, radice: Path):
    referto = esegui(
        scrivi_config(tmp_path, radice, state_dir=tmp_path / "stato")
    )
    controllo = _controllo(referto, "store degli override")
    assert controllo.esito is Esito.OK
    assert referto.pronto is True


def test_store_configurato_ma_non_utilizzabile_e_errore(
    tmp_path: Path, radice: Path
):
    """Qui l'operatore ha chiesto la persistenza e non la sta ottenendo.

    È il caso peggiore dei due — un controllo che si crede di avere e non c'è —
    ed è la ragione per cui questo preflight esiste.
    """
    finta = tmp_path / "stato"
    finta.write_text("non sono una directory\n", encoding="utf-8")
    referto = esegui(scrivi_config(tmp_path, radice, state_dir=finta))
    controllo = _controllo(referto, "store degli override")
    assert controllo.esito is Esito.ERRORE
    assert referto.pronto is False


def test_store_illeggibile_e_errore(tmp_path: Path, radice: Path):
    stato = tmp_path / "stato"
    stato.mkdir()
    (stato / "overrides.jsonl").mkdir()  # esiste ma non si apre in lettura
    referto = esegui(scrivi_config(tmp_path, radice, state_dir=stato))
    controllo = _controllo(referto, "store degli override")
    assert controllo.esito is Esito.ERRORE
    assert "non leggibile" in controllo.messaggio


def test_righe_scartate_segnalate(tmp_path: Path, radice: Path):
    """Ogni riga scartata può essere un innalzamento perduto."""
    stato = tmp_path / "stato"
    stato.mkdir()
    (stato / "overrides.jsonl").write_text("{rotta\n", encoding="utf-8")
    referto = esegui(scrivi_config(tmp_path, radice, state_dir=stato))
    controllo = _controllo(referto, "store degli override")
    assert controllo.esito is Esito.AVVISO
    assert "innalzamento perduto" in controllo.messaggio


def test_store_dentro_il_repo_segnalato(tmp_path: Path, radice: Path):
    """Uno stato di sicurezza nell'albero di lavoro sparisce a un checkout."""
    referto = esegui(
        scrivi_config(tmp_path, radice, state_dir=radice / "var-stato-test")
    )
    try:
        controllo = _controllo(referto, "store fuori dal repo")
        assert controllo.esito is Esito.AVVISO
    finally:
        # rmtree e non una passata di unlink: da quando il preflight verifica
        # i posti provandoci davvero, sotto state_dir c'è anche slots/<agente>.
        shutil.rmtree(radice / "var-stato-test", ignore_errors=True)


# --------------------------------------------------------------------------- #
# Perché un percorso non è scrivibile: la causa giusta, non una plausibile
# --------------------------------------------------------------------------- #


def test_log_non_scrivibile_non_accusa_il_percorso_relativo(
    tmp_path: Path, radice: Path
):
    """Il rimedio nominava **sempre** la trappola del percorso relativo.

    Su un percorso assoluto e corretto, bloccato da un problema di
    proprietario, quel testo manda a cercare dalla parte sbagliata. Un
    diagnostico che indica una causa plausibile ma falsa è peggio di uno che
    dice solo «non riesco», perché viene creduto.
    """
    blocco = tmp_path / "non-sono-una-directory"
    blocco.write_text("x\n", encoding="utf-8")
    percorso = scrivi_config(tmp_path, radice)
    percorso.write_text(
        percorso.read_text(encoding="utf-8").replace(
            f'log_path = "{tmp_path}/audit.jsonl"',
            f'log_path = "{blocco}/audit.jsonl"',
        ),
        encoding="utf-8",
    )

    controllo = _controllo(esegui(percorso), "log d'audit")
    assert controllo.esito is Esito.ERRORE
    assert "relativo" not in controllo.rimedio
    # I fatti che servono per capire: chi esegue e cosa c'è sul percorso.
    assert "In esecuzione come" in controllo.rimedio
    assert "uid" in controllo.rimedio
    assert str(blocco) in controllo.rimedio


def test_log_dentro_il_repo_nomina_la_trappola(tmp_path: Path, radice: Path):
    """La trappola si nomina quando il sintomo c'è davvero."""
    from mcp_server.config import load_config
    from mcp_server.doctor import _perche_non_scrivibile

    cfg = load_config(scrivi_config(tmp_path, radice))
    testo = _perche_non_scrivibile(radice / "logs" / "audit.jsonl", cfg)
    assert "DENTRO repo_root" in testo


def test_stat_non_solleva_su_percorso_non_ispezionabile(tmp_path: Path):
    """``Path.exists()`` solleva PermissionError su una dir non attraversabile.

    È il guasto che questo codice deve descrivere, quindi non può usarlo.
    Trovato riproducendo il caso di Gabriele invece di immaginarlo.
    """
    from mcp_server.doctor import _descrivi, _stat

    blocco = tmp_path / "file-non-dir"
    blocco.write_text("x\n", encoding="utf-8")
    assert _stat(blocco / "sotto" / "audit.jsonl") is None
    assert "non ispezionabile" in _descrivi(blocco / "sotto" / "audit.jsonl")


def test_utente_di_servizio_dedotto_dal_proprietario_del_log(
    tmp_path: Path, radice: Path
):
    """I rimedi dicevano `$(id -un)`: giusti per la persona sbagliata.

    Su una VM fatta come documentata il server gira come utente di servizio
    via comando forzato SSH, mentre il preflight lo lancia a mano
    l'amministratore. Il proprietario della directory del log è il testimone
    più affidabile di chi sia il primo.
    """
    import os as _os

    from mcp_server.config import load_config
    from mcp_server.doctor import _utente, _utente_di_servizio

    cfg = load_config(scrivi_config(tmp_path, radice))
    atteso = _utente(_os.stat(cfg.log_path.parent).st_uid)
    assert _utente_di_servizio(cfg) == atteso


def test_rimedio_store_nomina_l_utente_di_servizio(tmp_path: Path, radice: Path):
    controllo = _controllo(
        esegui(scrivi_config(tmp_path, radice)), "store degli override"
    )
    assert "$(id -un)" not in controllo.rimedio
    assert "non chi lancia il preflight" in controllo.rimedio


def test_store_non_ispezionabile_non_uccide_il_preflight(
    tmp_path: Path, radice: Path
):
    """Il controllo che deve diagnosticare i permessi non può morirci dentro.

    Prima `_stato` chiedeva `percorso.exists()` fuori dal try, e quella
    domanda solleva PermissionError su una directory non attraversabile: il
    preflight finiva con un traceback invece che con un referto.
    """
    (tmp_path / "a").symlink_to(tmp_path / "b")
    (tmp_path / "b").symlink_to(tmp_path / "a")
    referto = esegui(scrivi_config(tmp_path, radice, state_dir=tmp_path / "a"))
    controllo = _controllo(referto, "store degli override")
    assert controllo.esito is Esito.ERRORE
    assert referto.pronto is False
    assert "In esecuzione come" in controllo.rimedio


def test_store_di_un_altro_utente_e_errore_non_falso_verde(
    tmp_path: Path, radice: Path, monkeypatch
):
    """Il file lo crea chi lancia il preflight: dall'utente sbagliato è un falso verde.

    Lanciato da root, il preflight crea lo store intestato a root; il servizio
    poi non ci scrive, ma il preflight direbbe «ok» su una persistenza che non
    funziona. Un falso verde è il guasto peggiore che un preflight possa
    produrre, quindi la discrepanza di proprietario è un ERRORE.
    """
    from mcp_server import doctor as mod

    stato = tmp_path / "stato"
    # Il servizio dedotto è il proprietario della dir del log: lo si finge
    # diverso da chi sta eseguendo, che è ciò che accade su una VM vera.
    monkeypatch.setattr(mod, "_utente_di_servizio", lambda cfg: "un-altro-utente")
    referto = esegui(scrivi_config(tmp_path, radice, state_dir=stato))

    controllo = _controllo(referto, "proprietario dello store")
    assert controllo.esito is Esito.ERRORE
    assert referto.pronto is False
    assert "non verranno persistiti" in controllo.messaggio


def test_senza_state_dir_il_tetto_e_per_processo(tmp_path: Path, radice: Path):
    referto = esegui(scrivi_config(tmp_path, radice))
    limiti = _controllo(referto, "limiti di esecuzione")
    assert "solo in questo processo" in limiti.messaggio
    posti = _controllo(referto, "posti condivisi")
    assert posti.esito is Esito.AVVISO
    assert "un processo per connessione" in posti.messaggio


def test_con_state_dir_il_tetto_e_condiviso(tmp_path: Path, radice: Path):
    referto = esegui(
        scrivi_config(tmp_path, radice, state_dir=tmp_path / "stato")
    )
    limiti = _controllo(referto, "limiti di esecuzione")
    assert "fra le connessioni dell'agente" in limiti.messaggio
    posti = _controllo(referto, "posti condivisi")
    assert posti.esito is Esito.OK
    # La conseguenza della scelta per-agente va dichiarata, non nascosta.
    assert "× agenti attivi" in posti.messaggio
    assert "slots/echo_dummy" in posti.messaggio


def test_posti_verificati_davvero_non_solo_stampati(
    tmp_path: Path, radice: Path
):
    """Il verde deve costare un tentativo, non una formattazione di stringa.

    La directory dei posti nasce alla prima esecuzione, quindi la sua assenza
    non è un guasto: l'unica domanda utile prima è se nascerà, e si risponde
    solo provando.
    """
    stato = tmp_path / "stato"
    referto = esegui(scrivi_config(tmp_path, radice, state_dir=stato))
    assert _controllo(referto, "posti condivisi").esito is Esito.OK
    assert (stato / "slots" / "echo_dummy").is_dir()
    # Il file di prova non resta: un `slot-NN` creato qui, se il preflight
    # girasse da root, sarebbe un posto che il servizio non può più aprire.
    assert list((stato / "slots" / "echo_dummy").iterdir()) == []


def test_posti_configurati_ma_non_creabili_e_errore(
    tmp_path: Path, radice: Path
):
    """Il tetto condiviso è promesso e non applicabile: il gate rifiuterà.

    Stesso caso peggiore dello store degli override — un controllo che si
    crede di avere e non c'è — e qui il preflight è l'unico punto in cui si
    vede prima di un'invocazione.
    """
    stato = tmp_path / "stato"
    stato.mkdir()
    # `slots` esiste ma non è una directory: il mkdir dei posti fallirà.
    (stato / "slots").write_text("non sono una directory\n", encoding="utf-8")
    referto = esegui(scrivi_config(tmp_path, radice, state_dir=stato))
    posti = _controllo(referto, "posti condivisi")
    assert posti.esito is Esito.ERRORE
    assert "non utilizzabile" in posti.messaggio
    assert referto.pronto is False


# --------------------------------------------------------------------------- #
# Il canale del servizio non deve poter auto-autorizzarsi (HC-04)
# --------------------------------------------------------------------------- #


def _sshd(tmp_path: Path, *, include_in_cima: bool = True, prima: str = "") -> Path:
    """Finto ``sshd_config``, con l'Include dove serve al test."""
    righe = ["# commento", ""]
    if prima:
        righe.append(prima)
    if include_in_cima:
        righe.append("Include /etc/ssh/sshd_config.d/*.conf")
    righe += ["PermitRootLogin prohibit-password", "UsePAM yes"]
    percorso = tmp_path / "sshd_config"
    percorso.write_text("\n".join(righe) + "\n", encoding="utf-8")
    return percorso


def _dropin_file(tmp_path: Path, chiavi: Path, *, forcecommand: bool = True) -> Path:
    corpo = [
        "PasswordAuthentication no",
        "Match User hermes",
        f"    AuthorizedKeysFile {chiavi}",
    ]
    if forcecommand:
        corpo.append("    ForceCommand /opt/hermes-core/bin/hermes-core-server")
    percorso = tmp_path / "10-hermes.conf"
    percorso.write_text("\n".join(corpo) + "\n", encoding="utf-8")
    return percorso


def _prepara_canale(monkeypatch, sshd: Path | None, dropin: Path | None, servizio: str):
    """Punta il controllo a file di test e fissa l'utente di servizio.

    L'utente si fissa invece di creare file con proprietari diversi: un test
    che richiede ``chown`` gira solo da root, e questa suite deve dare lo
    stesso esito sulla VM, dove la lancia l'amministratore senza privilegi.
    """
    from mcp_server import doctor as mod

    monkeypatch.setattr(
        mod, "PERCORSO_SSHD_CONFIG", sshd if sshd else Path("/non/esiste/sshd_config")
    )
    monkeypatch.setattr(
        mod, "PERCORSO_DROPIN_SSH", dropin if dropin else Path("/non/esiste/10.conf")
    )
    monkeypatch.setattr(mod, "_utente_di_servizio", lambda cfg: servizio)


def test_include_in_cima_riconosciuto(tmp_path: Path):
    from mcp_server.doctor import _direttive_prima_dell_include

    presente, prima = _direttive_prima_dell_include(_sshd(tmp_path))
    assert presente is True
    assert prima == []


def test_include_preceduto_da_direttive_attive(tmp_path: Path):
    """In sshd vince il primo valore: ciò che sta sopra l'Include vince."""
    from mcp_server.doctor import _direttive_prima_dell_include

    presente, prima = _direttive_prima_dell_include(
        _sshd(tmp_path, prima="PasswordAuthentication yes")
    )
    assert presente is True
    assert prima == ["PasswordAuthentication"]


def test_include_assente(tmp_path: Path):
    from mcp_server.doctor import _direttive_prima_dell_include

    presente, _ = _direttive_prima_dell_include(
        _sshd(tmp_path, include_in_cima=False)
    )
    assert presente is False


def test_dropin_legge_solo_il_blocco_match(tmp_path: Path):
    from mcp_server.doctor import _dropin

    chiavi = tmp_path / "hermes"
    direttive = _dropin(_dropin_file(tmp_path, chiavi))
    assert direttive is not None
    assert direttive["authorizedkeysfile"] == str(chiavi)
    assert "forcecommand" in direttive
    # Fuori dal blocco Match: non è una direttiva del canale del servizio.
    assert "passwordauthentication" not in direttive


def test_senza_sshd_il_canale_non_e_un_controllo(
    tmp_path: Path, radice: Path, monkeypatch
):
    """Il server può girare sulla stessa macchina del client.

    Pretendere un canale SSH dove non ce n'è produrrebbe un errore su una
    installazione sana.
    """
    _prepara_canale(monkeypatch, None, None, "hermes")
    referto = esegui(scrivi_config(tmp_path, radice))
    assert [c for c in referto.controlli if c.nome.startswith("canale ssh")] == []


def test_dropin_assente_e_avviso(tmp_path: Path, radice: Path, monkeypatch):
    _prepara_canale(monkeypatch, _sshd(tmp_path), None, "hermes")
    referto = esegui(scrivi_config(tmp_path, radice))
    controllo = _controllo(referto, "canale ssh del servizio")
    assert controllo.esito is Esito.AVVISO
    assert "può riscrivere" in controllo.messaggio


def test_dropin_installato_ma_senza_include_e_errore(
    tmp_path: Path, radice: Path, monkeypatch
):
    """Un drop-in inerte è il falso verde peggiore: c'è, e non fa niente."""
    chiavi = tmp_path / "hermes"
    chiavi.write_text("ssh-ed25519 AAAA test\n", encoding="utf-8")
    _prepara_canale(
        monkeypatch,
        _sshd(tmp_path, include_in_cima=False),
        _dropin_file(tmp_path, chiavi),
        "hermes",
    )
    referto = esegui(scrivi_config(tmp_path, radice))
    controllo = _controllo(referto, "canale ssh del servizio")
    assert controllo.esito is Esito.ERRORE
    assert "non viene letto" in controllo.messaggio
    assert referto.pronto is False


def test_canale_irrigidito_e_ok(tmp_path: Path, radice: Path, monkeypatch):
    chiavi = tmp_path / "hermes"
    chiavi.write_text("ssh-ed25519 AAAA test\n", encoding="utf-8")
    chiavi.chmod(0o644)
    _prepara_canale(
        monkeypatch, _sshd(tmp_path), _dropin_file(tmp_path, chiavi), "hermes"
    )
    referto = esegui(scrivi_config(tmp_path, radice))
    assert _controllo(referto, "canale ssh del servizio").esito is Esito.OK
    autorizzazioni = _controllo(referto, "autorizzazioni del canale")
    assert autorizzazioni.esito is Esito.OK
    assert "non può modificare le proprie autorizzazioni" in autorizzazioni.messaggio


def test_chiavi_di_proprieta_del_servizio_e_errore(
    tmp_path: Path, radice: Path, monkeypatch
):
    """È il difetto che spostare le chiavi doveva chiudere.

    Il file di test appartiene a chi lancia la suite, quindi si dichiara quello
    come utente di servizio: l'esito non dipende dai privilegi del runner.
    """
    import pwd as _pwd

    proprietario = _pwd.getpwuid(os.getuid()).pw_name
    chiavi = tmp_path / "authorized_keys"
    chiavi.write_text("ssh-ed25519 AAAA test\n", encoding="utf-8")
    chiavi.chmod(0o644)
    _prepara_canale(
        monkeypatch, _sshd(tmp_path), _dropin_file(tmp_path, chiavi), proprietario
    )
    referto = esegui(scrivi_config(tmp_path, radice))
    controllo = _controllo(referto, "autorizzazioni del canale")
    assert controllo.esito is Esito.ERRORE
    assert "riscrivere le proprie autorizzazioni" in controllo.messaggio
    assert referto.pronto is False


def test_chiavi_scrivibili_da_altri_e_errore(
    tmp_path: Path, radice: Path, monkeypatch
):
    chiavi = tmp_path / "hermes"
    chiavi.write_text("ssh-ed25519 AAAA test\n", encoding="utf-8")
    chiavi.chmod(0o666)
    _prepara_canale(
        monkeypatch, _sshd(tmp_path), _dropin_file(tmp_path, chiavi), "hermes"
    )
    referto = esegui(scrivi_config(tmp_path, radice))
    assert _controllo(referto, "autorizzazioni del canale").esito is Esito.ERRORE


# --------------------------------------------------------------------------- #
# Perimetro dei bersagli (A2)
# --------------------------------------------------------------------------- #


def _scope(tmp_path: Path, contenuto: str | None = None) -> Path:
    percorso = tmp_path / "scope.toml"
    percorso.write_text(
        contenuto
        if contenuto is not None
        else 'reti = ["10.10.0.0/16"]\n\n[alias]\ndc01 = "10.10.0.5"\n',
        encoding="utf-8",
    )
    return percorso


def test_senza_perimetro_e_senza_tool_con_bersaglio_e_avviso(
    tmp_path: Path, radice: Path
):
    """Nulla di registrato lo richiede: manca una proprietà, non un pezzo."""
    referto = esegui(scrivi_config(tmp_path, radice))
    controllo = _controllo(referto, "perimetro dei bersagli")
    assert controllo.esito is Esito.AVVISO
    assert referto.pronto is True


def test_tool_con_bersaglio_senza_perimetro_e_errore(tmp_path: Path, radice: Path):
    """Quel tool non è invocabile, e senza questo controllo si scoprirebbe
    alla prima invocazione — cioè quando serve."""
    referto = esegui(scrivi_config(tmp_path, radice, target_kind="host"))
    controllo = _controllo(referto, "perimetro dei bersagli")
    assert controllo.esito is Esito.ERRORE
    assert "echo.ping" in controllo.messaggio
    assert referto.pronto is False


def test_perimetro_non_caricabile_e_errore(tmp_path: Path, radice: Path):
    """Promesso e non applicabile: il caso peggiore dei due."""
    rotto = _scope(tmp_path, "reti = [\n")
    referto = esegui(
        scrivi_config(tmp_path, radice, scope_file=rotto, target_kind="host")
    )
    controllo = _controllo(referto, "perimetro dei bersagli")
    assert controllo.esito is Esito.ERRORE
    assert "non parsabile" in controllo.messaggio
    assert referto.pronto is False


def test_perimetro_vuoto_e_errore(tmp_path: Path, radice: Path):
    referto = esegui(
        scrivi_config(tmp_path, radice, scope_file=_scope(tmp_path, "reti = []\n"))
    )
    assert _controllo(referto, "perimetro dei bersagli").esito is Esito.ERRORE


def test_perimetro_valido_e_ok_e_dichiara_reti_e_alias(
    tmp_path: Path, radice: Path, monkeypatch
):
    """Il messaggio deve dire qual è il perimetro, non solo che c'è.

    Un operatore che non sa quali reti sono ammesse non sa interpretare un
    rifiuto.
    """
    from mcp_server import doctor as mod

    monkeypatch.setattr(mod, "_utente_di_servizio", lambda cfg: "hermes")
    referto = esegui(
        scrivi_config(
            tmp_path, radice, scope_file=_scope(tmp_path), target_kind="host"
        )
    )
    controllo = _controllo(referto, "perimetro dei bersagli")
    assert controllo.esito is Esito.OK
    assert "10.10.0.0/16" in controllo.messaggio
    assert "dc01" in controllo.messaggio
    assert "nessuna risoluzione DNS" in controllo.messaggio
    assert _controllo(referto, "tool con bersaglio").esito is Esito.OK


def test_perimetro_scrivibile_dal_servizio_e_errore(
    tmp_path: Path, radice: Path, monkeypatch
):
    """Un perimetro che il servizio può riscrivere non è un perimetro.

    Come per il canale SSH, l'utente di servizio si dichiara invece di
    cambiare proprietario al file: un test che richiede `chown` gira solo da
    root, e questa suite deve dare lo stesso esito sulla VM.
    """
    import pwd as _pwd

    from mcp_server import doctor as mod

    proprietario = _pwd.getpwuid(os.getuid()).pw_name
    monkeypatch.setattr(mod, "_utente_di_servizio", lambda cfg: proprietario)
    referto = esegui(scrivi_config(tmp_path, radice, scope_file=_scope(tmp_path)))
    controllo = _controllo(referto, "proprietario del perimetro")
    assert controllo.esito is Esito.ERRORE
    assert "ampliare il proprio perimetro" in controllo.messaggio
    assert referto.pronto is False


def test_perimetro_leggibile_da_altri_ma_non_scrivibile_e_ok(
    tmp_path: Path, radice: Path, monkeypatch
):
    """Leggibile va bene: il perimetro non è un segreto, è un vincolo."""
    from mcp_server import doctor as mod

    monkeypatch.setattr(mod, "_utente_di_servizio", lambda cfg: "hermes")
    percorso = _scope(tmp_path)
    percorso.chmod(0o644)
    referto = esegui(scrivi_config(tmp_path, radice, scope_file=percorso))
    assert _controllo(referto, "perimetro dei bersagli").esito is Esito.OK


# --------------------------------------------------------------------------- #
# Isolamento dei tool sotto un'altra identità (A1)
# --------------------------------------------------------------------------- #

#: Wrapper "valido" per i test: root-owned, 0755 su qualunque Linux.
WRAPPER_FINTO = "/bin/true"


def _sonda_ok(monkeypatch, codice: int = 0, stderr: str = "") -> None:
    """Sostituisce la sonda `sudo -n`, che non va eseguita nei test.

    La sonda vera esercita un privilegio sulla macchina: in una suite deve
    essere finta, altrimenti l'esito dipende da come è configurato `sudo` di
    chi lancia i test.
    """
    import subprocess as sp

    from mcp_server import doctor as mod

    def finto(argv, **kw):
        return sp.CompletedProcess(argv, codice, "", stderr)

    monkeypatch.setattr(mod.subprocess, "run", finto)


def test_senza_tool_runner_e_avviso(tmp_path: Path, radice: Path):
    """I tool girano come il servizio: manca una proprietà, non un pezzo."""
    referto = esegui(scrivi_config(tmp_path, radice))
    controllo = _controllo(referto, "wrapper di isolamento")
    assert controllo.esito is Esito.AVVISO
    assert "log d'audit compreso" in controllo.messaggio
    assert referto.pronto is True


def test_tool_runner_inutilizzabile_e_errore(tmp_path: Path, radice: Path):
    referto = esegui(
        scrivi_config(tmp_path, radice, tool_runner=tmp_path / "mai-esistito")
    )
    controllo = _controllo(referto, "wrapper di isolamento")
    assert controllo.esito is Esito.ERRORE
    assert referto.pronto is False
    # La sonda non va nemmeno provata: non c'è niente da autorizzare.
    assert not [
        c for c in referto.controlli if c.nome.startswith("autorizzazione sudo")
    ]


def test_wrapper_valido_e_sonda_riuscita(tmp_path: Path, radice: Path, monkeypatch):
    _sonda_ok(monkeypatch)
    referto = esegui(scrivi_config(tmp_path, radice, tool_runner=WRAPPER_FINTO))
    assert _controllo(referto, "wrapper di isolamento").esito is Esito.OK
    sonda = _controllo(referto, "autorizzazione sudo del wrapper")
    assert sonda.esito is Esito.OK
    assert "senza password" in sonda.messaggio


def test_sonda_fallita_e_errore_con_la_riga_di_sudoers(
    tmp_path: Path, radice: Path, monkeypatch
):
    """Scoprirlo adesso è l'intero scopo del preflight.

    Senza autorizzazione ogni invocazione fallirebbe, e `sudo` senza NOPASSWD
    lascerebbe il server in attesa di una password su un canale non
    interattivo.
    """
    _sonda_ok(monkeypatch, codice=1, stderr="sudo: a password is required")
    referto = esegui(scrivi_config(tmp_path, radice, tool_runner=WRAPPER_FINTO))
    sonda = _controllo(referto, "autorizzazione sudo del wrapper")
    assert sonda.esito is Esito.ERRORE
    assert "password is required" in sonda.messaggio
    assert "NOPASSWD" in (sonda.rimedio or "")
    assert referto.pronto is False


def test_confine_dai_tool_ok_con_permessi_stretti(
    tmp_path: Path, radice: Path, monkeypatch
):
    _sonda_ok(monkeypatch)
    log = tmp_path / "audit.jsonl"
    log.write_text("", encoding="utf-8")
    log.chmod(0o600)
    referto = esegui(scrivi_config(tmp_path, radice, tool_runner=WRAPPER_FINTO))
    assert _controllo(referto, "confine fra servizio e tool").esito is Esito.OK


def test_log_leggibile_da_tutti_rompe_il_confine(
    tmp_path: Path, radice: Path, monkeypatch
):
    """Separare l'identità serve a questo: che un tool non possa scrivere
    righe false nella traccia che dovrebbe registrarlo."""
    _sonda_ok(monkeypatch)
    log = tmp_path / "audit.jsonl"
    log.write_text("", encoding="utf-8")
    log.chmod(0o606)
    referto = esegui(scrivi_config(tmp_path, radice, tool_runner=WRAPPER_FINTO))
    controllo = _controllo(referto, "confine fra servizio e tool")
    assert controllo.esito is Esito.ERRORE
    assert "righe false" in controllo.messaggio
    assert referto.pronto is False


def test_utente_dei_tool_del_wrapper_e_quello_del_preflight(radice: Path):
    """La stessa costante in due linguaggi: va verificata, non ricordata.

    Il wrapper è uno script di shell e non può importare `UTENTE_TOOL`. La
    duplicazione è inevitabile, quindi la si misura — è la lezione delle tre
    copie della mappa status → esito, applicata fra linguaggi diversi.
    """
    from mcp_server.doctor import UTENTE_TOOL

    testo = (radice / "bin" / "hermes-tool-run").read_text(encoding="utf-8")
    assert f"TOOL_UID={UTENTE_TOOL}\n" in testo
    assert f"TOOL_GID={UTENTE_TOOL}\n" in testo


# --------------------------------------------------------------------------- #
# Lettura degli script dall'utente dei tool (ACL su agents/)
#
# La lacuna che questi test coprono è arrivata da un'invocazione reale, non da
# un test: l'ACL che dà a `hermes-tool` la lettura degli script non è un
# artefatto applicato dal repo, e chi installa saltandola vede il primo tool
# fallire con un «Permission denied» che non nomina la causa.
# --------------------------------------------------------------------------- #


def _sonde(
    monkeypatch,
    *,
    sudo: int = 0,
    lettura: int = 0,
    stderr_lettura: str = "",
    registro: list | None = None,
) -> None:
    """Sostituisce le DUE sonde, distinguendole per argv.

    Un finto che risponde lo stesso a tutto renderebbe indistinguibili la
    sonda di autorizzazione e quella di lettura, cioè proprio le due cose che
    questi test devono poter separare.
    """
    import subprocess as sp

    from mcp_server import doctor as mod

    def finto(argv, **kw):
        if registro is not None:
            registro.append(list(argv))
        if "--stop" in argv:
            return sp.CompletedProcess(argv, sudo, "", "")
        if mod.SONDA_LETTURA in argv:
            return sp.CompletedProcess(argv, lettura, "", stderr_lettura)
        return sp.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(mod.subprocess, "run", finto)


def test_la_sonda_di_lettura_distingue_apribile_da_non_apribile(tmp_path: Path):
    """Il programma della sonda, provato da sé prima di fidarsene.

    Un esito atteso che non si verifica mai non è una verifica: qui si misura
    che la sonda dica davvero due cose diverse nei due casi, senza passare
    dal wrapper e senza `sudo`.
    """
    import subprocess

    from mcp_server.doctor import ESITO_SONDA_NON_LEGGIBILE, SONDA_LETTURA

    leggibile = tmp_path / "c-e.py"
    leggibile.write_text("# qualcosa\n", encoding="utf-8")

    ok = subprocess.run(
        [sys.executable, "-I", "-S", "-c", SONDA_LETTURA, str(leggibile)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ok.returncode == 0, ok.stderr

    assente = subprocess.run(
        [sys.executable, "-I", "-S", "-c", SONDA_LETTURA, str(tmp_path / "mai")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert assente.returncode == ESITO_SONDA_NON_LEGGIBILE
    assert "FileNotFoundError" in assente.stderr


def test_lettura_degli_script_confermata(tmp_path: Path, radice: Path, monkeypatch):
    _sonde(monkeypatch)
    referto = esegui(scrivi_config(tmp_path, radice, tool_runner=WRAPPER_FINTO))
    controllo = _controllo(referto, "lettura degli script dai tool")
    assert controllo.esito is Esito.OK
    assert "un byte letto davvero" in controllo.messaggio


def test_script_non_leggibile_dai_tool_e_errore_con_le_acl(
    tmp_path: Path, radice: Path, monkeypatch
):
    """È il guasto del 4 novembre, visto dal preflight invece che dal tool."""
    from mcp_server.doctor import ESITO_SONDA_NON_LEGGIBILE, UTENTE_TOOL

    _sonde(
        monkeypatch,
        lettura=ESITO_SONDA_NON_LEGGIBILE,
        stderr_lettura="PermissionError: [Errno 13] Permission denied: 'run.py'",
    )
    referto = esegui(scrivi_config(tmp_path, radice, tool_runner=WRAPPER_FINTO))
    controllo = _controllo(referto, "lettura degli script dai tool")
    assert controllo.esito is Esito.ERRORE
    assert "echo.ping" in controllo.messaggio
    assert "Permission denied" in controllo.messaggio
    assert f"setfacl -m u:{UTENTE_TOOL}:--x" in controllo.rimedio
    assert f"setfacl -R -d -m u:{UTENTE_TOOL}:rX" in controllo.rimedio
    assert referto.pronto is False


def test_sonda_non_arrivata_alla_lettura_non_accusa_le_acl(
    tmp_path: Path, radice: Path, monkeypatch
):
    """Un wrapper che rifiuta non è uno script illeggibile.

    Confonderli manderebbe a riparare delle ACL che vanno bene — che è la
    forma «un controllo che indica una causa plausibile ma falsa» già vista
    nel rimedio del log.
    """
    from mcp_server.doctor import UTENTE_TOOL

    _sonde(
        monkeypatch,
        lettura=64,
        stderr_lettura="hermes-tool-run: nome di unità non valido",
    )
    referto = esegui(scrivi_config(tmp_path, radice, tool_runner=WRAPPER_FINTO))
    controllo = _controllo(referto, "lettura degli script dai tool")
    assert controllo.esito is Esito.ERRORE
    assert "non è arrivata a leggere" in controllo.messaggio
    assert "setfacl" not in controllo.rimedio
    assert f"u:{UTENTE_TOOL}" not in controllo.rimedio
    # E soprattutto: nessun verde accanto. Una catena rotta a metà non
    # autorizza a dire «tutti leggibili» avendone provato uno.
    assert not [
        c
        for c in referto.controlli
        if c.nome.startswith("lettura degli script") and c.esito is Esito.OK
    ]


def test_senza_autorizzazione_sudo_la_lettura_non_si_prova(
    tmp_path: Path, radice: Path, monkeypatch
):
    """Due errori sulla stessa causa mandano a cercare due guasti."""
    _sonde(monkeypatch, sudo=1)
    referto = esegui(scrivi_config(tmp_path, radice, tool_runner=WRAPPER_FINTO))
    assert _controllo(referto, "autorizzazione sudo del wrapper").esito is Esito.ERRORE
    assert not [
        c for c in referto.controlli if c.nome.startswith("lettura degli script")
    ]


def test_senza_wrapper_non_si_prova_la_lettura(tmp_path: Path, radice: Path):
    """Senza isolamento i tool girano come il servizio: altra domanda."""
    referto = esegui(scrivi_config(tmp_path, radice))
    assert not [
        c for c in referto.controlli if c.nome.startswith("lettura degli script")
    ]


def test_la_sonda_legge_lo_script_senza_eseguirlo(
    tmp_path: Path, radice: Path, monkeypatch
):
    """La catena è quella del gate; l'ultimo anello no, ed è il punto.

    Si verifica anche che l'unità non sia `UNITA_SONDA`: quella è riservata
    alla sonda di autorizzazione, e riusarla farebbe fermare a due preflight
    concorrenti l'unità l'uno dell'altro.
    """
    import uuid as mod_uuid

    from mcp_server.doctor import SONDA_LETTURA, UNITA_SONDA
    from mcp_server.executor import PREFISSO_UNITA

    registro: list[list[str]] = []
    _sonde(monkeypatch, registro=registro)
    esegui(scrivi_config(tmp_path, radice, tool_runner=WRAPPER_FINTO))

    letture = [a for a in registro if SONDA_LETTURA in a]
    assert len(letture) == 1
    argv = letture[0]

    assert argv[:2] == ["/usr/bin/sudo", "-n"]
    assert Path(argv[2]).resolve() == Path(WRAPPER_FINTO).resolve()
    unita = argv[3]
    assert unita != UNITA_SONDA
    assert unita.startswith(f"{PREFISSO_UNITA}-")
    mod_uuid.UUID(unita.removeprefix(f"{PREFISSO_UNITA}-"))
    assert argv[5] == "--"
    # L'interprete e i suoi flag sono gli stessi con cui girerebbe il tool.
    assert argv[6] == "/usr/bin/python3"
    assert argv[7:9] == ["-I", "-S"]
    # Lo script arriva come ARGOMENTO della sonda, non come programma.
    assert argv[9] == "-c"
    assert argv[-1].endswith("run.py")


def test_un_solo_script_condiviso_da_piu_tool_si_prova_una_volta(
    tmp_path: Path, radice: Path, monkeypatch
):
    """La domanda «è leggibile?» riguarda il file, non la registrazione."""
    from mcp_server.doctor import SONDA_LETTURA

    sha = sha256_file(radice / SCRIPT)
    percorso = tmp_path / "hermes.toml"
    percorso.write_text(
        textwrap.dedent(f"""\
            [server]
            agent = "echo_dummy"
            repo_root = "{radice}"
            log_path = "{tmp_path}/audit.jsonl"
            container_available = false
            tool_runner = "{WRAPPER_FINTO}"

            [vault]
            backend = "stub"
            stub_secrets = ["ssh/lab-kali"]

            [[tool]]
            tool_id = "echo.ping"
            owner_agent = "echo_dummy"
            default_tier = "verde"
            exec_path = "{SCRIPT}"
            exec_sha256 = "{sha}"
            description = "Dummy."

            [[tool]]
            tool_id = "echo.altro"
            owner_agent = "echo_dummy"
            default_tier = "verde"
            exec_path = "{SCRIPT}"
            exec_sha256 = "{sha}"
            exec_args = ["--altro"]
            description = "Stesso script, identità diversa."
            """),
        encoding="utf-8",
    )
    registro: list[list[str]] = []
    _sonde(monkeypatch, registro=registro)
    referto = esegui(percorso)

    assert len([a for a in registro if SONDA_LETTURA in a]) == 1
    controllo = _controllo(referto, "lettura degli script dai tool")
    assert controllo.esito is Esito.OK
    assert "1 script" in controllo.messaggio


# --------------------------------------------------------------------------- #
# Lockfile delle dipendenze
#
# `--require-hashes` garantisce il momento dell'installazione, non i mesi
# successivi: un `pip install` dato a mano per provare qualcosa non lascia
# tracce. Il confronto è la parte che si può sbagliare, quindi è una funzione
# pura e si verifica senza costruire un virtualenv per ogni caso.
# --------------------------------------------------------------------------- #


LOCK_FINTO = """\
# This file is autogenerated by pip-compile with Python 3.14
# by the following command:
#
#    pip-compile --generate-hashes --strip-extras --allow-unsafe pyproject.toml
#
annotated_types==0.8.0 \\
    --hash=sha256:13b2beaad985e05e2d6407ee4c4f35590b11f8d693a258a561055cac8f64cab7 \\
    --hash=sha256:f072f4d804ea359e4eaf198b1af7a8b0943881a87f31bb764f8bf219bb9419e0
    # via pydantic
mcp==2.3.0 \\
    --hash=sha256:8b147a50441cf059dc88c684e0aeed3687f0aa0f39c6cde7b90330effd2b34d8
    # via hermes-core (pyproject.toml)
"""


def test_lockfile_letto_saltando_hash_e_commenti():
    from mcp_server.doctor import leggi_lockfile

    pin = leggi_lockfile(LOCK_FINTO)
    # Due pacchetti, non venti: le righe `--hash=` iniziano con spazi e i
    # commenti con `#`. Un parser che le contasse direbbe che il lock fissa
    # decine di pacchetti inesistenti.
    assert pin == {"annotated-types": "0.8.0", "mcp": "2.3.0"}


def test_nomi_confrontati_in_forma_canonica():
    """`annotated_types` e `annotated-types` sono lo stesso pacchetto.

    Confrontarli alla lettera produrrebbe una deriva inventata — e una
    deriva inventata è peggio di nessun controllo, perché manda a riparare
    qualcosa che non è rotto.
    """
    from mcp_server.doctor import confronta_dipendenze, leggi_lockfile

    deriva = confronta_dipendenze(
        leggi_lockfile(LOCK_FINTO), {"annotated-types": "0.8.0", "mcp": "2.3.0"}
    )
    assert deriva.grave is False
    assert deriva.mancanti == [] and deriva.diverse == []


def test_versione_diversa_e_deriva_grave():
    from mcp_server.doctor import confronta_dipendenze

    deriva = confronta_dipendenze(
        {"mcp": "2.3.0"}, {"mcp": "2.4.1"}
    )
    assert deriva.diverse == [("mcp", "2.3.0", "2.4.1")]
    assert deriva.grave is True


def test_pacchetto_fissato_e_non_installato_e_deriva_grave():
    from mcp_server.doctor import confronta_dipendenze

    deriva = confronta_dipendenze({"mcp": "2.3.0"}, {})
    assert deriva.mancanti == ["mcp"]
    assert deriva.grave is True


def test_pacchetto_in_piu_non_e_grave_ma_si_dice():
    """Non smentisce il lock, ma racconta che qualcuno ha installato a mano."""
    from mcp_server.doctor import confronta_dipendenze

    deriva = confronta_dipendenze({"mcp": "2.3.0"}, {"mcp": "2.3.0", "requests": "2.0"})
    assert deriva.in_piu == ["requests"]
    assert deriva.grave is False


def test_pip_e_il_progetto_non_sono_pacchetti_in_piu():
    """Un avviso che compare su ogni installazione sana smette di essere letto."""
    from mcp_server.doctor import FUORI_CONFRONTO, confronta_dipendenze

    installate = {"mcp": "2.3.0"} | {nome: "1.0" for nome in FUORI_CONFRONTO}
    deriva = confronta_dipendenze({"mcp": "2.3.0"}, installate)
    assert deriva.in_piu == []


def test_lockfile_assente_e_avviso_non_errore(tmp_path: Path, radice: Path):
    """Manca una proprietà, non un pezzo: il server parte lo stesso."""
    repo = tmp_path / "repo"
    repo.mkdir()
    percorso = scrivi_config(tmp_path, radice, senza_tool=True, repo_root=repo)
    referto = esegui(percorso)
    controllo = _controllo(referto, "lockfile delle dipendenze")
    assert controllo.esito is Esito.AVVISO
    assert "ultime versioni" in controllo.messaggio
    assert referto.pronto is True


def test_lockfile_illeggibile_e_errore(tmp_path: Path, radice: Path):
    """Un lock senza pin non blocca niente, ma sembra che lo faccia."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.lock").write_text(
        "# solo commenti\n#    --hash=sha256:abc\n", encoding="utf-8"
    )
    referto = esegui(scrivi_config(tmp_path, radice, senza_tool=True, repo_root=repo))
    controllo = _controllo(referto, "lockfile delle dipendenze")
    assert controllo.esito is Esito.ERRORE
    assert referto.pronto is False


@pytest.mark.dipendenze_reali
def test_deriva_dall_ambiente_reale_rilevata(tmp_path: Path, radice: Path):
    """Un pin che l'ambiente non può soddisfare deve diventare un ERRORE.

    Il pacchetto è reale e la versione no: così il controllo deve trovare
    `mcp` installato a una versione diversa, che è il caso che conta — non
    un nome inventato, che proverebbe solo che sa leggere un file.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.lock").write_text(
        "mcp==0.0.1-inesistente\n", encoding="utf-8"
    )
    referto = esegui(scrivi_config(tmp_path, radice, senza_tool=True, repo_root=repo))
    controllo = _controllo(referto, "lockfile delle dipendenze")
    assert controllo.esito is Esito.ERRORE
    assert "mcp" in controllo.messaggio
    assert "--require-hashes" in controllo.rimedio
    assert referto.pronto is False


def test_il_referto_dice_su_quale_ambiente_ha_risposto(tmp_path: Path, radice: Path):
    """La risposta vale per l'interprete che lancia il preflight.

    Lanciarlo con il Python di sistema invece che con quello del venv
    risponderebbe sulla macchina giusta e sull'ambiente sbagliato: il
    referto deve dire quale ha guardato.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.lock").write_text("mcp==0.0.1\n", encoding="utf-8")
    referto = esegui(scrivi_config(tmp_path, radice, senza_tool=True, repo_root=repo))
    controllo = _controllo(referto, "lockfile delle dipendenze")
    assert sys.executable in controllo.messaggio


# --------------------------------------------------------------------------- #
# Dipendenze di INSTALLAZIONE
#
# Difetto trovato il 6 novembre, e trovato dal file vero: con il lockfile
# reale in posizione, 9 test sono diventati rossi perché `setuptools` non è
# installato — `python3 -m venv` non lo mette da Python 3.12. Il controllo
# trattava tutto il lock come runtime e avrebbe detto NON PRONTO a un
# dispiegamento che funziona. Il falso rosso insegna a ignorare i rossi.
# --------------------------------------------------------------------------- #


BUILD_IN_FINTO = """\
# commento che non dichiara niente
setuptools>=68
"""


def test_dipendenze_di_build_lette_senza_i_vincoli():
    from mcp_server.doctor import leggi_dipendenze_di_build

    assert leggi_dipendenze_di_build(BUILD_IN_FINTO) == frozenset({"setuptools"})


def test_dipendenza_di_build_assente_non_e_grave():
    """Il server gira senza: dirlo NON PRONTO sarebbe un falso rosso."""
    from mcp_server.doctor import confronta_dipendenze

    deriva = confronta_dipendenze(
        {"mcp": "2.3.0", "setuptools": "84.2.1"},
        {"mcp": "2.3.0"},
        frozenset({"setuptools"}),
    )
    assert deriva.mancanti_di_build == ["setuptools"]
    assert deriva.mancanti == []
    assert deriva.grave is False


def test_dipendenza_di_build_a_versione_diversa_resta_grave():
    """Se c'è, è quella che `pip install -e .` eseguirebbe."""
    from mcp_server.doctor import confronta_dipendenze

    deriva = confronta_dipendenze(
        {"setuptools": "84.2.1"},
        {"setuptools": "70.0.0"},
        frozenset({"setuptools"}),
    )
    assert deriva.diverse == [("setuptools", "84.2.1", "70.0.0")]
    assert deriva.grave is True


def test_senza_la_dichiarazione_di_build_si_confronta_tutto():
    """Il lato prudente: dice troppo, non troppo poco."""
    from mcp_server.doctor import confronta_dipendenze

    deriva = confronta_dipendenze({"setuptools": "84.2.1"}, {})
    assert deriva.mancanti == ["setuptools"]
    assert deriva.grave is True


@pytest.mark.dipendenze_reali
def test_build_assente_e_avviso_separato_e_referto_pronto(
    tmp_path: Path, radice: Path
):
    """Il caso reale del 6 novembre, in forma di regressione.

    Il lock fissa una dipendenza di build che l'ambiente non ha. Deve
    uscirne un AVVISO con un nome proprio — non confuso con la deriva di
    runtime — e il referto deve restare PRONTO.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements-build.in").write_text(BUILD_IN_FINTO, encoding="utf-8")
    # Il pin di runtime deve combaciare con l'ambiente, altrimenti il test
    # misurerebbe la deriva di runtime invece di quella di build.
    versione = importlib.metadata.version("mcp")
    (repo / "requirements.lock").write_text(
        f"mcp=={versione}\nsetuptools==0.0.1-inesistente\n", encoding="utf-8"
    )

    referto = esegui(scrivi_config(tmp_path, radice, senza_tool=True, repo_root=repo))

    runtime = _controllo(referto, "lockfile delle dipendenze")
    assert runtime.esito is Esito.OK
    assert "di runtime" in runtime.messaggio

    build = _controllo(referto, "dipendenze di installazione")
    assert build.esito is Esito.AVVISO
    assert "setuptools" in build.messaggio
    assert "non è un guasto" in build.rimedio
    assert referto.pronto is True


@pytest.mark.dipendenze_reali
def test_il_lock_reale_del_repo_combacia_con_questo_ambiente(radice: Path):
    """Il lock versionato descrive l'ambiente in cui girano i test.

    Non è una tautologia: se qualcuno aggiorna una dipendenza in
    pyproject.toml senza rigenerare il lock, oppure rigenera il lock senza
    reinstallare, questo test lo dice — ed è il solo posto dove la coerenza
    fra i due file viene misurata invece che assunta.
    """
    from mcp_server.doctor import (
        confronta_dipendenze,
        leggi_dipendenze_di_build,
        leggi_lockfile,
        _installate,
    )

    lock = radice / "requirements.lock"
    if not lock.exists():  # pragma: no cover - il lock è versionato
        pytest.skip("lockfile assente")

    deriva = confronta_dipendenze(
        leggi_lockfile(lock.read_text(encoding="utf-8")),
        _installate(),
        leggi_dipendenze_di_build(
            (radice / "requirements-build.in").read_text(encoding="utf-8")
        ),
    )
    assert deriva.diverse == [], f"versioni divergenti: {deriva.diverse}"
    assert deriva.mancanti == [], f"pacchetti di runtime mancanti: {deriva.mancanti}"
