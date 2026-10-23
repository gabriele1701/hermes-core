"""Test del preflight (M0 passo 8).

Un diagnostico che dice sempre «ok» è peggio che inutile: dà fiducia
ingiustificata. I test verificano soprattutto che i guasti vengano
**rilevati**, e che il rimedio suggerito sia utilizzabile.
"""

from __future__ import annotations

import io
import textwrap
from pathlib import Path

import pytest

from mcp_server.doctor import Esito, esegui, main, stampa
from mcp_server.executor import sha256_file

#: Tutto il modulo è integrazione: ogni controllo che arriva all'handshake
#: avvia un processo. Marcato a livello di modulo invece che test per test,
#: perché è la natura del componente e non una proprietà dei singoli casi.
pytestmark = pytest.mark.slow

SCRIPT = "agents/echo_agent/run.py"


@pytest.fixture()
def radice() -> Path:
    return Path(__file__).resolve().parent.parent


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
) -> Path:
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
            description = "Agente dummy."
            """)
    )
    percorso = tmp_path / "hermes.toml"
    percorso.write_text(
        textwrap.dedent(f"""\
            [server]
            agent = "{agent}"
            repo_root = "{radice}"
            log_path = "{tmp_path}/audit.jsonl"
            container_available = false

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
        Path(os.sys.executable).resolve()
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
