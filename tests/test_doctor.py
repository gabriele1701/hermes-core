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
    state_dir: Path | str | None = None,
) -> Path:
    riga_stato = f'state_dir = "{state_dir}"\n' if state_dir is not None else ""
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
        percorso = radice / "var-stato-test"
        if percorso.exists():
            for figlio in percorso.iterdir():
                figlio.unlink()
            percorso.rmdir()


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
