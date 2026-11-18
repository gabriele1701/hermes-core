"""Le sonde di hermes-assess: tre esiti, e «non eseguita» non è un rifiuto."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from mcp_server.assess import sonde
from mcp_server.assess.contesto import come_utente

CTX = SimpleNamespace(cfg=SimpleNamespace(tool_python=Path(sys.executable), tool_python_flags=("-I", "-S")))


def _esegui(operazione: str, oggetto: Path):
    esito = subprocess.run(
        sonde.argv_sonda(CTX, operazione, oggetto), capture_output=True, text=True, check=False
    )
    return sonde.interpreta(
        esito, operazione=operazione, oggetto=oggetto, identita="test", controllo_positivo=False
    )


# --------------------------------------------------------------------------- #
# La sonda vera, come utente corrente
# --------------------------------------------------------------------------- #


def test_leggi_un_file(tmp_path: Path):
    f = tmp_path / "a"
    f.write_text("x")
    e = _esegui("leggi", f)
    assert e.eseguita and e.riuscita


def test_un_file_assente_e_un_rifiuto_eseguito(tmp_path: Path):
    e = _esegui("leggi", tmp_path / "manca")
    assert e.eseguita and not e.riuscita
    assert e.dettaglio.startswith("ENOENT")


def test_un_link_non_si_segue(tmp_path: Path):
    """Una sonda che segue un link misura il bersaglio del link."""
    (tmp_path / "vero").write_text("x")
    (tmp_path / "link").symlink_to(tmp_path / "vero")
    e = _esegui("leggi", tmp_path / "link")
    assert e.eseguita and not e.riuscita
    assert e.dettaglio.startswith("ELOOP")


def test_apri_scrittura_non_scrive(tmp_path: Path):
    f = tmp_path / "log"
    f.write_text("prima\n")
    e = _esegui("apri_scrittura", f)
    assert e.riuscita
    assert f.read_text() == "prima\n"


def test_crea_non_lascia_nomi(tmp_path: Path):
    e = _esegui("crea", tmp_path)
    if not e.riuscita and e.dettaglio.startswith(("EOPNOTSUPP", "EISDIR")):
        pytest.skip("il filesystem del test non supporta O_TMPFILE")
    assert e.riuscita
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root apre comunque")
def test_un_permesso_negato_e_un_rifiuto(tmp_path: Path):
    f = tmp_path / "chiuso"
    f.write_text("x")
    f.chmod(0)
    e = _esegui("leggi", f)
    assert e.eseguita and not e.riuscita
    assert e.dettaglio.startswith("EACCES")


def test_operazione_sconosciuta():
    with pytest.raises(ValueError):
        sonde.argv_sonda(CTX, "cancella", Path("/"))


# --------------------------------------------------------------------------- #
# Interpretazione: quando la sonda non ha risposto
# --------------------------------------------------------------------------- #


def _completato(codice: int, stdout: str, stderr: str = ""):
    return subprocess.CompletedProcess([], codice, stdout, stderr)


@pytest.mark.parametrize(
    "esito",
    [
        None,
        _completato(64, "", "hermes-tool-run: nome di unità non valido"),
        _completato(0, "non è json\n"),
        _completato(0, ""),
        _completato(0, '{"altro": 1}\n'),
    ],
    ids=["non-partita", "wrapper-rifiuta", "non-json", "vuoto", "senza-campo"],
)
def test_una_sonda_muta_non_e_un_rifiuto(esito):
    e = sonde.interpreta(
        esito, operazione="leggi", oggetto=Path("/x"), identita="t", controllo_positivo=False
    )
    assert not e.eseguita and not e.riuscita


def test_il_messaggio_del_wrapper_finisce_nel_dettaglio():
    e = sonde.interpreta(
        _completato(64, "", "hermes-tool-run: timeout non numerico\n"),
        operazione="leggi", oggetto=Path("/x"), identita="t", controllo_positivo=False,
    )
    assert "timeout non numerico" in e.dettaglio


# --------------------------------------------------------------------------- #
# La discesa di identità
# --------------------------------------------------------------------------- #


def test_come_utente_usa_uid_e_gid_numerici_e_niente_nuovi_privilegi():
    argv = come_utente("root", ["true"])
    assert "--reuid=0" in argv and "--regid=0" in argv
    assert "--no-new-privs" in argv and "--reset-env" in argv
    assert argv[-1] == "true" and argv[-2] == "--"


def test_il_server_scende_senza_no_new_privs():
    """Con quel bit sudo rifiuterebbe, e il server non raggiungerebbe il wrapper."""
    assert "--no-new-privs" not in come_utente("root", ["true"], nnp=False)


def test_un_utente_inesistente_si_dice():
    with pytest.raises(KeyError):
        come_utente("utente-che-non-esiste-davvero", ["true"])
