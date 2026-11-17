"""Gli esiti dei tool isolati: il manifesto e il comando che li porta via.

Il manifesto è la sola cosa che lega i file lasciati da un tool alla riga di
audit dell'invocazione. Ha due lettori — il gate, che lo scrive nel log, e
`bin/hermes-esiti`, che lo ricalcola per confrontarlo — e un solo
implementatore, `mcp_server/esiti.py`. I test qui sotto verificano le due
proprietà che gli servono: che sia **deterministico**, e che non si fidi del
contenuto, che lo ha scritto il tool.
"""

from __future__ import annotations

import json
import os
import subprocess
import tarfile
import uuid
from pathlib import Path

import pytest

from mcp_server.esiti import manifesto, nota_esiti

RADICE = Path(__file__).resolve().parent.parent
COMANDO = RADICE / "bin" / "hermes-esiti"


def _popola(cartella: Path) -> None:
    (cartella / "sotto").mkdir(parents=True)
    (cartella / "sotto" / "b.bin").write_bytes(b"\x00\x01")
    (cartella / "a.txt").write_text("uno\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# Il manifesto
# --------------------------------------------------------------------------- #


def test_il_manifesto_conta_file_e_byte(tmp_path: Path):
    _popola(tmp_path)
    m = manifesto(tmp_path)
    assert (m.file, m.byte) == (2, 6)
    assert m.riassunto == f"esiti: 2 file, 6 byte, manifesto sha256:{m.sha256}"


def test_il_manifesto_non_dipende_dall_ordine_di_creazione(tmp_path: Path):
    """Due directory con lo stesso contenuto, create in ordine diverso."""
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    for nome in ("z", "a", "m"):
        (a / nome).write_text(nome, encoding="utf-8")
    for nome in ("m", "z", "a"):
        (b / nome).write_text(nome, encoding="utf-8")
    assert manifesto(a).sha256 == manifesto(b).sha256


def test_cambiare_un_byte_cambia_il_manifesto(tmp_path: Path):
    _popola(tmp_path)
    prima = manifesto(tmp_path).sha256
    (tmp_path / "a.txt").write_text("due\n", encoding="utf-8")
    assert manifesto(tmp_path).sha256 != prima


def test_un_link_si_registra_e_non_si_segue(tmp_path: Path):
    """Il tool può lasciare un link verso un file che non poteva leggere.

    Seguirlo farebbe entrare nel manifesto l'impronta di quel file, letto con
    i permessi del servizio.
    """
    fuori = tmp_path / "fuori.txt"
    fuori.write_text("segreto", encoding="utf-8")
    esiti = tmp_path / "esiti"
    esiti.mkdir()
    (esiti / "trappola").symlink_to(fuori)
    (esiti / "cartella-trappola").symlink_to(tmp_path)

    m = manifesto(esiti)
    assert m.file == 0 and m.byte == 0
    assert m.righe == (
        f'link  {json.dumps(str(tmp_path))}  "cartella-trappola"',
        f'link  {json.dumps(str(fuori))}  "trappola"',
    )


def test_un_nome_con_un_a_capo_resta_una_riga(tmp_path: Path):
    """Un a-capo in un nome di file sarebbe una riga di manifesto in più."""
    (tmp_path / "riga\nfinta").write_text("x", encoding="utf-8")
    m = manifesto(tmp_path)
    assert len(m.righe) == 1
    assert m.testo.count("\n") == 1
    assert '"riga\\nfinta"' in m.righe[0]


def test_nota_esiti_nei_tre_casi(tmp_path: Path):
    assert nota_esiti(tmp_path / "mai-creata") == "; esiti: nessuno"
    _popola(tmp_path / "piena")
    assert nota_esiti(tmp_path / "piena").startswith("; esiti: 2 file, 6 byte")


@pytest.mark.skipif(os.geteuid() == 0, reason="da root i permessi non bloccano")
def test_nota_esiti_non_solleva_su_una_directory_illeggibile(tmp_path: Path):
    """Si chiama dopo che il tool è girato: non deve togliere la riga di audit."""
    chiusa = tmp_path / "chiusa"
    chiusa.mkdir()
    (chiusa / "f").write_text("x", encoding="utf-8")
    (chiusa / "f").chmod(0)
    try:
        assert "non leggibili dal servizio" in nota_esiti(chiusa)
    finally:
        (chiusa / "f").chmod(0o644)


# --------------------------------------------------------------------------- #
# bin/hermes-esiti
# --------------------------------------------------------------------------- #


def _esegui(esiti: Path, log: Path, *argomenti: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(COMANDO), *argomenti],
        capture_output=True,
        text=True,
        cwd=cwd,
        env={**os.environ, "HERMES_DIR_ESITI": str(esiti), "HERMES_LOG": str(log)},
        timeout=60,
        check=False,
    )


@pytest.fixture
def scena(tmp_path: Path):
    esiti = tmp_path / "esiti"
    cid = str(uuid.uuid4())
    _popola(esiti / cid)
    log = tmp_path / "audit.jsonl"
    m = manifesto(esiti / cid)
    log.write_text(
        json.dumps(
            {
                "correlation_id": cid,
                "action": "tool_call",
                "outcome": "ok",
                "detail": f"exit=0; {m.riassunto}",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    uscita = tmp_path / "uscita"
    uscita.mkdir()
    return esiti, log, cid, uscita


def test_elenco_delle_invocazioni_con_esiti(scena):
    esiti, log, cid, uscita = scena
    esito = _esegui(esiti, log, cwd=uscita)
    assert esito.returncode == 0, esito.stderr
    assert cid in esito.stdout


def test_l_archivio_coincide_con_il_log(scena):
    esiti, log, cid, uscita = scena
    esito = _esegui(esiti, log, cid, str(uscita), cwd=uscita)
    assert esito.returncode == 0, esito.stderr
    assert "coincide" in esito.stdout

    with tarfile.open(uscita / f"hermes-esiti-{cid}.tar.gz") as tar:
        nomi = set(tar.getnames())
        assert {f"{cid}/a.txt", f"{cid}/sotto/b.bin", "MANIFESTO"} <= nomi
        testo = tar.extractfile("MANIFESTO").read().decode("ascii")
    assert testo == manifesto(esiti / cid).testo


def test_una_directory_cambiata_dopo_l_esecuzione_si_vede(scena):
    """L'archivio si fa lo stesso: i file non si perdono per un'informazione."""
    esiti, log, cid, uscita = scena
    (esiti / cid / "a.txt").write_text("cambiato\n", encoding="utf-8")
    esito = _esegui(esiti, log, cid, str(uscita), cwd=uscita)
    assert esito.returncode == 3
    assert "DIFFERISCE" in esito.stdout
    assert (uscita / f"hermes-esiti-{cid}.tar.gz").exists()


def test_senza_manifesto_nel_log_lo_dice(scena):
    esiti, log, cid, uscita = scena
    log.write_text("", encoding="utf-8")
    esito = _esegui(esiti, log, cid, str(uscita), cwd=uscita)
    assert esito.returncode == 0
    assert "nessun manifesto" in esito.stdout


def test_un_identificativo_non_valido_si_rifiuta(scena):
    esiti, log, _, uscita = scena
    esito = _esegui(esiti, log, "../../etc", cwd=uscita)
    assert esito.returncode == 2
    assert "non è un correlation_id" in esito.stderr


def test_un_invocazione_senza_esiti(scena):
    esiti, log, _, uscita = scena
    esito = _esegui(esiti, log, str(uuid.uuid4()), cwd=uscita)
    assert esito.returncode == 0
    assert "Nessun esito" in esito.stdout


def test_il_comando_e_uno_script_valido_ed_eseguibile():
    esito = subprocess.run(["sh", "-n", str(COMANDO)], capture_output=True, text=True)
    assert esito.returncode == 0, esito.stderr
    assert COMANDO.stat().st_mode & 0o111


@pytest.mark.skipif(os.geteuid() == 0, reason="da root i permessi non bloccano")
def test_nota_esiti_non_solleva_se_la_madre_non_e_attraversabile(tmp_path: Path):
    """Il caso trovato eseguendo la suite fuori dal gruppo del servizio.

    `Path.exists()` solleva quando non può attraversare la directory madre:
    qui la funzione deve dire «non leggibili», non far perdere la riga di
    audit a un'esecuzione già avvenuta.
    """
    madre = tmp_path / "esiti"
    (madre / "una").mkdir(parents=True)
    madre.chmod(0)
    try:
        assert "non leggibili dal servizio" in nota_esiti(madre / "una")
    finally:
        madre.chmod(0o755)
