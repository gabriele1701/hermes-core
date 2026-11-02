"""Test dei posti di esecuzione condivisi fra processi (patch di sicurezza, 6b).

Il test che conta davvero è uno solo: **un processo ucciso deve liberare il
suo posto**. È la proprietà per cui qui serve un lock e non un contatore, e
l'unico modo di verificarla è uccidere un processo vero.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcp_server.contracts import OwnerAgent
from mcp_server.slots import NOME_DIR, SlotPool, SlotUnavailable

#: Codice di un processo che prende un posto e lo tiene finché non muore.
_OCCUPANTE = """
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
sys.stdout.write("preso\\n")
sys.stdout.flush()
time.sleep(300)
"""


@pytest.fixture()
def pool(tmp_path: Path) -> SlotPool:
    return SlotPool(tmp_path / "slots", 2)


def _occupa(percorso: Path) -> subprocess.Popen:
    """Avvia un processo che tiene il lock, e aspetta che l'abbia preso."""
    # La directory dei posti nasce al primo acquire(): qui si simula un altro
    # processo che arriva per primo, quindi va creata a mano.
    percorso.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    proc = subprocess.Popen(
        [sys.executable, "-c", _OCCUPANTE, str(percorso)],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    assert proc.stdout.readline().strip() == "preso"
    return proc


# --------------------------------------------------------------------------- #
# Comportamento di base
# --------------------------------------------------------------------------- #


def test_occupa_fino_al_limite_poi_rifiuta(pool: SlotPool):
    primo = pool.acquire()
    secondo = pool.acquire()
    with pytest.raises(SlotUnavailable):
        pool.acquire()
    primo.release()
    pool.acquire().release()
    secondo.release()


def test_rilascio_libera_il_posto(pool: SlotPool):
    posto = pool.acquire()
    assert pool.occupati() == 1
    posto.release()
    assert pool.occupati() == 0


def test_rilascio_idempotente(pool: SlotPool):
    posto = pool.acquire()
    posto.release()
    posto.release()  # non deve chiudere un fd già chiuso, o peggio un altro
    assert pool.occupati() == 0


def test_usabile_come_context_manager(pool: SlotPool):
    with pool.acquire():
        assert pool.occupati() == 1
    assert pool.occupati() == 0


def test_permessi_restrittivi(pool: SlotPool):
    with pool.acquire() as posto:
        assert os.stat(posto.percorso).st_mode & 0o077 == 0
        assert os.stat(pool.directory).st_mode & 0o077 == 0


def test_posti_minimi(tmp_path: Path):
    with pytest.raises(ValueError):
        SlotPool(tmp_path, 0)


def test_directory_inutilizzabile_solleva(tmp_path: Path):
    """Un pool che fallisce in silenzio diventa «nessun limite».

    Qui si solleva e basta: è il chiamante a decidere se degradare, e lo fa
    registrandolo.
    """
    blocco = tmp_path / "slots"
    blocco.write_text("non sono una directory\n", encoding="utf-8")
    with pytest.raises(OSError):
        SlotPool(blocco, 2).acquire()


# --------------------------------------------------------------------------- #
# Fra processi: è il motivo per cui questo modulo esiste
# --------------------------------------------------------------------------- #


def test_un_altro_processo_occupa_il_posto(pool: SlotPool):
    """Il semaforo in memoria non vedeva nulla di tutto questo."""
    occupanti = [_occupa(pool.percorso(0)), _occupa(pool.percorso(1))]
    try:
        with pytest.raises(SlotUnavailable):
            pool.acquire()
    finally:
        for proc in occupanti:
            proc.kill()
            proc.wait(timeout=10)


def test_processo_ucciso_libera_il_posto(pool: SlotPool):
    """La proprietà che giustifica il lock al posto di un contatore.

    Un contatore su file resterebbe incrementato per sempre dopo un ``kill
    -9``, e dopo qualche incidente il limite sarebbe esaurito senza che nulla
    stia girando. Il kernel invece chiude i descriptor di un processo morto,
    comunque sia morto, e con essi il lock.
    """
    occupanti = [_occupa(pool.percorso(0)), _occupa(pool.percorso(1))]
    with pytest.raises(SlotUnavailable):
        pool.acquire()

    occupanti[0].send_signal(signal.SIGKILL)
    occupanti[0].wait(timeout=10)

    # Il rilascio è fatto dal kernel allo smontaggio del processo: può non
    # essere istantaneo rispetto al wait().
    for _ in range(50):
        try:
            pool.acquire().release()
            break
        except SlotUnavailable:
            time.sleep(0.05)
    else:  # pragma: no cover
        pytest.fail("il posto di un processo ucciso non è stato liberato")

    occupanti[1].kill()
    occupanti[1].wait(timeout=10)


def test_agenti_diversi_non_si_contendono_i_posti(tmp_path: Path):
    """Un pool unico sarebbe un canale di denial-of-service fra agenti.

    Tutto il resto dell'architettura tiene gli agenti separati per
    costruzione; aprire proprio qui la possibilità che l'agente di pentest in
    ciclo affami quello di vulnerability assessment sarebbe il male peggiore.
    """
    kali = SlotPool.per_agente(tmp_path, OwnerAgent.PENTEST_KALI, 1)
    vuln = SlotPool.per_agente(tmp_path, OwnerAgent.VULN_ASSESSMENT, 1)

    with kali.acquire():
        with pytest.raises(SlotUnavailable):
            kali.acquire()
        vuln.acquire().release()  # l'altro agente non è toccato

    assert kali.directory != vuln.directory
    assert kali.directory.parent.name == NOME_DIR


def test_stesso_agente_condivide_fra_pool_distinti(tmp_path: Path):
    """Due pool distinti sono due processi diversi dello stesso agente."""
    uno = SlotPool.per_agente(tmp_path, OwnerAgent.ECHO_DUMMY, 1)
    due = SlotPool.per_agente(tmp_path, OwnerAgent.ECHO_DUMMY, 1)
    with uno.acquire():
        with pytest.raises(SlotUnavailable):
            due.acquire()
