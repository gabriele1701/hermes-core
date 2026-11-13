"""Test di `bin/hermes-bootstrap`.

Quello che si può verificare da qui, e quello che no
----------------------------------------------------

Lo script installa utenti, ACL, righe di sudoers e unità di systemd: niente
di tutto ciò è esercitabile da una suite, che gira senza privilegi e dentro
un contenitore. Verificarlo **davvero** vuol dire eseguirlo, e il modo più
economico è farlo su una macchina già preparata, dove deve finire senza
cambiare niente.

Qui si copre l'altra metà, quella che un'esecuzione non vede: che le
costanti duplicate fra shell, Python e unità **coincidano**. Sono copie
inevitabili — un nome utente vive in uno script di shell, in un modulo
Python e in un file `.service` — e la regola del progetto è che dove la
copia è inevitabile ci sia un test che legge l'una e confronta con l'altra.

Il limite è dichiarato anche in `docs/ci.md` e nel job «cosa questa CI non
verifica», accanto a tutto il resto che solo una macchina vera misura.

**Nessun test di questo modulo deve eseguire il bootstrap per davvero.** I
soli che lo lanciano sono quelli che si fermano prima di toccare qualcosa —
l'aiuto, un argomento ignoto, il controllo dell'identità — e quest'ultimo
salta da root, dove non si fermerebbe affatto.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path

import pytest

from mcp_server.doctor import (
    MITTENTE_INSTALLATO,
    NON_COMPILATO,
    UTENTE_SPEDIZIONE,
    SpedizioneError,
    leggi_spedizione,
)

RADICE = Path(__file__).resolve().parent.parent
BOOTSTRAP = RADICE / "bin" / "hermes-bootstrap"


def _assegnazione(testo: str, nome: str) -> str:
    """Il valore di `NOME=valore` in uno script di shell, una volta sola."""
    trovate = re.findall(rf"^{nome}=(\S+)$", testo, flags=re.MULTILINE)
    assert len(trovate) == 1, f"{nome}: {len(trovate)} assegnazioni, non 1"
    return trovate[0]


@pytest.fixture(scope="module")
def script() -> str:
    return BOOTSTRAP.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Lo script deve almeno essere uno script
# --------------------------------------------------------------------------- #


def test_la_sintassi_e_valida(script: str):
    """`sh -n` non esegue niente e trova gli errori di struttura."""
    esito = subprocess.run(
        ["sh", "-n", str(BOOTSTRAP)], capture_output=True, text=True, timeout=60
    )
    assert esito.returncode == 0, esito.stderr


def test_e_eseguibile():
    assert BOOTSTRAP.stat().st_mode & 0o111, "manca il bit di esecuzione"


def test_si_ferma_senza_privilegi():
    """Il primo controllo è l'identità, e deve arrivare prima di tutto.

    Lanciato senza privilegi non deve provare e fallire a metà: deve dirlo
    subito. Una preparazione interrotta a metà è peggio di una non iniziata.

    Salta da root, e il motivo è serio: da root questo test **eseguirebbe
    un'installazione vera** sulla macchina di chi lancia la suite — utenti,
    sudoers, drop-in di sshd. È successo mentre lo scrivevo. Un test che
    salta è incomparabilmente meglio di un test che installa.
    """
    if os.geteuid() == 0:
        pytest.skip("da root questo lancerebbe un'installazione vera")

    esito = subprocess.run(
        [str(BOOTSTRAP)], capture_output=True, text=True, timeout=60
    )

    assert esito.returncode != 0
    assert "root" in esito.stderr


def test_l_aiuto_non_richiede_privilegi(script: str):
    esito = subprocess.run(
        [str(BOOTSTRAP), "--aiuto"], capture_output=True, text=True, timeout=60
    )
    assert esito.returncode == 0
    assert "--dev" in esito.stdout


def test_un_argomento_ignoto_non_passa():
    """Gli argomenti si controllano PRIMA dell'identità, quindi è sicuro."""
    esito = subprocess.run(
        [str(BOOTSTRAP), "--distruggi"], capture_output=True, text=True, timeout=60
    )
    assert esito.returncode != 0
    assert "non riconosciuto" in esito.stderr


# --------------------------------------------------------------------------- #
# Le copie della stessa costante, in tre linguaggi
# --------------------------------------------------------------------------- #


def test_i_nomi_utente_coincidono_con_le_unita_e_i_moduli(script: str):
    assert _assegnazione(script, "UTENTE_SPEDIZIONE") == UTENTE_SPEDIZIONE

    unita = (RADICE / "config" / "systemd" / "hermes-log-ship.service").read_text(
        encoding="utf-8"
    )
    assert f"User={UTENTE_SPEDIZIONE}\n" in unita


def test_il_bootstrap_installa_dove_le_unita_e_il_preflight_cercano(script: str):
    """Tre file dicono dove vive il mittente. Devono dire la stessa cosa."""
    assert _assegnazione(script, "MITTENTE") == str(MITTENTE_INSTALLATO)

    unita = (RADICE / "config" / "systemd" / "hermes-log-ship.service").read_text(
        encoding="utf-8"
    )
    assert f"ExecStart={MITTENTE_INSTALLATO}\n" in unita


def test_il_segnaposto_e_lo_stesso_ovunque(script: str):
    """Shell, mittente e preflight devono parlare dello stesso valore.

    Se divergessero, il preflight rifiuterebbe un segnaposto che il
    bootstrap non scrive più, e lascerebbe passare quello che scrive.
    """
    assert _assegnazione(script, "NON_COMPILATO") == NON_COMPILATO
    mittente = (RADICE / "bin" / "hermes-log-ship").read_text(encoding="utf-8")
    assert NON_COMPILATO in mittente


def test_una_configurazione_non_compilata_viene_rifiutata():
    """Non si lascia fallire più tardi: il sintomo non punterebbe alla causa.

    Senza questo rifiuto, un `log-shipping.conf` appena generato fallirebbe
    con un errore di risoluzione DNS — vero, inutile, e muto sul fatto che
    nessuno ha compilato il file.
    """
    testo = (RADICE / "config" / "log-shipping.example.conf").read_text(
        encoding="utf-8"
    )
    non_compilata = re.sub(
        r"^COLLECTOR_HOST=.*$", f"COLLECTOR_HOST={NON_COMPILATO}", testo,
        flags=re.MULTILINE,
    )

    with pytest.raises(SpedizioneError) as err:
        leggi_spedizione(non_compilata)

    assert NON_COMPILATO in str(err.value)
    assert "COLLECTOR_HOST" in str(err.value)


# --------------------------------------------------------------------------- #
# Il modello deve descrivere il repo che lo accompagna
# --------------------------------------------------------------------------- #


def test_lo_sha_del_modello_e_quello_dello_script_sul_disco():
    """Un modello che mente rende inutilizzabile un'installazione nuova.

    `docs §3` dice di copiare `hermes.example.toml` e partire. Se lo SHA lì
    dentro non è quello di `agents/echo_agent/run.py`, il primo tool fallisce
    il controllo di integrità — e il vincolo del progetto è che dal repo
    completo si arrivi a un server funzionante.

    Era già successo: il modello portava lo SHA di una versione precedente
    dello script, e nessun test se ne era accorto. Il bootstrap lo ricalcola,
    ma chi segue la procedura a mano no.
    """
    modello = (RADICE / "config" / "hermes.example.toml").read_text(encoding="utf-8")
    percorsi = re.findall(r'^exec_path = "(.+)"$', modello, flags=re.MULTILINE)
    sha_dichiarati = re.findall(
        r'^exec_sha256 = "([0-9a-f]{64})"$', modello, flags=re.MULTILINE
    )
    assert percorsi, "nessun tool nel modello"
    assert len(percorsi) == len(sha_dichiarati)

    for percorso, dichiarato in zip(percorsi, sha_dichiarati, strict=True):
        reale = hashlib.sha256((RADICE / percorso).read_bytes()).hexdigest()
        assert dichiarato == reale, (
            f"{percorso}: il modello dichiara {dichiarato[:12]}…, "
            f"sul disco c'è {reale[:12]}…"
        )
