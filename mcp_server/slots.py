"""Posti di esecuzione condivisi fra processi.

Il tetto sulle esecuzioni contemporanee viveva in un semaforo del processo
server, e l'host MCP avvia **un processo per connessione**: conteneva un
modello in ciclo dentro una sessione, non la somma di più sessioni aperte in
parallelo. Un agente con tre connessioni aperte poteva eseguire ``3 × N`` tool
insieme pur avendo configurato ``N``.

Perché un lock e non un contatore
---------------------------------

La tentazione è un contatore su file: leggi, incrementa, scrivi. Non funziona,
e non per un problema di atomicità — quello si risolverebbe. Non funziona
perché **un processo può morire**. Un tool che va in timeout, un `kill -9`,
l'host che chiude la connessione a metà esecuzione: il contatore resterebbe
incrementato per sempre, e dopo qualche incidente il limite sarebbe esaurito
senza che nulla stia girando. Un controllo che si auto-esaurisce è peggio di
nessun controllo, perché blocca il lavoro legittimo e spinge chi amministra a
disattivarlo.

``flock`` non ha quel problema: il kernel rilascia il lock quando il file
descriptor si chiude, e **i descriptor si chiudono alla morte del processo**,
comunque sia morto. Non c'è stato da ripulire, nessuna scadenza da indovinare,
nessun lock orfano.

È anche il motivo per cui questo modulo non riusa lo store degli override, pur
vivendo nella stessa ``state_dir``: quello è un registro append-only di fatti
avvenuti, questo è un conteggio di risorse occupate che devono liberarsi da
sole. Condividono dove stanno, non come funzionano.

Posti per agente, non per macchina
----------------------------------

I posti sono partizionati per agente: ``state_dir/slots/<agente>/``. Un pool
unico darebbe un tetto complessivo migliore, ma sarebbe il primo punto
dell'architettura in cui **un agente può degradarne un altro** — l'agente di
pentest in ciclo affamerebbe quello di vulnerability assessment. Tutto il
resto del progetto tiene gli agenti separati per costruzione (un processo
ciascuno, i tool di proprietà, i tool altrui invisibili), e aprire proprio qui
un canale di denial-of-service fra agenti sarebbe il male peggiore fra i due.

La conseguenza va detta: il tetto di macchina è ``N × agenti``, non ``N``. Un
tetto di macchina vero non è lavoro di questo processo — lo danno una slice
systemd o un cgroup, che contano CPU e memoria reali invece di esecuzioni.

Degradare dichiarandolo
-----------------------

Senza ``state_dir``, o se la directory dei posti non è utilizzabile, il limite
resta quello di prima — per processo — e la cosa viene **registrata**, non
taciuta. Vale la stessa regola degli override: un controllo che decade in
silenzio è peggio di un controllo assente.
"""

from __future__ import annotations

import errno
import fcntl
import os
import stat
from pathlib import Path
from types import TracebackType

from mcp_server.contracts import OwnerAgent

_FILE_MODE = 0o600
_DIR_MODE = 0o700

#: Nome della directory dei posti dentro ``state_dir``.
NOME_DIR = "slots"


class SlotUnavailable(Exception):
    """Nessun posto libero nel pool condiviso."""


class SlotPool:
    """Posti di esecuzione condivisi fra i processi di uno stesso agente.

    Parameters
    ----------
    directory:
        Cartella dei file di lock, tipicamente ``state_dir/slots/<agente>``.
    posti:
        Quante esecuzioni contemporanee ammettere.
    """

    def __init__(self, directory: str | os.PathLike[str], posti: int) -> None:
        if posti < 1:
            raise ValueError("i posti devono essere almeno 1")
        self._directory = Path(directory)
        self._posti = posti

    @classmethod
    def per_agente(
        cls, state_dir: str | os.PathLike[str], agent: OwnerAgent, posti: int
    ) -> SlotPool:
        """Pool dedicato a un agente dentro la directory di stato."""
        return cls(Path(state_dir) / NOME_DIR / agent.value, posti)

    @property
    def directory(self) -> Path:
        return self._directory

    @property
    def posti(self) -> int:
        return self._posti

    def percorso(self, indice: int) -> Path:
        return self._directory / f"slot-{indice:02d}"

    # -- acquisizione -------------------------------------------------------- #

    def acquire(self) -> Posto:
        """Occupa un posto, o solleva.

        Raises
        ------
        SlotUnavailable
            Se tutti i posti sono occupati da altri processi.
        OSError
            Se la directory dei posti non è utilizzabile. Il chiamante decide
            se degradare al limite di processo: qui non si inghiotte nulla,
            perché un pool che fallisce in silenzio diventa «nessun limite».
        """
        self._directory.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        _restringi(self._directory, _DIR_MODE)

        for indice in range(self._posti):
            percorso = self.percorso(indice)
            fd = os.open(percorso, os.O_RDWR | os.O_CREAT, _FILE_MODE)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as err:
                os.close(fd)
                if err.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                    continue  # occupato da un altro processo
                raise
            _restringi(percorso, _FILE_MODE)
            # Il pid serve solo a chi guarda: il lock vale di per sé, e il
            # contenuto non viene mai letto per decidere qualcosa.
            _annota_pid(fd)
            return Posto(fd, percorso)

        raise SlotUnavailable(
            f"tutti i {self._posti} posti sono occupati in {self._directory}"
        )

    def occupati(self) -> int:
        """Quanti posti risultano occupati ora. **Solo per diagnostica.**

        Due avvertenze, entrambe serie.

        È una fotografia: fra la lettura e qualunque azione il numero può
        cambiare, e usarla per autorizzare un'esecuzione reintrodurrebbe la
        corsa che ``flock`` elimina.

        E non è innocua: per sapere se un posto è libero bisogna **provare a
        prenderlo**, quindi per una frazione di istante questo metodo occupa i
        posti liberi che incontra. Su un pool in uso può far rifiutare
        un'esecuzione legittima. Va chiamata in test e in ispezione manuale,
        mai da un percorso che gira in produzione.

        Non usa ``Path.exists()``: quella solleva su una directory non
        attraversabile invece di rispondere ``False``, e un metodo di
        diagnostica che muore non diagnostica niente.
        """
        conteggio = 0
        for indice in range(self._posti):
            try:
                fd = os.open(self.percorso(indice), os.O_RDWR)
            except OSError:
                continue  # inesistente, o non ispezionabile: non è occupato da noi
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                conteggio += 1
            finally:
                os.close(fd)
        return conteggio


class Posto:
    """Un posto occupato. Si libera chiudendo il descriptor.

    Non c'è un metodo che «decrementa» qualcosa: il rilascio è la chiusura del
    file descriptor, e avviene comunque — anche se il processo muore senza
    arrivare al ``finally``.
    """

    __slots__ = ("_fd", "_percorso", "_chiuso")

    def __init__(self, fd: int, percorso: Path) -> None:
        self._fd = fd
        self._percorso = percorso
        self._chiuso = False

    @property
    def percorso(self) -> Path:
        return self._percorso

    def release(self) -> None:
        if self._chiuso:
            return
        self._chiuso = True
        try:
            os.close(self._fd)  # chiude il fd e con esso il lock
        except OSError:  # pragma: no cover
            pass

    def __enter__(self) -> Posto:
        return self

    def __exit__(
        self,
        tipo: type[BaseException] | None,
        valore: BaseException | None,
        traccia: TracebackType | None,
    ) -> None:
        self.release()


def _annota_pid(fd: int) -> None:
    """Scrive il pid nel file del posto, a beneficio di chi ispeziona."""
    try:
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
    except OSError:  # pragma: no cover
        pass


def _restringi(percorso: Path, modo: int) -> None:
    """Impone i permessi se non sono già quelli, tollerando un rifiuto."""
    try:
        if stat.S_IMODE(percorso.stat().st_mode) != modo:
            os.chmod(percorso, modo)
    except OSError:
        pass


__all__ = ["NOME_DIR", "Posto", "SlotPool", "SlotUnavailable"]
